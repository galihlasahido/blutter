#include "pch.h"
#include "MachOHelper.h"
#include <cstring>
#include <iterator>
#include <stdexcept>
#include <vector>
#if defined(_WIN32) || defined(WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

// --- Iteration 4 WIP ---------------------------------------------------------
// This is a standalone Mach-O parser. It mirrors ElfHelper's shape: given a
// mapped file, locate the four Dart snapshot pointers by symbol name.
//
// NOT wired into DartApp / DartLoader yet — iteration 4 will add the Mach-O
// segment → DartApp base / heap_base mapping and arm64e PAC handling.
// -----------------------------------------------------------------------------

namespace {

// Subset of <mach-o/loader.h> we rely on. Vendored so this translation unit
// doesn't depend on system headers that are unavailable on Linux / Windows
// build hosts.
constexpr uint32_t MH_MAGIC_64 = 0xfeedfacf;
constexpr uint32_t MH_CIGAM_64 = 0xcffaedfe;
constexpr uint32_t FAT_MAGIC   = 0xcafebabe;
constexpr uint32_t FAT_MAGIC_64 = 0xcafebabf;

constexpr uint32_t CPU_TYPE_ARM64  = 0x0100000C;
constexpr uint32_t CPU_TYPE_X86_64 = 0x01000007;

constexpr uint32_t LC_SEGMENT_64 = 0x19;
constexpr uint32_t LC_SYMTAB     = 0x02;

#pragma pack(push, 1)
struct mach_header_64 {
	uint32_t magic;
	int32_t  cputype;
	int32_t  cpusubtype;
	uint32_t filetype;
	uint32_t ncmds;
	uint32_t sizeofcmds;
	uint32_t flags;
	uint32_t reserved;
};

struct load_command {
	uint32_t cmd;
	uint32_t cmdsize;
};

struct segment_command_64 {
	uint32_t cmd;
	uint32_t cmdsize;
	char     segname[16];
	uint64_t vmaddr;
	uint64_t vmsize;
	uint64_t fileoff;
	uint64_t filesize;
	int32_t  maxprot;
	int32_t  initprot;
	uint32_t nsects;
	uint32_t flags;
};

struct section_64 {
	char     sectname[16];
	char     segname[16];
	uint64_t addr;
	uint64_t size;
	uint32_t offset;
	uint32_t align;
	uint32_t reloff;
	uint32_t nreloc;
	uint32_t flags;
	uint32_t reserved1;
	uint32_t reserved2;
	uint32_t reserved3;
};

struct symtab_command {
	uint32_t cmd;
	uint32_t cmdsize;
	uint32_t symoff;
	uint32_t nsyms;
	uint32_t stroff;
	uint32_t strsize;
};

struct nlist_64 {
	uint32_t n_strx;
	uint8_t  n_type;
	uint8_t  n_sect;
	uint16_t n_desc;
	uint64_t n_value;
};

struct fat_header {
	uint32_t magic;   // big-endian
	uint32_t nfat;    // big-endian
};

struct fat_arch {
	int32_t  cputype;    // big-endian
	int32_t  cpusubtype;
	uint32_t offset;
	uint32_t size;
	uint32_t align;
};
#pragma pack(pop)

// Dart's Mach-O symbol table for these constants has historically been stored
// with a single leading underscore (as shown by `nm`). Some builds / linker
// options emit the double-underscore mangling (`__kDart...`). Accept either.
constexpr const char* kVmSnapshotDataSymbols[] = {
	"_kDartVmSnapshotData", "__kDartVmSnapshotData"
};
constexpr const char* kVmSnapshotInstructionsSymbols[] = {
	"_kDartVmSnapshotInstructions", "__kDartVmSnapshotInstructions"
};
constexpr const char* kIsolateSnapshotDataSymbols[] = {
	"_kDartIsolateSnapshotData", "__kDartIsolateSnapshotData"
};
constexpr const char* kIsolateSnapshotInstructionsSymbols[] = {
	"_kDartIsolateSnapshotInstructions", "__kDartIsolateSnapshotInstructions"
};

bool matchesAny(const char* name, const char* const* alternatives, size_t count) {
	for (size_t i = 0; i < count; ++i) {
		if (strcmp(name, alternatives[i]) == 0)
			return true;
	}
	return false;
}

uint32_t bswap32(uint32_t v) {
	return ((v & 0x000000FF) << 24)
	     | ((v & 0x0000FF00) << 8)
	     | ((v & 0x00FF0000) >> 8)
	     | ((v & 0xFF000000) >> 24);
}

struct SliceView {
	const uint8_t* base;  // start of the thin slice within the container bytes
	size_t size;
	int32_t cputype;
};

// Walk a FAT container and pick the arm64 slice if present, else the first one.
SliceView pickFatSlice(const uint8_t* data, size_t size) {
	if (size < sizeof(fat_header))
		throw std::invalid_argument("Mach-O FAT: truncated header");
	const auto* fh = reinterpret_cast<const fat_header*>(data);
	uint32_t magic = bswap32(fh->magic);
	if (magic == FAT_MAGIC_64)
		throw std::invalid_argument("Mach-O FAT: 64-bit offset variant not supported");
	if (magic != FAT_MAGIC)
		throw std::invalid_argument("Mach-O FAT: bad magic");
	uint32_t nfat = bswap32(fh->nfat);
	if (sizeof(fat_header) + size_t(nfat) * sizeof(fat_arch) > size)
		throw std::invalid_argument("Mach-O FAT: truncated arch table");

	const auto* arches = reinterpret_cast<const fat_arch*>(data + sizeof(fat_header));
	const fat_arch* picked = nullptr;
	for (uint32_t i = 0; i < nfat; i++) {
		int32_t cputype = static_cast<int32_t>(bswap32(static_cast<uint32_t>(arches[i].cputype)));
		if (cputype == CPU_TYPE_ARM64) {
			picked = &arches[i];
			break;
		}
	}
	if (picked == nullptr && nfat > 0)
		picked = &arches[0];
	if (picked == nullptr)
		throw std::invalid_argument("Mach-O FAT: no slices");

	uint32_t slice_offset = bswap32(picked->offset);
	uint32_t slice_size   = bswap32(picked->size);
	if (size_t(slice_offset) + slice_size > size)
		throw std::invalid_argument("Mach-O FAT: slice out of range");

	int32_t cputype = static_cast<int32_t>(bswap32(static_cast<uint32_t>(picked->cputype)));
	return SliceView{ data + slice_offset, slice_size, cputype };
}

struct SectionInfo {
	uint64_t vmaddr;
	uint32_t fileoff;
	uint64_t size;
};

// Translate a symbol's vm address to an offset inside the slice bytes.
const uint8_t* vmToPtr(const SliceView& slice,
	const std::vector<SectionInfo>& sections,
	uint64_t vmaddr)
{
	for (const auto& s : sections) {
		if (s.size > 0 && vmaddr >= s.vmaddr && vmaddr < s.vmaddr + s.size) {
			uint64_t delta = vmaddr - s.vmaddr;
			return slice.base + s.fileoff + delta;
		}
	}
	return nullptr;
}

LibAppInfo parseThinSlice(const SliceView& slice) {
	if (slice.size < sizeof(mach_header_64))
		throw std::invalid_argument("Mach-O: truncated header");
	const auto* hdr = reinterpret_cast<const mach_header_64*>(slice.base);
	if (hdr->magic == MH_CIGAM_64)
		throw std::invalid_argument("Mach-O: big-endian header not supported");
	if (hdr->magic != MH_MAGIC_64)
		throw std::invalid_argument("Mach-O: bad magic for thin slice");

	std::vector<SectionInfo> sections;
	const uint8_t* sym_base = nullptr;
	uint32_t nsyms = 0;
	const char* strtab = nullptr;
	uint32_t strsize = 0;

	const uint8_t* lc_cursor = slice.base + sizeof(mach_header_64);
	const uint8_t* lc_end = slice.base + slice.size;
	for (uint32_t i = 0; i < hdr->ncmds; i++) {
		if (lc_cursor + sizeof(load_command) > lc_end)
			throw std::invalid_argument("Mach-O: truncated load command");
		const auto* lc = reinterpret_cast<const load_command*>(lc_cursor);
		if (lc_cursor + lc->cmdsize > lc_end)
			throw std::invalid_argument("Mach-O: load command overflows slice");

		if (lc->cmd == LC_SEGMENT_64) {
			const auto* seg = reinterpret_cast<const segment_command_64*>(lc_cursor);
			const auto* sect = reinterpret_cast<const section_64*>(lc_cursor + sizeof(segment_command_64));
			for (uint32_t s = 0; s < seg->nsects; s++) {
				sections.push_back(SectionInfo{
					sect[s].addr,
					sect[s].offset,
					sect[s].size,
				});
			}
		}
		else if (lc->cmd == LC_SYMTAB) {
			const auto* st = reinterpret_cast<const symtab_command*>(lc_cursor);
			if (size_t(st->symoff) + size_t(st->nsyms) * sizeof(nlist_64) > slice.size)
				throw std::invalid_argument("Mach-O: symtab out of range");
			if (size_t(st->stroff) + st->strsize > slice.size)
				throw std::invalid_argument("Mach-O: strtab out of range");
			sym_base = slice.base + st->symoff;
			nsyms = st->nsyms;
			strtab = reinterpret_cast<const char*>(slice.base + st->stroff);
			strsize = st->strsize;
		}

		lc_cursor += lc->cmdsize;
	}

	if (sym_base == nullptr || strtab == nullptr)
		throw std::invalid_argument("Mach-O: no LC_SYMTAB");

	const uint8_t* vm_data = nullptr;
	const uint8_t* vm_instr = nullptr;
	const uint8_t* iso_data = nullptr;
	const uint8_t* iso_instr = nullptr;

	const auto* symtab = reinterpret_cast<const nlist_64*>(sym_base);
	for (uint32_t i = 0; i < nsyms; i++) {
		if (symtab[i].n_strx == 0 || symtab[i].n_strx >= strsize)
			continue;
		const char* name = strtab + symtab[i].n_strx;
		// Bounds-safe strcmp: we guaranteed n_strx < strsize but the string
		// itself can still run past the end if it's not null-terminated. Use
		// strnlen against the remaining bytes to cap the scan.
		size_t remaining = strsize - symtab[i].n_strx;
		size_t namelen = strnlen(name, remaining);
		if (namelen == remaining)
			continue;  // unterminated, skip
		if (matchesAny(name, kVmSnapshotDataSymbols, std::size(kVmSnapshotDataSymbols))) {
			vm_data = vmToPtr(slice, sections, symtab[i].n_value);
		}
		else if (matchesAny(name, kVmSnapshotInstructionsSymbols, std::size(kVmSnapshotInstructionsSymbols))) {
			vm_instr = vmToPtr(slice, sections, symtab[i].n_value);
		}
		else if (matchesAny(name, kIsolateSnapshotDataSymbols, std::size(kIsolateSnapshotDataSymbols))) {
			iso_data = vmToPtr(slice, sections, symtab[i].n_value);
		}
		else if (matchesAny(name, kIsolateSnapshotInstructionsSymbols, std::size(kIsolateSnapshotInstructionsSymbols))) {
			iso_instr = vmToPtr(slice, sections, symtab[i].n_value);
		}
	}

	if (vm_data == nullptr)
		throw std::invalid_argument("Mach-O: missing _kDartVmSnapshotData");
	if (vm_instr == nullptr)
		throw std::invalid_argument("Mach-O: missing _kDartVmSnapshotInstructions");
	if (iso_data == nullptr)
		throw std::invalid_argument("Mach-O: missing _kDartIsolateSnapshotData");
	if (iso_instr == nullptr)
		throw std::invalid_argument("Mach-O: missing _kDartIsolateSnapshotInstructions");

	return LibAppInfo{
		.lib = slice.base,
		.vm_snapshot_data = vm_data,
		.vm_snapshot_instructions = vm_instr,
		.isolate_snapshot_data = iso_data,
		.isolate_snapshot_instructions = iso_instr,
	};
}

#ifdef _WIN32
struct MappedFile {
	void* data;
	size_t size;
};

MappedFile mmap_file(const char* path) {
	HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		throw std::invalid_argument("Mach-O: cannot open file");
	LARGE_INTEGER sz;
	GetFileSizeEx(hFile, &sz);
	HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	void* mem = MapViewOfFile(hMap, FILE_MAP_COPY, 0, 0, 0);
	CloseHandle(hMap);
	CloseHandle(hFile);
	return MappedFile{ mem, static_cast<size_t>(sz.QuadPart) };
}
#else
struct MappedFile {
	void* data;
	size_t size;
};

MappedFile mmap_file(const char* path) {
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		throw std::invalid_argument("Mach-O: cannot open file");
	struct stat st;
	if (fstat(fd, &st) != 0) {
		close(fd);
		throw std::invalid_argument("Mach-O: cannot stat file");
	}
	void* mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);
	if (mem == MAP_FAILED)
		throw std::invalid_argument("Mach-O: mmap failed");
	return MappedFile{ mem, static_cast<size_t>(st.st_size) };
}
#endif

} // namespace

bool MachOHelper::IsMachO(const uint8_t* data, size_t size) {
	if (size < 4)
		return false;
	uint32_t magic_le;
	std::memcpy(&magic_le, data, sizeof(magic_le));
	if (magic_le == MH_MAGIC_64)
		return true;
	// FAT magic is big-endian on disk; read as BE and check.
	uint32_t magic_be = bswap32(magic_le);
	return magic_be == FAT_MAGIC || magic_be == FAT_MAGIC_64;
}

LibAppInfo MachOHelper::findSnapshots(const uint8_t* data, size_t size) {
	if (size < 4)
		throw std::invalid_argument("Mach-O: file too small");
	uint32_t magic_le;
	std::memcpy(&magic_le, data, sizeof(magic_le));
	uint32_t magic_be = bswap32(magic_le);

	if (magic_be == FAT_MAGIC || magic_be == FAT_MAGIC_64) {
		SliceView slice = pickFatSlice(data, size);
		return parseThinSlice(slice);
	}
	if (magic_le != MH_MAGIC_64)
		throw std::invalid_argument("Mach-O: unsupported magic");

	SliceView slice{ data, size, 0 };
	return parseThinSlice(slice);
}

LibAppInfo MachOHelper::MapLibApp(const char* path) {
	MappedFile m = mmap_file(path);
	return findSnapshots(reinterpret_cast<const uint8_t*>(m.data), m.size);
}
