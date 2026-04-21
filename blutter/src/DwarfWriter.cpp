#include "pch.h"
#include "DwarfWriter.h"
#include "DartClass.h"
#include "DartFunction.h"
#include "DartLibrary.h"
#include "DartStub.h"
#include <fstream>
#include <unordered_map>

namespace {

// DWARF v5 constants — only the subset we emit. See dwarf.h / DWARF-5 spec.
constexpr uint16_t DW_TAG_compile_unit = 0x11;
constexpr uint16_t DW_TAG_subprogram   = 0x2e;
constexpr uint8_t  DW_CHILDREN_yes = 1;
constexpr uint8_t  DW_CHILDREN_no  = 0;
constexpr uint16_t DW_AT_name     = 0x03;
constexpr uint16_t DW_AT_low_pc   = 0x11;
constexpr uint16_t DW_AT_high_pc  = 0x12;
constexpr uint16_t DW_AT_language = 0x13;
constexpr uint16_t DW_AT_comp_dir = 0x1b;
constexpr uint16_t DW_AT_producer = 0x25;
constexpr uint16_t DW_FORM_addr   = 0x01;
constexpr uint16_t DW_FORM_data8  = 0x07;
constexpr uint16_t DW_FORM_data1  = 0x0b;
constexpr uint16_t DW_FORM_strp   = 0x0e;
constexpr uint8_t  DW_UT_compile  = 0x01;
constexpr uint16_t DW_LANG_C_plus_plus = 0x04;

// ELF64 constants — handwritten to avoid pulling in <elf.h>, which is not
// available on all host platforms (notably macOS without a Linux sysroot).
constexpr uint8_t  ELF_MAG0 = 0x7f;
constexpr uint8_t  ELFCLASS64 = 2;
constexpr uint8_t  ELFDATA2LSB = 1;
constexpr uint8_t  EV_CURRENT = 1;
constexpr uint16_t ET_REL = 1;
constexpr uint16_t EM_AARCH64 = 183;
constexpr uint32_t SHT_PROGBITS = 1;
constexpr uint32_t SHT_SYMTAB   = 2;
constexpr uint32_t SHT_STRTAB   = 3;
constexpr uint64_t SHF_MERGE    = 0x10;
constexpr uint64_t SHF_STRINGS  = 0x20;
constexpr uint16_t SHN_ABS = 0xfff1;
constexpr uint8_t  STB_LOCAL = 0;
constexpr uint8_t  STT_FILE  = 4;
constexpr uint8_t  STT_FUNC  = 2;
constexpr uint8_t  STV_DEFAULT = 0;

struct ByteBuf {
	std::vector<uint8_t> data;
	size_t size() const { return data.size(); }
	const uint8_t* bytes() const { return data.data(); }
	void u8(uint8_t v) { data.push_back(v); }
	void u16(uint16_t v) { u8(v & 0xff); u8((v >> 8) & 0xff); }
	void u32(uint32_t v) { u16(v & 0xffff); u16((v >> 16) & 0xffff); }
	void u64(uint64_t v) { u32(v & 0xffffffff); u32((v >> 32) & 0xffffffff); }
	void uleb128(uint64_t v) {
		do {
			uint8_t b = v & 0x7f;
			v >>= 7;
			if (v != 0) b |= 0x80;
			data.push_back(b);
		} while (v != 0);
	}
	void put_u32_at(size_t off, uint32_t v) {
		data[off + 0] = v & 0xff;
		data[off + 1] = (v >> 8) & 0xff;
		data[off + 2] = (v >> 16) & 0xff;
		data[off + 3] = (v >> 24) & 0xff;
	}
};

// String-table builder that dedups identical strings and hands out offsets
// into a single NUL-separated blob. Index 0 is reserved for the empty string
// (required convention for ELF .strtab / .shstrtab; harmless for .debug_str).
class StrTab {
public:
	StrTab() { buf_.u8(0); }
	uint32_t add(const std::string& s) {
		auto it = cache_.find(s);
		if (it != cache_.end()) return it->second;
		uint32_t off = (uint32_t)buf_.size();
		for (char c : s) buf_.u8((uint8_t)c);
		buf_.u8(0);
		cache_.emplace(s, off);
		return off;
	}
	const ByteBuf& buf() const { return buf_; }
private:
	ByteBuf buf_;
	std::unordered_map<std::string, uint32_t> cache_;
};

struct FnRec { std::string name; uint64_t addr; uint64_t size; };

// Elf64_Sym is 24 bytes. We pack it inline rather than pulling in <elf.h>.
void packSymbol(ByteBuf& out, uint32_t nameOff, uint8_t info,
				uint8_t other, uint16_t shndx, uint64_t value, uint64_t size)
{
	out.u32(nameOff);
	out.u8(info);
	out.u8(other);
	out.u16(shndx);
	out.u64(value);
	out.u64(size);
}

} // namespace

void DwarfWriter::Create(const char* filename)
{
	// ---- Collect (name, addr, size) records for every function + stub ----
	std::vector<FnRec> fns;
	fns.reserve(app.functions.size() + app.stubs.size());
	for (auto lib : app.libs) {
		for (auto cls : lib->classes) {
			for (auto dartFn : cls->Functions()) {
				if (dartFn->Size() <= 0) continue;
				std::string name = lib->GetName();
				const std::string& clsName = cls->Name();
				if (!clsName.empty()) { name += "::"; name += clsName; }
				name += "::"; name += dartFn->Name();
				fns.push_back({ std::move(name), dartFn->Address(), (uint64_t)dartFn->Size() });
			}
		}
	}
	for (const auto& [addr, stub] : app.stubs) {
		if (!stub || stub->Size() <= 0) continue;
		fns.push_back({ stub->FullName(), stub->Address(), (uint64_t)stub->Size() });
	}

	// ---- .debug_str ----
	StrTab debugStr;
	const uint32_t strProducer = debugStr.add("Blutter");
	const uint32_t strCuName   = debugStr.add("libapp");
	const uint32_t strCompDir  = debugStr.add(".");
	std::vector<uint32_t> fnNameOffs;
	fnNameOffs.reserve(fns.size());
	for (const auto& f : fns) fnNameOffs.push_back(debugStr.add(f.name));

	// ---- .debug_abbrev ----
	// Two abbrevs: compile_unit (has children) and subprogram (no children).
	ByteBuf abbrev;
	abbrev.uleb128(1);
	abbrev.uleb128(DW_TAG_compile_unit);
	abbrev.u8(DW_CHILDREN_yes);
	abbrev.uleb128(DW_AT_producer); abbrev.uleb128(DW_FORM_strp);
	abbrev.uleb128(DW_AT_language); abbrev.uleb128(DW_FORM_data1);
	abbrev.uleb128(DW_AT_name);     abbrev.uleb128(DW_FORM_strp);
	abbrev.uleb128(DW_AT_comp_dir); abbrev.uleb128(DW_FORM_strp);
	abbrev.uleb128(0); abbrev.uleb128(0);

	abbrev.uleb128(2);
	abbrev.uleb128(DW_TAG_subprogram);
	abbrev.u8(DW_CHILDREN_no);
	abbrev.uleb128(DW_AT_name);    abbrev.uleb128(DW_FORM_strp);
	abbrev.uleb128(DW_AT_low_pc);  abbrev.uleb128(DW_FORM_addr);
	abbrev.uleb128(DW_AT_high_pc); abbrev.uleb128(DW_FORM_data8);
	abbrev.uleb128(0); abbrev.uleb128(0);

	abbrev.uleb128(0); // end of abbrev table

	// ---- .debug_info ----
	// Single compile unit. DW_AT_high_pc is emitted as data8 (offset from
	// low_pc), per DWARF-4+ convention which DWARF-5 continues.
	ByteBuf info;
	const size_t unitLengthOff = info.size();
	info.u32(0);              // unit_length — back-patched after body written
	info.u16(5);              // version
	info.u8(DW_UT_compile);
	info.u8(8);               // address_size
	info.u32(0);              // debug_abbrev_offset (single CU at offset 0)

	info.uleb128(1);          // abbrev code -> compile_unit
	info.u32(strProducer);
	info.u8((uint8_t)DW_LANG_C_plus_plus);
	info.u32(strCuName);
	info.u32(strCompDir);
	for (size_t i = 0; i < fns.size(); ++i) {
		info.uleb128(2);      // abbrev code -> subprogram
		info.u32(fnNameOffs[i]);
		info.u64(fns[i].addr);
		info.u64(fns[i].size);
	}
	info.uleb128(0);          // end-of-children sibling for CU

	const uint32_t unitLength = (uint32_t)(info.size() - unitLengthOff - 4);
	info.put_u32_at(unitLengthOff, unitLength);

	// ---- .strtab + .symtab ----
	// Emit ELF symbols too: .debug_info alone suffices for `gdb ... -s file`,
	// but gdb's separate-debug-file machinery historically cross-checks the
	// .symtab, and adding it makes `nm` / `objdump -t` work.
	StrTab symStr;
	const uint32_t symFile = symStr.add("libapp");
	ByteBuf symtab;
	packSymbol(symtab, 0, 0, 0, 0, 0, 0); // STN_UNDEF
	packSymbol(symtab, symFile, (STB_LOCAL << 4) | STT_FILE, STV_DEFAULT, SHN_ABS, 0, 0);
	for (const auto& f : fns) {
		const uint32_t nameOff = symStr.add(f.name);
		packSymbol(symtab, nameOff, (STB_LOCAL << 4) | STT_FUNC, STV_DEFAULT, SHN_ABS, f.addr, f.size);
	}
	// All symbols are STB_LOCAL, so sh_info = number of local symbols = total.
	const uint32_t symtabInfo = (uint32_t)(symtab.size() / 24);

	// ---- .shstrtab ----
	StrTab shstr;
	const uint32_t n_shstrtab     = shstr.add(".shstrtab");
	const uint32_t n_strtab       = shstr.add(".strtab");
	const uint32_t n_symtab       = shstr.add(".symtab");
	const uint32_t n_debug_str    = shstr.add(".debug_str");
	const uint32_t n_debug_abbrev = shstr.add(".debug_abbrev");
	const uint32_t n_debug_info   = shstr.add(".debug_info");

	// ---- Layout ----
	// Section order in the file (also defines shdr index):
	//   0: NULL
	//   1: .shstrtab
	//   2: .strtab
	//   3: .symtab
	//   4: .debug_str
	//   5: .debug_abbrev
	//   6: .debug_info
	constexpr uint16_t idxShstrtab    = 1;
	constexpr uint16_t idxStrtab      = 2;
	constexpr uint16_t idxSymtab      = 3;
	constexpr uint16_t idxDebugStr    = 4;
	constexpr uint16_t idxDebugAbbrev = 5;
	constexpr uint16_t idxDebugInfo   = 6;
	constexpr uint16_t numSections    = 7;

	auto alignUp = [](uint64_t v, uint64_t a) { return (v + a - 1) & ~(a - 1); };

	uint64_t cur = 64; // after ELF header
	cur = alignUp(cur, 1);
	const uint64_t offShstrtab = cur;    cur += shstr.buf().size();
	cur = alignUp(cur, 1);
	const uint64_t offStrtab = cur;      cur += symStr.buf().size();
	cur = alignUp(cur, 8);
	const uint64_t offSymtab = cur;      cur += symtab.size();
	cur = alignUp(cur, 1);
	const uint64_t offDebugStr = cur;    cur += debugStr.buf().size();
	cur = alignUp(cur, 1);
	const uint64_t offDebugAbbrev = cur; cur += abbrev.size();
	cur = alignUp(cur, 1);
	const uint64_t offDebugInfo = cur;   cur += info.size();
	cur = alignUp(cur, 8);
	const uint64_t shoff = cur;

	// ---- Write file ----
	std::ofstream out(filename, std::ios::binary);

	// ELF header (64 bytes)
	ByteBuf eh;
	eh.u8(ELF_MAG0); eh.u8('E'); eh.u8('L'); eh.u8('F');
	eh.u8(ELFCLASS64); eh.u8(ELFDATA2LSB); eh.u8(EV_CURRENT); eh.u8(0);
	for (int i = 0; i < 8; ++i) eh.u8(0); // EI_ABIVERSION + padding
	eh.u16(ET_REL);
	eh.u16(EM_AARCH64);
	eh.u32(EV_CURRENT);
	eh.u64(0);          // e_entry
	eh.u64(0);          // e_phoff
	eh.u64(shoff);      // e_shoff
	eh.u32(0);          // e_flags
	eh.u16(64);         // e_ehsize
	eh.u16(0);          // e_phentsize
	eh.u16(0);          // e_phnum
	eh.u16(64);         // e_shentsize
	eh.u16(numSections);
	eh.u16(idxShstrtab);
	out.write(reinterpret_cast<const char*>(eh.bytes()), eh.size());

	auto padAndWrite = [&](uint64_t targetOff, const ByteBuf& b) {
		while ((uint64_t)out.tellp() < targetOff) out.put(0);
		out.write(reinterpret_cast<const char*>(b.bytes()), b.size());
	};
	padAndWrite(offShstrtab,    shstr.buf());
	padAndWrite(offStrtab,      symStr.buf());
	padAndWrite(offSymtab,      symtab);
	padAndWrite(offDebugStr,    debugStr.buf());
	padAndWrite(offDebugAbbrev, abbrev);
	padAndWrite(offDebugInfo,   info);

	while ((uint64_t)out.tellp() < shoff) out.put(0);

	// Section headers (64 bytes each)
	auto writeShdr = [&](uint32_t name, uint32_t type, uint64_t flags,
						 uint64_t addr, uint64_t offset, uint64_t size,
						 uint32_t link, uint32_t infoField,
						 uint64_t align, uint64_t entsize) {
		ByteBuf b;
		b.u32(name);
		b.u32(type);
		b.u64(flags);
		b.u64(addr);
		b.u64(offset);
		b.u64(size);
		b.u32(link);
		b.u32(infoField);
		b.u64(align);
		b.u64(entsize);
		out.write(reinterpret_cast<const char*>(b.bytes()), b.size());
	};
	// NULL
	writeShdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	// .shstrtab
	writeShdr(n_shstrtab,     SHT_STRTAB,   0, 0, offShstrtab,    shstr.buf().size(),  0, 0, 1, 0);
	// .strtab (for .symtab)
	writeShdr(n_strtab,       SHT_STRTAB,   0, 0, offStrtab,      symStr.buf().size(), 0, 0, 1, 0);
	// .symtab — link points to .strtab, info is index of first non-local (== count).
	writeShdr(n_symtab,       SHT_SYMTAB,   0, 0, offSymtab,      symtab.size(),
			  idxStrtab, symtabInfo, 8, 24);
	// .debug_str uses SHF_MERGE|SHF_STRINGS with entsize=1 per DWARF convention.
	writeShdr(n_debug_str,    SHT_PROGBITS, SHF_MERGE | SHF_STRINGS,
			  0, offDebugStr, debugStr.buf().size(), 0, 0, 1, 1);
	// .debug_abbrev
	writeShdr(n_debug_abbrev, SHT_PROGBITS, 0, 0, offDebugAbbrev, abbrev.size(), 0, 0, 1, 0);
	// .debug_info
	writeShdr(n_debug_info,   SHT_PROGBITS, 0, 0, offDebugInfo,   info.size(),   0, 0, 1, 0);
}
