#pragma once
// C++ port of tests/macho_fixture.py — builds minimal Mach-O 64 thin dylibs
// and FAT containers so the MachOHelper parser can be driven without a real
// iOS binary on disk.
//
// Layout deliberately mirrors the Python version so the two can be diffed.
// Header-only by design: each test translation unit includes this directly.

#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace macho_fixture {

constexpr uint32_t MH_MAGIC_64    = 0xFEEDFACFu;
constexpr int32_t  CPU_TYPE_ARM64  = 0x0100000C;
constexpr int32_t  CPU_TYPE_X86_64 = 0x01000007;
constexpr uint32_t MH_DYLIB       = 6;
constexpr uint32_t LC_SEGMENT_64  = 0x19;
constexpr uint32_t LC_SYMTAB      = 0x02;
constexpr uint32_t FAT_MAGIC      = 0xCAFEBABEu;

struct Section {
    std::string segname;
    std::string sectname;
    std::vector<uint8_t> data;
};

struct Symbol {
    std::string name;
    size_t section_index = 0;
    uint64_t offset = 0;
};

struct BuiltMachO {
    std::vector<uint8_t> bytes;
    std::vector<uint64_t> section_vmaddrs;
    std::vector<uint32_t> section_file_offsets;
    std::vector<uint64_t> symbol_vmaddrs;
};

struct ThinOpts {
    int32_t cputype = CPU_TYPE_ARM64;
    std::string segname = "__DATA_CONST";
    uint64_t vmaddr_base = 0x100000000ULL;
};

namespace detail {

inline void pack_le16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v));
    out.push_back(static_cast<uint8_t>(v >> 8));
}
inline void pack_le32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
inline void pack_le64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
inline void pack_fixed_string(std::vector<uint8_t>& out, const std::string& s, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        out.push_back(i < s.size() ? static_cast<uint8_t>(s[i]) : 0);
    }
}
inline void write_be32(uint8_t* dst, uint32_t v) {
    dst[0] = static_cast<uint8_t>(v >> 24);
    dst[1] = static_cast<uint8_t>(v >> 16);
    dst[2] = static_cast<uint8_t>(v >> 8);
    dst[3] = static_cast<uint8_t>(v);
}

} // namespace detail

inline BuiltMachO build_thin(
    const std::vector<Section>& sections,
    const std::vector<Symbol>& symbols = {},
    ThinOpts opts = {})
{
    const uint32_t nsect = static_cast<uint32_t>(sections.size());
    const uint32_t seg_cmd_size = 72 + 80 * nsect;
    const uint32_t symtab_cmd_size = 24;
    const uint32_t sizeofcmds = seg_cmd_size + symtab_cmd_size;
    const uint32_t header_end = 32 + sizeofcmds;

    std::vector<uint32_t> sect_file_offsets;
    std::vector<uint64_t> sect_vmaddrs;
    std::vector<uint8_t> data_blob;
    uint32_t cursor = header_end;
    for (const auto& s : sections) {
        sect_file_offsets.push_back(cursor);
        sect_vmaddrs.push_back(opts.vmaddr_base + cursor);
        data_blob.insert(data_blob.end(), s.data.begin(), s.data.end());
        cursor += static_cast<uint32_t>(s.data.size());
    }

    const uint32_t seg_fileoff = header_end;
    const uint32_t seg_filesize = cursor - header_end;
    const uint64_t seg_vmaddr = opts.vmaddr_base + seg_fileoff;
    const uint64_t seg_vmsize = seg_filesize;

    const uint32_t symtab_offset = cursor;
    const uint32_t symtab_size = 16u * static_cast<uint32_t>(symbols.size());
    const uint32_t strtab_offset = symtab_offset + symtab_size;

    std::vector<uint8_t> strtab;
    strtab.push_back(0);
    std::vector<uint32_t> name_offsets;
    for (const auto& sym : symbols) {
        name_offsets.push_back(static_cast<uint32_t>(strtab.size()));
        strtab.insert(strtab.end(), sym.name.begin(), sym.name.end());
        strtab.push_back(0);
    }
    const uint32_t strtab_size = static_cast<uint32_t>(strtab.size());

    using detail::pack_le16;
    using detail::pack_le32;
    using detail::pack_le64;
    using detail::pack_fixed_string;

    std::vector<uint8_t> out;
    // Mach-O header "<IiiIIIII"
    pack_le32(out, MH_MAGIC_64);
    pack_le32(out, static_cast<uint32_t>(opts.cputype));
    pack_le32(out, 0);               // cpusubtype
    pack_le32(out, MH_DYLIB);        // filetype
    pack_le32(out, 2);               // ncmds
    pack_le32(out, sizeofcmds);
    pack_le32(out, 0);               // flags
    pack_le32(out, 0);               // reserved

    // LC_SEGMENT_64 "<II16sQQQQiiII"
    pack_le32(out, LC_SEGMENT_64);
    pack_le32(out, seg_cmd_size);
    pack_fixed_string(out, opts.segname, 16);
    pack_le64(out, seg_vmaddr);
    pack_le64(out, seg_vmsize);
    pack_le64(out, seg_fileoff);
    pack_le64(out, seg_filesize);
    pack_le32(out, 7);               // maxprot
    pack_le32(out, 3);               // initprot
    pack_le32(out, nsect);
    pack_le32(out, 0);               // flags

    for (uint32_t i = 0; i < nsect; ++i) {
        const auto& s = sections[i];
        // "<16s16sQQIIIIIIII"
        pack_fixed_string(out, s.sectname, 16);
        pack_fixed_string(out, s.segname, 16);
        pack_le64(out, sect_vmaddrs[i]);
        pack_le64(out, s.data.size());
        pack_le32(out, sect_file_offsets[i]);
        pack_le32(out, 0); // align
        pack_le32(out, 0); // reloff
        pack_le32(out, 0); // nreloc
        pack_le32(out, 0); // flags
        pack_le32(out, 0); // reserved1
        pack_le32(out, 0); // reserved2
        pack_le32(out, 0); // reserved3
    }

    // LC_SYMTAB "<IIIIII"
    pack_le32(out, LC_SYMTAB);
    pack_le32(out, symtab_cmd_size);
    pack_le32(out, symtab_offset);
    pack_le32(out, static_cast<uint32_t>(symbols.size()));
    pack_le32(out, strtab_offset);
    pack_le32(out, strtab_size);

    // Section data immediately follows the load commands.
    out.insert(out.end(), data_blob.begin(), data_blob.end());

    // Symbol entries "<IBBHQ"
    std::vector<uint64_t> symbol_vmaddrs;
    symbol_vmaddrs.reserve(symbols.size());
    for (size_t i = 0; i < symbols.size(); ++i) {
        const auto& sym = symbols[i];
        const uint64_t n_value = sect_vmaddrs[sym.section_index] + sym.offset;
        symbol_vmaddrs.push_back(n_value);
        pack_le32(out, name_offsets[i]);
        out.push_back(0x0F);          // n_type: N_SECT | N_EXT
        out.push_back(static_cast<uint8_t>(sym.section_index + 1)); // n_sect (1-based)
        pack_le16(out, 0);            // n_desc
        pack_le64(out, n_value);
    }

    out.insert(out.end(), strtab.begin(), strtab.end());

    return BuiltMachO{
        std::move(out),
        std::move(sect_vmaddrs),
        std::move(sect_file_offsets),
        std::move(symbol_vmaddrs),
    };
}

inline std::vector<uint8_t> build_fat(
    const std::vector<std::pair<int32_t, std::vector<uint8_t>>>& slices,
    uint32_t align_log2 = 12)
{
    const uint32_t nfat = static_cast<uint32_t>(slices.size());
    const uint32_t align = 1u << align_log2;
    const uint32_t header_and_entries = 8 + 20u * nfat;
    uint32_t cursor = header_and_entries;
    if (cursor % align) cursor += align - (cursor % align);

    struct Entry { int32_t cputype; uint32_t offset; uint32_t size; };
    std::vector<Entry> entries;
    std::vector<std::pair<uint32_t, const std::vector<uint8_t>*>> slice_blobs;
    for (const auto& [cputype, blob] : slices) {
        entries.push_back(Entry{ cputype, cursor, static_cast<uint32_t>(blob.size()) });
        slice_blobs.push_back({ cursor, &blob });
        cursor += static_cast<uint32_t>(blob.size());
        if (cursor % align) cursor += align - (cursor % align);
    }

    std::vector<uint8_t> out(cursor, 0);
    detail::write_be32(out.data() + 0, FAT_MAGIC);
    detail::write_be32(out.data() + 4, nfat);
    for (uint32_t i = 0; i < nfat; ++i) {
        uint8_t* entry = out.data() + 8 + 20u * i;
        detail::write_be32(entry +  0, static_cast<uint32_t>(entries[i].cputype));
        detail::write_be32(entry +  4, 0);                 // cpusubtype
        detail::write_be32(entry +  8, entries[i].offset);
        detail::write_be32(entry + 12, entries[i].size);
        detail::write_be32(entry + 16, align_log2);
    }
    for (const auto& [slice_off, blob] : slice_blobs) {
        if (!blob->empty())
            std::memcpy(out.data() + slice_off, blob->data(), blob->size());
    }
    return out;
}

} // namespace macho_fixture
