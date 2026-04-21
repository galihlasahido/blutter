"""Minimal Mach-O 64 builder for unit tests.

Produces enough of a Mach-O to exercise the parser in ``macho_info``:
  * valid magic + cputype + load command count
  * one LC_SEGMENT_64 containing any number of sections (each can be in a
    different segname, like real __TEXT vs __DATA_CONST)
  * optional LC_SYMTAB with arbitrary symbols tied to a section
  * layout deliberately uses vmaddr != fileoff so the vm→file translation
    path is covered

Also builds minimal FAT containers (32-bit offsets) with 1+ thin slices.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007
MH_DYLIB = 6
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02

FAT_MAGIC = 0xCAFEBABE


@dataclass
class Section:
    segname: str
    sectname: str
    data: bytes


@dataclass
class Symbol:
    name: str
    section_index: int  # index into the sections list
    offset: int = 0     # byte offset inside that section


@dataclass
class BuiltMachO:
    bytes_: bytes
    section_vmaddrs: list[int] = field(default_factory=list)
    section_file_offsets: list[int] = field(default_factory=list)
    symbol_vmaddrs: list[int] = field(default_factory=list)


def build_thin(
    sections: list[Section],
    symbols: Optional[list[Symbol]] = None,
    *,
    cputype: int = CPU_TYPE_ARM64,
    segname: str = "__DATA_CONST",
    vmaddr_base: int = 0x100000000,
) -> BuiltMachO:
    """Build a thin Mach-O 64 dylib.

    All sections live in a single segment whose segname is ``segname`` at the
    segment-header level, but each ``Section`` may declare a different segname
    — that mirrors how real Mach-O nests __TEXT,__const inside a __TEXT segment.
    The parser only looks at per-section segnames, so this is enough to drive it.
    """
    symbols = list(symbols or [])
    nsect = len(sections)

    seg_cmd_size = 72 + 80 * nsect
    symtab_cmd_size = 24
    sizeofcmds = seg_cmd_size + symtab_cmd_size
    header_end = 32 + sizeofcmds

    # Section data lives immediately after the load commands.
    sect_file_offsets = []
    sect_vmaddrs = []
    data_blob = b""
    cursor = header_end
    for s in sections:
        sect_file_offsets.append(cursor)
        sect_vmaddrs.append(vmaddr_base + cursor)  # vm != file on purpose
        data_blob += s.data
        cursor += len(s.data)

    seg_fileoff = header_end
    seg_filesize = cursor - header_end
    seg_vmaddr = vmaddr_base + seg_fileoff
    seg_vmsize = seg_filesize

    # Symbol + string tables come after the data blob.
    symtab_offset = cursor
    symtab_size = 16 * len(symbols)
    strtab_offset = symtab_offset + symtab_size
    strtab = b"\x00"  # byte 0 is the null "no name" entry
    name_offsets = []
    for sym in symbols:
        name_offsets.append(len(strtab))
        strtab += sym.name.encode("ascii") + b"\x00"
    strtab_size = len(strtab)

    # Mach-O header
    header = struct.pack(
        "<IiiIIIII",
        MH_MAGIC_64,
        cputype,
        0,           # cpusubtype
        MH_DYLIB,    # filetype
        2,           # ncmds (LC_SEGMENT_64 + LC_SYMTAB)
        sizeofcmds,
        0,           # flags
        0,           # reserved
    )

    segment_header = struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64,
        seg_cmd_size,
        segname.encode("ascii").ljust(16, b"\x00"),
        seg_vmaddr,
        seg_vmsize,
        seg_fileoff,
        seg_filesize,
        7,           # maxprot (rwx — arbitrary)
        3,           # initprot (rw-)
        nsect,
        0,           # flags
    )

    section_headers = b""
    for s, foff, vma in zip(sections, sect_file_offsets, sect_vmaddrs):
        section_headers += struct.pack(
            "<16s16sQQIIIIIIII",
            s.sectname.encode("ascii").ljust(16, b"\x00"),
            s.segname.encode("ascii").ljust(16, b"\x00"),
            vma,            # addr
            len(s.data),    # size
            foff,           # offset
            0,              # align
            0,              # reloff
            0,              # nreloc
            0,              # flags
            0,              # reserved1
            0,              # reserved2
            0,              # reserved3
        )

    symtab_header = struct.pack(
        "<IIIIII",
        LC_SYMTAB,
        symtab_cmd_size,
        symtab_offset,
        len(symbols),
        strtab_offset,
        strtab_size,
    )

    # Symbol entries (nlist_64)
    symbol_vmaddrs = []
    symtab_blob = b""
    for sym, name_off in zip(symbols, name_offsets):
        sect_idx = sym.section_index
        n_value = sect_vmaddrs[sect_idx] + sym.offset
        symbol_vmaddrs.append(n_value)
        symtab_blob += struct.pack(
            "<IBBHQ",
            name_off,
            0x0F,                  # n_type: N_SECT | N_EXT
            sect_idx + 1,          # n_sect (1-based)
            0,                     # n_desc
            n_value,
        )

    blob = (
        header
        + segment_header
        + section_headers
        + symtab_header
        + data_blob
        + symtab_blob
        + strtab
    )

    return BuiltMachO(
        bytes_=blob,
        section_vmaddrs=sect_vmaddrs,
        section_file_offsets=sect_file_offsets,
        symbol_vmaddrs=symbol_vmaddrs,
    )


def build_fat(slices: list[tuple[int, bytes]], align_log2: int = 12) -> bytes:
    """Build a FAT container (32-bit offsets) around the given (cputype, bytes) slices.

    Each slice is padded to the alignment boundary given by ``align_log2``
    (default 4096 bytes).
    """
    nfat = len(slices)
    align = 1 << align_log2
    header_and_entries = 8 + 20 * nfat
    # Figure out file offsets.
    cursor = header_and_entries
    if cursor % align:
        cursor += align - (cursor % align)

    entries = []
    slice_blobs = []
    for cputype, blob in slices:
        entries.append((cputype, cursor, len(blob)))
        slice_blobs.append((cursor, blob))
        cursor += len(blob)
        if cursor % align:
            cursor += align - (cursor % align)

    out = bytearray(cursor)
    struct.pack_into(">II", out, 0, FAT_MAGIC, nfat)
    for i, (cputype, offset, size) in enumerate(entries):
        struct.pack_into(
            ">iiIII", out, 8 + 20 * i,
            cputype, 0, offset, size, align_log2,
        )
    for offset, blob in slice_blobs:
        out[offset:offset + len(blob)] = blob
    return bytes(out)
