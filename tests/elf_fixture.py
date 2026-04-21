"""Tiny ELF64 fixture builder.

Produces a minimal but structurally valid ELF64 shared object with:
  - a loadable `.rodata` section holding a caller-supplied payload
  - a `.dynsym` with one named symbol (default: `_kDartVmSnapshotData`)
  - a `.dynstr` section

Importantly, the rodata section is placed such that ``st_value != file_offset``
so that a test exercises the section-based translation in
``extract_snapshot_hash_flags``. The fixture DOES NOT need to be loadable by a
real dynamic linker; it only needs to satisfy pyelftools' reader expectations.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass


# ELF constants
EI_MAG = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ET_DYN = 3
ET_EXEC = 2

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNSYM = 11

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

STB_GLOBAL = 1
STT_OBJECT = 1


def _align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


@dataclass
class BuiltElf:
    bytes_: bytes
    # Where (virtual address + file offset) the rodata payload lives.
    rodata_vaddr: int
    rodata_file_offset: int
    # Offset into the payload at which the symbol lives.
    symbol_vaddr: int
    symbol_file_offset: int


def build_elf64(
    payload: bytes,
    *,
    symbol_name: str = "_kDartVmSnapshotData",
    symbol_payload_offset: int = 0,
    symbol_size: int | None = None,
    e_machine: int = 183,  # EM_AARCH64
    rodata_vaddr_offset: int = 0x1000,
    extra_padding_before_rodata: int = 0,
) -> BuiltElf:
    """Build a minimal ELF64 ET_DYN image containing ``payload`` as rodata.

    The resulting object has ``rodata.sh_addr != rodata.sh_offset`` when
    ``rodata_vaddr_offset`` is provided, so the symbol's ``st_value`` will
    differ from its file offset — exactly the condition the regression test
    for the section-translation fix needs.
    """
    ehdr_size = 64
    phdr_size = 56  # unused here, but documented
    shdr_size = 64

    # Section names for shstrtab.
    shstr_names = ["", ".rodata", ".dynsym", ".dynstr", ".shstrtab"]
    shstrtab = b"\0"
    name_offsets = {"": 0}
    for n in shstr_names[1:]:
        name_offsets[n] = len(shstrtab)
        shstrtab += n.encode() + b"\0"

    # .dynstr: first byte NUL, then symbol_name + extra sentinel terminator.
    dynstr = b"\0" + symbol_name.encode() + b"\0"
    sym_name_offset = 1  # right after leading NUL

    # .dynsym: two entries (NULL + our symbol). Each symbol is 24 bytes.
    # struct Elf64_Sym { uint32 st_name; uint8 st_info; uint8 st_other;
    #                    uint16 st_shndx; uint64 st_value; uint64 st_size; }
    # Index of the rodata section in the header table: we fix the layout below.
    # Section header table order: [0]=NULL, [1]=.rodata, [2]=.dynsym, [3]=.dynstr, [4]=.shstrtab
    RODATA_SHNDX = 1

    # Compute layout:
    # File offsets in order: ehdr, rodata, dynsym, dynstr, shstrtab, shdrs.
    offset = ehdr_size
    offset += extra_padding_before_rodata
    rodata_file_offset = _align(offset, 16)
    rodata_vaddr = rodata_file_offset + rodata_vaddr_offset

    offset = rodata_file_offset + len(payload)
    dynsym_file_offset = _align(offset, 8)
    dynsym_size = 24 * 2  # NULL + our symbol
    offset = dynsym_file_offset + dynsym_size

    dynstr_file_offset = offset
    offset = dynstr_file_offset + len(dynstr)

    shstrtab_file_offset = _align(offset, 1)
    offset = shstrtab_file_offset + len(shstrtab)

    shdr_file_offset = _align(offset, 8)

    # Symbol value — virtual address within the rodata section.
    sym_value = rodata_vaddr + symbol_payload_offset
    sym_size = symbol_size if symbol_size is not None else len(payload) - symbol_payload_offset

    # Assemble ELF header.
    e_ident = (
        EI_MAG
        + bytes([ELFCLASS64, ELFDATA2LSB, EV_CURRENT, 0, 0])
        + b"\0" * 7
    )
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        ET_DYN,               # e_type
        e_machine,            # e_machine
        EV_CURRENT,           # e_version
        0,                    # e_entry
        0,                    # e_phoff
        shdr_file_offset,     # e_shoff
        0,                    # e_flags
        ehdr_size,            # e_ehsize
        phdr_size,            # e_phentsize
        0,                    # e_phnum
        shdr_size,            # e_shentsize
        5,                    # e_shnum
        4,                    # e_shstrndx (index of .shstrtab)
    )

    # Assemble section headers.
    def make_shdr(name_off, sh_type, flags, addr, off, size, link=0, info=0, align=1, entsize=0):
        return struct.pack(
            "<IIQQQQIIQQ",
            name_off, sh_type, flags, addr, off, size, link, info, align, entsize,
        )

    shdrs = b""
    # [0] NULL
    shdrs += make_shdr(0, SHT_NULL, 0, 0, 0, 0)
    # [1] .rodata
    shdrs += make_shdr(
        name_offsets[".rodata"], SHT_PROGBITS, SHF_ALLOC,
        rodata_vaddr, rodata_file_offset, len(payload), align=16,
    )
    # [2] .dynsym (link -> index of .dynstr, info = 1 = one local before globals)
    shdrs += make_shdr(
        name_offsets[".dynsym"], SHT_DYNSYM, SHF_ALLOC,
        0, dynsym_file_offset, dynsym_size, link=3, info=1, align=8, entsize=24,
    )
    # [3] .dynstr
    shdrs += make_shdr(
        name_offsets[".dynstr"], SHT_STRTAB, SHF_ALLOC,
        0, dynstr_file_offset, len(dynstr), align=1,
    )
    # [4] .shstrtab
    shdrs += make_shdr(
        name_offsets[".shstrtab"], SHT_STRTAB, 0,
        0, shstrtab_file_offset, len(shstrtab), align=1,
    )

    # Assemble .dynsym entries.
    dynsym_null = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    st_info = (STB_GLOBAL << 4) | STT_OBJECT
    dynsym_entry = struct.pack(
        "<IBBHQQ",
        sym_name_offset,
        st_info,
        0,            # st_other
        RODATA_SHNDX, # st_shndx
        sym_value,    # st_value
        sym_size,     # st_size
    )
    dynsym_blob = dynsym_null + dynsym_entry

    # Pack into a single buffer with correct padding.
    buf = bytearray()
    buf += ehdr
    # pad up to rodata_file_offset
    buf += b"\0" * (rodata_file_offset - len(buf))
    buf += payload
    buf += b"\0" * (dynsym_file_offset - len(buf))
    buf += dynsym_blob
    buf += b"\0" * (dynstr_file_offset - len(buf))
    buf += dynstr
    buf += b"\0" * (shstrtab_file_offset - len(buf))
    buf += shstrtab
    buf += b"\0" * (shdr_file_offset - len(buf))
    buf += shdrs

    return BuiltElf(
        bytes_=bytes(buf),
        rodata_vaddr=rodata_vaddr,
        rodata_file_offset=rodata_file_offset,
        symbol_vaddr=sym_value,
        symbol_file_offset=rodata_file_offset + symbol_payload_offset,
    )


def build_libflutter_rodata(
    *,
    engine_ids=("a" * 40, "b" * 40),
    version_line: str | None = None,
    e_machine: int = 183,
) -> bytes:
    """Build a libflutter-like ELF image whose `.rodata` contains SHA hashes
    and optionally a version string (`X (stable)`)."""
    # Pad with leading zeros so the `\x00<sha>\x00` pattern matches the look-ahead regex.
    pieces = [b"\0"]
    for eid in engine_ids:
        pieces.append(eid.encode() + b"\0")
    if version_line:
        pieces.append(b"\0" + version_line.encode() + b"\0")
    payload = b"".join(pieces)
    built = build_elf64(payload, symbol_name="_flutter_version_marker", e_machine=e_machine)
    # .rodata section name must match what extract_libflutter_info looks up.
    return built.bytes_
