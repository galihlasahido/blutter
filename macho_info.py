"""Minimal Mach-O 64-bit parser.

Just enough to support Blutter's iOS detection flow:
    * file-format sniffing via magic
    * walk LC_SEGMENT_64 load commands to build a (sectname, segname) → (vmaddr, fileoff, size) map
    * walk LC_SYMTAB to resolve C symbol names to their virtual address
    * translate virtual addresses to absolute file offsets (works for fat containers)

Supports: thin Mach-O 64 (little-endian) and FAT (32-bit offsets). Other flavours
(Mach-O 32, Mach-O BE, FAT_64) are out of scope — iOS Flutter binaries are always
LE Mach-O 64.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional


MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE  # byte-swapped (big-endian Mach-O 64) — rejected
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF  # fat with 64-bit offsets — rejected (iOS does not ship these)

CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02


@dataclass
class MachOSection:
    sectname: str
    segname: str
    vmaddr: int
    fileoff: int   # relative to the slice start, not the container
    size: int


@dataclass
class MachOSymbol:
    name: str
    n_value: int
    n_sect: int


@dataclass
class MachOSlice:
    """A parsed Mach-O slice (either a thin file or one arch of a fat container)."""
    cputype: int
    base_file_offset: int  # where this slice starts in the container bytes
    sections: list[MachOSection] = field(default_factory=list)
    symbols: list[MachOSymbol] = field(default_factory=list)
    container_bytes: bytes = b""

    @property
    def arch(self) -> str:
        return {
            CPU_TYPE_ARM64: "arm64",
            CPU_TYPE_X86_64: "x64",
        }.get(self.cputype, f"unknown({self.cputype:#x})")

    def find_section(self, sectname: str, segname: Optional[str] = None) -> Optional[MachOSection]:
        for s in self.sections:
            if s.sectname == sectname and (segname is None or s.segname == segname):
                return s
        return None

    def find_symbol(self, *names: str) -> Optional[MachOSymbol]:
        wanted = set(names)
        for sym in self.symbols:
            if sym.name in wanted:
                return sym
        return None

    def vm_to_file_offset(self, vm_addr: int) -> Optional[int]:
        """Translate a virtual address to an absolute offset in the container bytes."""
        for s in self.sections:
            if s.size > 0 and s.vmaddr <= vm_addr < s.vmaddr + s.size:
                return self.base_file_offset + s.fileoff + (vm_addr - s.vmaddr)
        return None

    def section_bytes(self, section: MachOSection) -> bytes:
        start = self.base_file_offset + section.fileoff
        return self.container_bytes[start:start + section.size]


def sniff_format(data: bytes) -> str:
    """Return one of 'macho', 'fat-macho', 'unsupported-macho', 'not-macho'."""
    if len(data) < 4:
        return "not-macho"
    magic_le = struct.unpack_from("<I", data, 0)[0]
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_le == MH_MAGIC_64:
        return "macho"
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        return "fat-macho"
    if magic_le == MH_CIGAM_64 or magic_be == FAT_MAGIC_64:
        return "unsupported-macho"
    return "not-macho"


def parse(path: str, prefer_arch: str = "arm64") -> MachOSlice:
    with open(path, "rb") as f:
        data = f.read()
    return parse_bytes(data, prefer_arch)


def parse_bytes(data: bytes, prefer_arch: str = "arm64") -> MachOSlice:
    fmt = sniff_format(data)
    if fmt == "not-macho":
        raise ValueError("Not a Mach-O file")
    if fmt == "unsupported-macho":
        raise ValueError("Unsupported Mach-O flavour (big-endian or 64-bit FAT)")

    if fmt == "fat-macho":
        return _parse_fat(data, prefer_arch)
    return _parse_thin(data, base_offset=0, container=data)


def _parse_fat(data: bytes, prefer_arch: str) -> MachOSlice:
    _, nfat = struct.unpack_from(">II", data, 0)
    target_cpu = {"arm64": CPU_TYPE_ARM64, "x64": CPU_TYPE_X86_64}.get(prefer_arch, CPU_TYPE_ARM64)

    entries = []
    for i in range(nfat):
        offset = 8 + i * 20
        cputype, cpusubtype, file_offset, size, align = struct.unpack_from(">iiIII", data, offset)
        entries.append((cputype, file_offset, size))

    # Prefer an exact cputype match; fall back to first slice.
    picked = next(((cpu, off, sz) for cpu, off, sz in entries if cpu == target_cpu), None)
    if picked is None:
        picked = entries[0]
    cputype, file_offset, size = picked

    slice_data = data[file_offset:file_offset + size]
    return _parse_thin(slice_data, base_offset=file_offset, container=data)


def _parse_thin(slice_data: bytes, base_offset: int, container: bytes) -> MachOSlice:
    magic, cputype, _cpusub, _filetype, ncmds, _sizeofcmds, _flags, _reserved = \
        struct.unpack_from("<IiiIIIII", slice_data, 0)
    if magic != MH_MAGIC_64:
        raise ValueError(f"Not a 64-bit little-endian Mach-O slice (magic={magic:#x})")

    sl = MachOSlice(cputype=cputype, base_file_offset=base_offset, container_bytes=container)

    pos = 32  # sizeof(mach_header_64)
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", slice_data, pos)
        if cmd == LC_SEGMENT_64:
            _read_segment_cmd(slice_data, pos, sl)
        elif cmd == LC_SYMTAB:
            _read_symtab_cmd(slice_data, pos, sl)
        pos += cmdsize

    return sl


def _read_segment_cmd(slice_data: bytes, pos: int, sl: MachOSlice) -> None:
    # struct segment_command_64
    _cmd, _cmdsize, segname_raw, _vmaddr, _vmsize, _fileoff, _filesize, \
        _maxprot, _initprot, nsects, _flags = \
        struct.unpack_from("<II16sQQQQiiII", slice_data, pos)
    segname = segname_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")

    sect_pos = pos + 72  # after segment_command_64 header
    for _ in range(nsects):
        sect_bytes = slice_data[sect_pos:sect_pos + 80]
        sectname_raw, sect_segname_raw, s_addr, s_size, s_offset = \
            struct.unpack_from("<16s16sQQI", sect_bytes, 0)
        sectname = sectname_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        sect_segname = sect_segname_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace") or segname
        sl.sections.append(MachOSection(
            sectname=sectname, segname=sect_segname,
            vmaddr=s_addr, fileoff=s_offset, size=s_size,
        ))
        sect_pos += 80


def _read_symtab_cmd(slice_data: bytes, pos: int, sl: MachOSlice) -> None:
    _cmd, _cmdsize, symoff, nsyms, stroff, strsize = \
        struct.unpack_from("<IIIIII", slice_data, pos)
    strtab = slice_data[stroff:stroff + strsize]
    for i in range(nsyms):
        sym_pos = symoff + i * 16
        n_strx, _n_type, n_sect, _n_desc, n_value = \
            struct.unpack_from("<IBBHQ", slice_data, sym_pos)
        if n_strx == 0 or n_strx >= strsize:
            continue
        end = strtab.find(b"\x00", n_strx)
        if end == -1:
            continue
        name = strtab[n_strx:end].decode("ascii", errors="replace")
        sl.symbols.append(MachOSymbol(name=name, n_value=n_value, n_sect=n_sect))
