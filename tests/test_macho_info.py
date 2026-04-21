"""Tests for the minimal Mach-O parser in ``macho_info``."""
from __future__ import annotations

import pytest

import macho_info

from tests.macho_fixture import (
    CPU_TYPE_ARM64,
    CPU_TYPE_X86_64,
    Section,
    Symbol,
    build_fat,
    build_thin,
)


class TestSniffFormat:
    def test_thin_macho(self):
        built = build_thin([Section("__DATA_CONST", "__const", b"\x00" * 16)])
        assert macho_info.sniff_format(built.bytes_) == "macho"

    def test_fat_macho(self):
        thin = build_thin([Section("__DATA_CONST", "__const", b"\x00" * 16)])
        fat = build_fat([(CPU_TYPE_ARM64, thin.bytes_)])
        assert macho_info.sniff_format(fat) == "fat-macho"

    def test_not_macho(self):
        assert macho_info.sniff_format(b"\x7fELFxxxx") == "not-macho"
        assert macho_info.sniff_format(b"PK\x03\x04") == "not-macho"

    def test_unsupported_big_endian_macho(self):
        # byte-swapped MH_MAGIC_64 — legitimately a Mach-O but not one we support.
        assert macho_info.sniff_format(b"\xcf\xfa\xed\xfe"[::-1]) in ("unsupported-macho", "not-macho")


class TestThinParser:
    def test_sections_discovered(self):
        sections = [
            Section("__TEXT", "__const", b"A" * 64),
            Section("__DATA_CONST", "__const", b"B" * 128),
        ]
        built = build_thin(sections)
        sl = macho_info.parse_bytes(built.bytes_)
        assert sl.arch == "arm64"
        assert len(sl.sections) == 2

        text_const = sl.find_section("__const", "__TEXT")
        assert text_const is not None
        assert text_const.size == 64

        data_const = sl.find_section("__const", "__DATA_CONST")
        assert data_const is not None
        assert data_const.size == 128

    def test_vm_to_file_offset(self):
        payload = b"helloworld" + b"\x00" * 100
        section = Section("__TEXT", "__const", payload)
        symbols = [Symbol(name="_kMarker", section_index=0, offset=5)]
        built = build_thin([section], symbols)
        sl = macho_info.parse_bytes(built.bytes_)

        sym = sl.find_symbol("_kMarker")
        assert sym is not None
        file_off = sl.vm_to_file_offset(sym.n_value)
        assert file_off is not None
        # The 5-byte offset inside "helloworld" lands on "world".
        assert sl.container_bytes[file_off:file_off + 5] == b"world"

    def test_symbol_lookup_multiple_names(self):
        section = Section("__TEXT", "__const", b"\x00" * 16)
        symbols = [Symbol(name="__kDartVmSnapshotData", section_index=0, offset=0)]
        built = build_thin([section], symbols)
        sl = macho_info.parse_bytes(built.bytes_)
        # find_symbol accepts multiple candidates (both the underscore-prefixed
        # Mach-O convention and the raw ELF-style name).
        assert sl.find_symbol("_kDartVmSnapshotData", "__kDartVmSnapshotData") is not None
        assert sl.find_symbol("_nonexistent") is None

    def test_section_bytes(self):
        section = Section("__TEXT", "__const", b"payload-XYZ")
        built = build_thin([section])
        sl = macho_info.parse_bytes(built.bytes_)
        s = sl.find_section("__const", "__TEXT")
        assert sl.section_bytes(s) == b"payload-XYZ"


class TestFatParser:
    def test_selects_arm64_slice_when_preferred(self):
        arm64 = build_thin([Section("__TEXT", "__const", b"arm64_marker\x00")],
                            cputype=CPU_TYPE_ARM64)
        x86 = build_thin([Section("__TEXT", "__const", b"x86_marker\x00")],
                          cputype=CPU_TYPE_X86_64)
        fat = build_fat([(CPU_TYPE_X86_64, x86.bytes_), (CPU_TYPE_ARM64, arm64.bytes_)])

        sl = macho_info.parse_bytes(fat, prefer_arch="arm64")
        assert sl.arch == "arm64"
        assert sl.base_file_offset > 0  # not at container origin
        # Container bytes still hold the whole FAT, so absolute offsets work.
        section = sl.find_section("__const", "__TEXT")
        assert sl.section_bytes(section).startswith(b"arm64_marker")

    def test_falls_back_to_first_slice_when_not_found(self):
        x86 = build_thin([Section("__TEXT", "__const", b"only_x86\x00")],
                         cputype=CPU_TYPE_X86_64)
        fat = build_fat([(CPU_TYPE_X86_64, x86.bytes_)])

        sl = macho_info.parse_bytes(fat, prefer_arch="arm64")
        assert sl.arch == "x64"  # fell back to the first (and only) slice

    def test_vm_to_file_offset_is_container_absolute(self):
        """A symbol in a fat slice must resolve to an absolute offset in the
        original container bytes, not relative to the slice."""
        section = Section("__TEXT", "__const", b"ABCDEF" + b"\x00" * 64)
        symbols = [Symbol(name="_marker", section_index=0, offset=2)]
        arm64 = build_thin([section], symbols, cputype=CPU_TYPE_ARM64)
        fat = build_fat([(CPU_TYPE_ARM64, arm64.bytes_)])

        sl = macho_info.parse_bytes(fat)
        sym = sl.find_symbol("_marker")
        file_off = sl.vm_to_file_offset(sym.n_value)
        assert file_off is not None
        # Container-absolute offset — must land on "CDEF..." in the fat bytes.
        assert sl.container_bytes[file_off:file_off + 4] == b"CDEF"
