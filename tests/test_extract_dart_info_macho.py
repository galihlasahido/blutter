"""Integration tests for the Mach-O paths in ``extract_dart_info``.

These mirror the ELF-side tests in ``test_extract_dart_info.py`` but build
Mach-O fixtures instead.
"""
from __future__ import annotations

import pytest

import extract_dart_info

from tests.macho_fixture import (
    CPU_TYPE_ARM64,
    CPU_TYPE_X86_64,
    Section,
    Symbol,
    build_fat,
    build_thin,
)


def _snapshot_payload(snapshot_hash: str, flags: str) -> bytes:
    assert len(snapshot_hash) == 32
    header = b"\xaa" * 20
    return header + snapshot_hash.encode() + flags.encode() + b"\x00" + b"\x00" * 64


class TestSnapshotHashFlagsMachO:
    def test_thin_arm64(self, tmp_path):
        snapshot_hash = "3" * 32
        flags = "product no-code_comments"
        payload = _snapshot_payload(snapshot_hash, flags)
        # Mach-O linker prepends an underscore to C symbols.
        built = build_thin(
            [Section("__DATA_CONST", "__const", payload)],
            [Symbol(name="__kDartVmSnapshotData", section_index=0, offset=0)],
        )
        lib = tmp_path / "App"
        lib.write_bytes(built.bytes_)

        h, got_flags = extract_dart_info.extract_snapshot_hash_flags(str(lib))
        assert h == snapshot_hash
        assert got_flags == flags.split(" ")

    def test_fat_container_picks_arm64(self, tmp_path):
        snapshot_hash = "7" * 32
        flags = "product compressed-pointers"
        payload = _snapshot_payload(snapshot_hash, flags)
        arm64 = build_thin(
            [Section("__DATA_CONST", "__const", payload)],
            [Symbol(name="__kDartVmSnapshotData", section_index=0, offset=0)],
            cputype=CPU_TYPE_ARM64,
        )
        # Second slice holds a different hash; arm64 preference must pick the
        # right slice, otherwise we'd read the wrong 32 bytes.
        other_payload = _snapshot_payload("0" * 32, "other")
        x86 = build_thin(
            [Section("__DATA_CONST", "__const", other_payload)],
            [Symbol(name="__kDartVmSnapshotData", section_index=0, offset=0)],
            cputype=CPU_TYPE_X86_64,
        )
        fat = build_fat([(CPU_TYPE_X86_64, x86.bytes_), (CPU_TYPE_ARM64, arm64.bytes_)])
        lib = tmp_path / "App"
        lib.write_bytes(fat)

        h, got_flags = extract_dart_info.extract_snapshot_hash_flags(str(lib))
        assert h == snapshot_hash
        assert got_flags == flags.split(" ")

    def test_missing_symbol_raises(self, tmp_path):
        built = build_thin([Section("__DATA_CONST", "__const", b"\x00" * 16)])
        lib = tmp_path / "App"
        lib.write_bytes(built.bytes_)
        with pytest.raises(RuntimeError, match="kDartVmSnapshotData"):
            extract_dart_info.extract_snapshot_hash_flags(str(lib))


class TestLibflutterInfoMachO:
    def _flutter_payload(self, engine_a: str, engine_b: str, version: str) -> bytes:
        return (
            b"\x00" + engine_a.encode() + b"\x00"
            + engine_b.encode() + b"\x00"
            + b"\x00" + version.encode() + b"\x00"
        )

    def test_arm64_ios(self, tmp_path):
        payload = self._flutter_payload("a" * 40, "b" * 40, "3.8.0 (stable)")
        built = build_thin(
            [Section("__TEXT", "__const", payload)],
            cputype=CPU_TYPE_ARM64,
        )
        lib = tmp_path / "Flutter"
        lib.write_bytes(built.bytes_)

        engine_ids, dart_version, arch, os_name = (
            extract_dart_info.extract_libflutter_info(str(lib))
        )
        assert set(engine_ids) == {"a" * 40, "b" * 40}
        assert dart_version == "3.8.0"
        assert arch == "arm64"
        assert os_name == "ios"

    def test_cstring_section_also_scanned(self, tmp_path):
        """Some versions put strings in __TEXT,__cstring; we must scan both."""
        payload = self._flutter_payload("c" * 40, "d" * 40, "3.7.0 (stable)")
        built = build_thin(
            [Section("__TEXT", "__cstring", payload)],
            cputype=CPU_TYPE_ARM64,
        )
        lib = tmp_path / "Flutter"
        lib.write_bytes(built.bytes_)

        engine_ids, dart_version, _, _ = (
            extract_dart_info.extract_libflutter_info(str(lib))
        )
        assert set(engine_ids) == {"c" * 40, "d" * 40}
        assert dart_version == "3.7.0"

    def test_fat_binary(self, tmp_path):
        payload = self._flutter_payload("e" * 40, "f" * 40, "3.10.0 (beta)")
        arm64 = build_thin(
            [Section("__TEXT", "__const", payload)],
            cputype=CPU_TYPE_ARM64,
        )
        fat = build_fat([(CPU_TYPE_ARM64, arm64.bytes_)])
        lib = tmp_path / "Flutter"
        lib.write_bytes(fat)

        _, dart_version, arch, os_name = (
            extract_dart_info.extract_libflutter_info(str(lib))
        )
        assert dart_version == "3.10.0"
        assert arch == "arm64"
        assert os_name == "ios"
