"""Tests for extract_dart_info.py.

Key regressions covered:
  * architecture detection uses EM_X86_64 (was EM_IA_64)
  * snapshot hash file offset translated via section mapping
    (was: st_value used as raw file offset, broken for ET_DYN)
"""
from __future__ import annotations

import pytest

import extract_dart_info

from tests.elf_fixture import build_elf64


def _make_snapshot_payload(snapshot_hash: str, flags: str) -> bytes:
    """Layout mirrors the 20-byte header + 32-byte hash + flags string that
    real Dart VM snapshot data presents starting at `_kDartVmSnapshotData`."""
    assert len(snapshot_hash) == 32
    header = b"\xaa" * 20
    flags_bytes = flags.encode() + b"\0"
    tail = b"\0" * 64  # padding so f.read(256) does not fall off a real file
    return header + snapshot_hash.encode() + flags_bytes + tail


class TestSnapshotHashExtraction:
    def test_basic_hash_and_flags(self, tmp_path):
        snapshot_hash = "0" * 32
        flags = "product no-code_comments compressed-pointers"
        payload = _make_snapshot_payload(snapshot_hash, flags)
        built = build_elf64(payload, symbol_size=200)
        lib = tmp_path / "libapp.so"
        lib.write_bytes(built.bytes_)

        h, got_flags = extract_dart_info.extract_snapshot_hash_flags(str(lib))
        assert h == snapshot_hash
        assert got_flags == flags.split(" ")

    def test_regression_vaddr_differs_from_file_offset(self, tmp_path):
        """When st_value is not equal to the file offset (typical for ET_DYN),
        the section-based translation in extract_snapshot_hash_flags must kick in.
        With the old code (`f.seek(st_value+20)`), this test returns garbage."""
        snapshot_hash = "f" * 32
        flags = "product compressed-pointers"
        payload = _make_snapshot_payload(snapshot_hash, flags)
        built = build_elf64(
            payload, symbol_size=200, rodata_vaddr_offset=0x10000
        )
        assert built.symbol_vaddr != built.symbol_file_offset

        lib = tmp_path / "libapp.so"
        lib.write_bytes(built.bytes_)

        h, got_flags = extract_dart_info.extract_snapshot_hash_flags(str(lib))
        assert h == snapshot_hash
        assert got_flags == flags.split(" ")


class TestArchitectureDetection:
    def _build_libflutter(self, tmp_path, e_machine):
        # Build an ELF with .rodata containing the two engine-id SHA hashes and a
        # version line, then patch the arch field.
        engine_id_a = "a" * 40
        engine_id_b = "b" * 40
        version = "3.8.0 (stable)"
        payload = (
            b"\0" + engine_id_a.encode() + b"\0" +
            engine_id_b.encode() + b"\0" +
            b"\0" + version.encode() + b"\0"
        )
        built = build_elf64(payload, e_machine=e_machine, symbol_name="_flutter_marker")
        lib = tmp_path / "libflutter.so"
        lib.write_bytes(built.bytes_)
        return lib

    def test_arm64(self, tmp_path):
        lib = self._build_libflutter(tmp_path, 183)  # EM_AARCH64
        engine_ids, dart_version, arch, os_name = (
            extract_dart_info.extract_libflutter_info(str(lib))
        )
        assert arch == "arm64"
        assert os_name == "android"
        assert dart_version == "3.8.0"
        assert set(engine_ids) == {"a" * 40, "b" * 40}

    def test_x86_64_regression(self, tmp_path):
        """Previously extract_libflutter_info checked EM_IA_64 (Itanium, 50)
        which never matches an x86-64 libflutter. This test pins the fix."""
        lib = self._build_libflutter(tmp_path, 62)  # EM_X86_64
        _, _, arch, _ = extract_dart_info.extract_libflutter_info(str(lib))
        assert arch == "x64"

    def test_unsupported_arch_asserts(self, tmp_path):
        lib = self._build_libflutter(tmp_path, 40)  # EM_ARM (32-bit)
        with pytest.raises(AssertionError, match="Unsupport architecture"):
            extract_dart_info.extract_libflutter_info(str(lib))


class TestEngineHashCount:
    """Regression coverage for the hardening that drops the hard-coded
    `assert len(engine_ids) == 2`. Real libflutter builds have shipped with
    1, 2, or 3 SHA hashes at various times."""

    def _lib_with_hashes(self, tmp_path, hashes, version="3.8.0 (stable)"):
        payload = b"\x00" + b"\x00".join(h.encode() for h in hashes) + b"\x00"
        payload += b"\x00" + version.encode() + b"\x00"
        built = build_elf64(payload, symbol_name="_flutter_marker")
        lib = tmp_path / "libflutter.so"
        lib.write_bytes(built.bytes_)
        return lib

    def test_single_hash(self, tmp_path):
        lib = self._lib_with_hashes(tmp_path, ["a" * 40])
        engine_ids, _, _, _ = extract_dart_info.extract_libflutter_info(str(lib))
        assert engine_ids == ["a" * 40]

    def test_three_hashes(self, tmp_path):
        lib = self._lib_with_hashes(tmp_path, ["a" * 40, "b" * 40, "c" * 40])
        engine_ids, _, _, _ = extract_dart_info.extract_libflutter_info(str(lib))
        assert set(engine_ids) == {"a" * 40, "b" * 40, "c" * 40}

    def test_duplicate_hashes_collapsed(self, tmp_path):
        lib = self._lib_with_hashes(tmp_path, ["a" * 40, "a" * 40, "b" * 40])
        engine_ids, _, _, _ = extract_dart_info.extract_libflutter_info(str(lib))
        # Preserves insertion order but dedupes.
        assert engine_ids == ["a" * 40, "b" * 40]

    def test_no_hashes_no_version_raises(self, tmp_path):
        # Must raise when neither hashes nor a Dart version string are present.
        built = build_elf64(b"\x00no-hashes-here\x00", symbol_name="_flutter_marker")
        lib = tmp_path / "libflutter.so"
        lib.write_bytes(built.bytes_)
        with pytest.raises(AssertionError, match="Dart version string or engine SHA"):
            extract_dart_info.extract_libflutter_info(str(lib))

    def test_version_without_hashes_ok(self, tmp_path):
        # iOS Flutter.framework often has the stamped version string but no
        # embedded SHA-1 engine hashes. That must be accepted.
        payload = b"\x00" + b"3.11.4 (stable) (...) on \"ios_arm64\"" + b"\x00"
        built = build_elf64(payload, symbol_name="_flutter_marker")
        lib = tmp_path / "libflutter.so"
        lib.write_bytes(built.bytes_)
        engine_ids, dart_version, _, _ = extract_dart_info.extract_libflutter_info(str(lib))
        assert engine_ids == []
        assert dart_version == "3.11.4"


class TestResolveLibPair:
    """extract_dart_info CLI must accept both Android and iOS layouts."""

    def test_android_layout(self, tmp_path):
        (tmp_path / "libapp.so").write_bytes(b"")
        (tmp_path / "libflutter.so").write_bytes(b"")
        app, flutter = extract_dart_info._resolve_lib_pair(str(tmp_path))
        assert app.endswith("libapp.so")
        assert flutter.endswith("libflutter.so")

    def test_ios_framework_layout(self, tmp_path):
        (tmp_path / "App.framework").mkdir()
        (tmp_path / "App.framework" / "App").write_bytes(b"")
        (tmp_path / "Flutter.framework").mkdir()
        (tmp_path / "Flutter.framework" / "Flutter").write_bytes(b"")
        app, flutter = extract_dart_info._resolve_lib_pair(str(tmp_path))
        assert app.endswith("App.framework/App")
        assert flutter.endswith("Flutter.framework/Flutter")

    def test_ios_flat_layout(self, tmp_path):
        (tmp_path / "App").write_bytes(b"")
        (tmp_path / "Flutter").write_bytes(b"")
        app, flutter = extract_dart_info._resolve_lib_pair(str(tmp_path))
        assert app.endswith("/App")
        assert flutter.endswith("/Flutter")

    def test_no_layout_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="libapp/libflutter pair"):
            extract_dart_info._resolve_lib_pair(str(tmp_path))

    def test_android_precedence_over_ios(self, tmp_path):
        # If for some reason both exist, Android layout wins (arbitrary but stable).
        (tmp_path / "libapp.so").write_bytes(b"")
        (tmp_path / "libflutter.so").write_bytes(b"")
        (tmp_path / "App").write_bytes(b"")
        (tmp_path / "Flutter").write_bytes(b"")
        app, flutter = extract_dart_info._resolve_lib_pair(str(tmp_path))
        assert app.endswith("libapp.so")
        assert flutter.endswith("libflutter.so")
