"""Tests for blutter.find_compat_macro.

Each test sets up a fake `packages/include/dartvm{ver}/vm/` tree with the five
header files the function reads, then monkey-patches ``PKG_INC_DIR`` so the
function runs against the fake tree.

The "post-commit" defaults below mirror a modern Dart (>=3.8) checkout: every
marker that triggers a legacy flag is ABSENT, and every marker that triggers a
modern flag is PRESENT. Individual tests override one marker at a time.
"""
import pytest

import blutter


# Post-commit content — emits zero flags by default.
DEFAULT_HEADERS = {
    "class_id.h": (
        "enum { kSomeCid = 1, kLastInternalOnlyCid = 42 };\n"
        "// V(ImmutableLinkedHashMap) intentionally absent: modern Dart uses Map/Set directly.\n"
    ),
    "class_table.h": "class ClassTable { };\n",
    "stub_code_list.h": "V(InitLateStaticField)\nV(InitLateFinalStaticField)\n",
    "object_store.h": "RW(Code, build_generic_method_extractor_code)\n",
    "object.h": "int64_t AsTruncatedInt64Value() const;\n",
}


def write_headers(tmp_path, version, overrides=None):
    """Create tmp_path/dartvm{version}/vm/ with five headers; return the tmp_path."""
    headers = dict(DEFAULT_HEADERS)
    if overrides:
        headers.update(overrides)
    vm_dir = tmp_path / f"dartvm{version}" / "vm"
    vm_dir.mkdir(parents=True)
    for name, content in headers.items():
        (vm_dir / name).write_text(content)
    return tmp_path


@pytest.fixture
def inc_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(blutter, "PKG_INC_DIR", str(tmp_path))
    return tmp_path


class TestDefaults:
    def test_modern_dart_emits_no_macros(self, inc_dir):
        write_headers(inc_dir, "3.8.0")
        assert blutter.find_compat_macro("3.8.0", no_analysis=False) == []

    def test_no_analysis_flag(self, inc_dir):
        write_headers(inc_dir, "3.8.0")
        assert blutter.find_compat_macro("3.8.0", no_analysis=True) == ["-DNO_CODE_ANALYSIS=1"]


class TestOldMapSetName:
    def test_linked_hash_map_triggers(self, inc_dir):
        write_headers(inc_dir, "2.17.0", overrides={
            "class_id.h": "V(LinkedHashMap)\nV(ImmutableLinkedHashMap)\nkLastInternalOnlyCid\n",
        })
        macros = blutter.find_compat_macro("2.17.0", no_analysis=False)
        assert "-DOLD_MAP_SET_NAME=1" in macros
        assert "-DOLD_MAP_NO_IMMUTABLE=1" not in macros

    def test_linked_hash_map_without_immutable(self, inc_dir):
        write_headers(inc_dir, "2.13.0", overrides={
            "class_id.h": "V(LinkedHashMap)\nkLastInternalOnlyCid\n",
        })
        macros = blutter.find_compat_macro("2.13.0", no_analysis=False)
        assert "-DOLD_MAP_SET_NAME=1" in macros
        assert "-DOLD_MAP_NO_IMMUTABLE=1" in macros


class TestLastInternalOnlyCid:
    def test_missing_marker_emits_flag(self, inc_dir):
        # Note: find_compat_macro greps for ' kLastInternalOnlyCid ' with surrounding
        # spaces, so the marker must be completely absent from the header contents.
        write_headers(inc_dir, "2.10.0", overrides={
            "class_id.h": "enum { kSomeCid = 1 };\n",
        })
        assert "-DNO_LAST_INTERNAL_ONLY_CID=1" in blutter.find_compat_macro("2.10.0", False)

    def test_marker_present_skips_flag(self, inc_dir):
        write_headers(inc_dir, "3.8.0")  # default has the marker
        assert "-DNO_LAST_INTERNAL_ONLY_CID=1" not in blutter.find_compat_macro("3.8.0", False)


class TestTypeRef:
    def test_type_ref_detected(self, inc_dir):
        write_headers(inc_dir, "2.19.0", overrides={
            "class_id.h": DEFAULT_HEADERS["class_id.h"] + "V(TypeRef)\n",
        })
        assert "-DHAS_TYPE_REF=1" in blutter.find_compat_macro("2.19.0", False)


class TestRecordType:
    def test_dart3_with_record_type(self, inc_dir):
        write_headers(inc_dir, "3.0.0", overrides={
            "class_id.h": DEFAULT_HEADERS["class_id.h"] + "V(RecordType)\n",
        })
        assert "-DHAS_RECORD_TYPE=1" in blutter.find_compat_macro("3.0.0", False)

    def test_dart2_ignores_record_type_even_if_present(self, inc_dir):
        write_headers(inc_dir, "2.19.0", overrides={
            "class_id.h": DEFAULT_HEADERS["class_id.h"] + "V(RecordType)\n",
        })
        # In Dart 2.19 the RecordType implementation is incomplete; must not set the flag.
        assert "-DHAS_RECORD_TYPE=1" not in blutter.find_compat_macro("2.19.0", False)

    def test_dart3_without_record_type(self, inc_dir):
        write_headers(inc_dir, "3.8.0")
        assert "-DHAS_RECORD_TYPE=1" not in blutter.find_compat_macro("3.8.0", False)


class TestSharedClassTable:
    def test_detected(self, inc_dir):
        write_headers(inc_dir, "2.17.0", overrides={
            "class_table.h": "class SharedClassTable { };\nclass ClassTable { };\n",
        })
        assert "-DHAS_SHARED_CLASS_TABLE=1" in blutter.find_compat_macro("2.17.0", False)

    def test_absent(self, inc_dir):
        write_headers(inc_dir, "3.8.0")
        assert "-DHAS_SHARED_CLASS_TABLE=1" not in blutter.find_compat_macro("3.8.0", False)


class TestInitLateStaticField:
    def test_missing_stub_triggers(self, inc_dir):
        write_headers(inc_dir, "2.12.0", overrides={
            "stub_code_list.h": "V(OtherStub)\n",
        })
        assert "-DNO_INIT_LATE_STATIC_FIELD=1" in blutter.find_compat_macro("2.12.0", False)

    def test_present_stub_skips(self, inc_dir):
        write_headers(inc_dir, "3.8.0")
        assert "-DNO_INIT_LATE_STATIC_FIELD=1" not in blutter.find_compat_macro("3.8.0", False)


class TestMethodExtractorStub:
    def test_missing_entry(self, inc_dir):
        write_headers(inc_dir, "3.0.0", overrides={
            "object_store.h": "// legacy object store with no method extractor code\n",
        })
        assert "-DNO_METHOD_EXTRACTOR_STUB=1" in blutter.find_compat_macro("3.0.0", False)

    def test_present_entry(self, inc_dir):
        write_headers(inc_dir, "3.8.0")
        assert "-DNO_METHOD_EXTRACTOR_STUB=1" not in blutter.find_compat_macro("3.8.0", False)


class TestUniformIntegerAccess:
    def test_missing_truncated_accessor(self, inc_dir):
        write_headers(inc_dir, "3.4.0", overrides={
            "object.h": "// AsInt64Value() only; no AsTruncatedInt64Value here\n",
        })
        assert "-DUNIFORM_INTEGER_ACCESS=1" in blutter.find_compat_macro("3.4.0", False)

    def test_truncated_accessor_present(self, inc_dir):
        write_headers(inc_dir, "2.19.0", overrides={
            "object.h": "int64_t AsTruncatedInt64Value() const;\n",
        })
        assert "-DUNIFORM_INTEGER_ACCESS=1" not in blutter.find_compat_macro("2.19.0", False)
