from dartvm_fetch_build import DartLibInfo


class TestDefaults:
    def test_android_default_has_compressed_ptrs(self):
        info = DartLibInfo("3.8.0", "android", "arm64")
        assert info.has_compressed_ptrs is True

    def test_ios_default_no_compressed_ptrs(self):
        info = DartLibInfo("3.8.0", "ios", "arm64")
        assert info.has_compressed_ptrs is False


class TestExplicitOverride:
    def test_force_no_compressed_ptrs_on_android(self):
        info = DartLibInfo("3.8.0", "android", "arm64", has_compressed_ptrs=False)
        assert info.has_compressed_ptrs is False

    def test_force_compressed_ptrs_on_ios(self):
        info = DartLibInfo("3.8.0", "ios", "arm64", has_compressed_ptrs=True)
        assert info.has_compressed_ptrs is True


class TestLibName:
    def test_android_arm64_name(self):
        info = DartLibInfo("3.8.0", "android", "arm64")
        assert info.lib_name == "dartvm3.8.0_android_arm64"

    def test_ios_arm64_name(self):
        info = DartLibInfo("3.5.0", "ios", "arm64")
        assert info.lib_name == "dartvm3.5.0_ios_arm64"

    def test_x64_name(self):
        info = DartLibInfo("3.8.0", "android", "x64")
        assert info.lib_name == "dartvm3.8.0_android_x64"


class TestSnapshotHash:
    def test_default_none(self):
        info = DartLibInfo("3.8.0", "android", "arm64")
        assert info.snapshot_hash is None

    def test_preserved_when_given(self):
        h = "a" * 32
        info = DartLibInfo("3.8.0", "android", "arm64", snapshot_hash=h)
        assert info.snapshot_hash == h
