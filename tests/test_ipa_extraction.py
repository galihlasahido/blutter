"""Tests for ``blutter.extract_libs_from_ipa``.

Builds a synthetic .ipa (a zip with the standard
``Payload/<Name>.app/Frameworks/{App,Flutter}.framework/`` layout) and checks
that the extractor finds and unpacks both binaries.
"""
import os
import zipfile

import pytest

import blutter


def _make_ipa(path, app_bytes=b"APPPAYLOAD", flutter_bytes=b"FLUTTERPAYLOAD",
              app_name="Runner.app"):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"Payload/{app_name}/Info.plist", b"<plist/>")
        zf.writestr(f"Payload/{app_name}/Frameworks/App.framework/App", app_bytes)
        zf.writestr(
            f"Payload/{app_name}/Frameworks/App.framework/Info.plist",
            b"<plist/>",
        )
        zf.writestr(
            f"Payload/{app_name}/Frameworks/Flutter.framework/Flutter",
            flutter_bytes,
        )
        zf.writestr(
            f"Payload/{app_name}/Frameworks/Flutter.framework/Info.plist",
            b"<plist/>",
        )


class TestExtractLibsFromIpa:
    def test_finds_and_extracts_both(self, tmp_path):
        ipa = tmp_path / "test.ipa"
        _make_ipa(ipa)

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        app_file, flutter_file = blutter.extract_libs_from_ipa(str(ipa), str(out_dir))

        assert os.path.isfile(app_file)
        assert os.path.isfile(flutter_file)
        with open(app_file, "rb") as f:
            assert f.read() == b"APPPAYLOAD"
        with open(flutter_file, "rb") as f:
            assert f.read() == b"FLUTTERPAYLOAD"

    def test_handles_arbitrary_app_name(self, tmp_path):
        ipa = tmp_path / "weird.ipa"
        _make_ipa(ipa, app_name="SomethingElse.app")

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        app_file, flutter_file = blutter.extract_libs_from_ipa(str(ipa), str(out_dir))
        assert "SomethingElse.app" in app_file
        assert "SomethingElse.app" in flutter_file

    def test_missing_binary_exits(self, tmp_path):
        ipa = tmp_path / "broken.ipa"
        with zipfile.ZipFile(ipa, "w") as zf:
            zf.writestr("Payload/Runner.app/Info.plist", b"<plist/>")
            # App.framework present, Flutter missing.
            zf.writestr("Payload/Runner.app/Frameworks/App.framework/App", b"x")

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        with pytest.raises(SystemExit):
            blutter.extract_libs_from_ipa(str(ipa), str(out_dir))
