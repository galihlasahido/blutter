import os

import pytest

import blutter
from blutter import BlutterInput
from dartvm_fetch_build import DartLibInfo


@pytest.fixture
def android_info():
    return DartLibInfo("3.8.0", "android", "arm64")


@pytest.fixture
def ios_info():
    return DartLibInfo("3.8.0", "ios", "arm64")


class TestNameSuffix:
    def test_default_android_empty(self, android_info):
        inp = BlutterInput("libapp.so", android_info, "out", False, False, False)
        assert inp.name_suffix == ""

    def test_ios_adds_no_compressed_ptrs(self, ios_info):
        inp = BlutterInput("App", ios_info, "out", False, False, False)
        assert inp.name_suffix == "_no-compressed-ptrs"

    def test_no_analysis_adds_suffix(self, android_info):
        inp = BlutterInput("libapp.so", android_info, "out", False, False, True)
        assert inp.name_suffix == "_no-analysis"

    def test_both_suffixes_stacked_in_order(self, ios_info):
        inp = BlutterInput("App", ios_info, "out", False, False, True)
        assert inp.name_suffix == "_no-compressed-ptrs_no-analysis"


class TestForceNoAnalysis:
    def test_dart_2_14_forces_no_analysis(self, capsys):
        info = DartLibInfo("2.14.0", "android", "arm64")
        inp = BlutterInput("libapp.so", info, "out", False, False, False)
        assert inp.no_analysis is True
        assert 'force "no-analysis"' in capsys.readouterr().out

    def test_dart_2_15_does_not_force(self, capsys):
        info = DartLibInfo("2.15.0", "android", "arm64")
        inp = BlutterInput("libapp.so", info, "out", False, False, False)
        assert inp.no_analysis is False
        assert capsys.readouterr().out == ""

    def test_dart_3_x_does_not_force(self):
        info = DartLibInfo("3.0.0", "android", "arm64")
        inp = BlutterInput("libapp.so", info, "out", False, False, False)
        assert inp.no_analysis is False

    def test_dart_2_14_no_duplicate_message_when_already_requested(self, capsys):
        info = DartLibInfo("2.14.0", "android", "arm64")
        inp = BlutterInput("libapp.so", info, "out", False, False, True)
        assert inp.no_analysis is True
        # When caller already passed --no-analysis, we shouldn't print the override notice.
        assert capsys.readouterr().out == ""


class TestBlutterFilePath:
    def test_posix_path_no_extension(self, android_info, monkeypatch):
        monkeypatch.setattr(os, "name", "posix")
        inp = BlutterInput("libapp.so", android_info, "out", False, False, False)
        assert inp.blutter_file.endswith("blutter_dartvm3.8.0_android_arm64")
        assert not inp.blutter_file.endswith(".exe")

    def test_windows_path_has_exe(self, android_info, monkeypatch):
        monkeypatch.setattr(os, "name", "nt")
        inp = BlutterInput("libapp.so", android_info, "out", False, False, False)
        assert inp.blutter_file.endswith("blutter_dartvm3.8.0_android_arm64.exe")

    def test_blutter_name_respects_suffix(self, ios_info):
        inp = BlutterInput("App", ios_info, "out", False, False, True)
        assert inp.blutter_name == "blutter_dartvm3.8.0_ios_arm64_no-compressed-ptrs_no-analysis"

    def test_blutter_file_lives_in_bin_dir(self, android_info):
        inp = BlutterInput("libapp.so", android_info, "out", False, False, False)
        assert os.path.dirname(inp.blutter_file) == blutter.BIN_DIR
