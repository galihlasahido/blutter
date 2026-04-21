from dartvm_fetch_build import version_tuple


class TestParse:
    def test_three_components(self):
        assert version_tuple("3.8.0") == (3, 8, 0)

    def test_two_components(self):
        assert version_tuple("3.8") == (3, 8)

    def test_pre_release_suffix(self):
        # '3.8.0-226.0.dev' → the '0-226' component strips non-digits after the 0.
        assert version_tuple("3.8.0-226.0.dev") == (3, 8, 0, 0)

    def test_patch_with_letter_suffix(self):
        assert version_tuple("3.11.0rc1") == (3, 11, 0)


class TestOrdering:
    def test_minor_ordering(self):
        assert version_tuple("3.11.0") > version_tuple("3.8.0")

    def test_patch_ordering(self):
        assert version_tuple("3.7.9") < version_tuple("3.8.0")

    def test_major_ordering(self):
        assert version_tuple("4.0.0") > version_tuple("3.8.0")


class TestRegression:
    # Was: `int(vers[0]) >= 3 and int(vers[1]) >= 8` — silently False for 4.0
    def test_four_zero_geq_three_eight(self):
        assert version_tuple("4.0.0") >= (3, 8)

    def test_four_two_geq_three_eight(self):
        assert version_tuple("4.2.0") >= (3, 8)

    def test_three_seven_lt_three_eight(self):
        assert version_tuple("3.7.9") < (3, 8)

    def test_three_eight_geq_three_eight(self):
        assert version_tuple("3.8.0") >= (3, 8)

    # Dart <2.15 forces --no-analysis
    def test_two_fourteen_lt_two_fifteen(self):
        assert version_tuple("2.14.0") < (2, 15)

    def test_two_fifteen_not_lt_two_fifteen(self):
        assert not version_tuple("2.15.0") < (2, 15)

    def test_three_x_not_lt_two_fifteen(self):
        assert not version_tuple("3.0.0") < (2, 15)
