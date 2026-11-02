from app.version_checker import check_version


def test_old_php_version():

    assert check_version("8.3.35") == "POTENTIALLY_AFFECTED"


def test_fixed_php_version():

    assert check_version("8.3.36") == "FIXED_VERSION_DISCLOSED"


def test_unknown_version():

    assert check_version(None) == "UNKNOWN"


def test_old_branch():

    assert check_version("8.1.29") == "REQUIRES_VENDOR_CHECK"