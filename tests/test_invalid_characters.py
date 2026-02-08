"""Tests for invalid character detection in paths."""

import platform

import pytest

from bad_path import DangerousPathError, PathChecker, is_dangerous_path


def test_has_invalid_chars_property_exists():
    """Test that PathChecker has a has_invalid_chars property."""
    checker = PathChecker("/tmp/test.txt")
    assert hasattr(checker, "has_invalid_chars")
    assert isinstance(checker.has_invalid_chars, bool)


def test_posix_safe_path_no_invalid_chars():
    """Test that a safe POSIX path has no invalid characters."""
    if platform.system() == "Windows":
        pytest.skip("POSIX-specific test")

    checker = PathChecker("/tmp/test_file.txt")
    assert checker.has_invalid_chars is False


def test_posix_null_byte_is_invalid():
    """Test that null byte is detected as invalid on POSIX systems."""
    if platform.system() == "Windows":
        pytest.skip("POSIX-specific test")

    checker = PathChecker("/tmp/test\x00file.txt")
    assert checker.has_invalid_chars is True


def test_darwin_colon_is_invalid():
    """Test that colon is detected as invalid on macOS."""
    if platform.system() != "Darwin":
        pytest.skip("macOS-specific test")

    checker = PathChecker("/tmp/test:file.txt")
    assert checker.has_invalid_chars is True


def test_darwin_null_byte_is_invalid():
    """Test that null byte is detected as invalid on macOS."""
    if platform.system() != "Darwin":
        pytest.skip("macOS-specific test")

    checker = PathChecker("/tmp/test\x00file.txt")
    assert checker.has_invalid_chars is True


def test_darwin_var_folders_safe():
    """Test that /var/folders (temp files) is safe on macOS."""
    if platform.system() != "Darwin":
        pytest.skip("macOS-specific test")

    # /var/folders is used for temporary files and should be safe
    checker = PathChecker("/var/folders/test/file.txt")
    assert checker  # Should be safe
    assert not checker.is_system_path


def test_darwin_var_subdirs_dangerous():
    """Test that /var subdirectories (except folders) are dangerous on macOS."""
    if platform.system() != "Darwin":
        pytest.skip("macOS-specific test")

    # These /var subdirectories should be dangerous
    dangerous_paths = [
        "/var/root/test.txt",
        "/var/db/test.db",
        "/var/log/system.log",
    ]
    for path in dangerous_paths:
        checker = PathChecker(path)
        assert not checker  # Should be dangerous
        assert checker.is_system_path


def test_windows_invalid_chars():
    """Test that Windows invalid characters are detected."""
    if platform.system() != "Windows":
        pytest.skip("Windows-specific test")

    invalid_chars = ['<', '>', ':', '"', '|', '?', '*']
    for char in invalid_chars:
        checker = PathChecker(f"C:\\tmp\\test{char}file.txt")
        assert checker.has_invalid_chars is True, f"Character '{char}' should be invalid"


def test_windows_control_chars_are_invalid():
    """Test that Windows control characters are detected as invalid."""
    if platform.system() != "Windows":
        pytest.skip("Windows-specific test")

    # Test a few control characters
    for i in [0, 1, 10, 31]:
        checker = PathChecker(f"C:\\tmp\\test{chr(i)}file.txt")
        assert checker.has_invalid_chars is True, f"Control character {i} should be invalid"


def test_windows_reserved_names():
    """Test that Windows reserved names are detected as invalid."""
    if platform.system() != "Windows":
        pytest.skip("Windows-specific test")

    reserved_names = ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"]
    for name in reserved_names:
        # Test uppercase
        checker = PathChecker(f"C:\\tmp\\{name}")
        assert checker.has_invalid_chars is True, f"Reserved name '{name}' should be invalid"

        # Test lowercase (case-insensitive)
        checker = PathChecker(f"C:\\tmp\\{name.lower()}")
        msg = f"Reserved name '{name.lower()}' should be invalid"
        assert checker.has_invalid_chars is True, msg

        # Test with extension
        checker = PathChecker(f"C:\\tmp\\{name}.txt")
        msg = f"Reserved name '{name}.txt' should be invalid"
        assert checker.has_invalid_chars is True, msg


def test_windows_path_ending_with_space():
    """Test that Windows paths ending with space are detected as invalid."""
    if platform.system() != "Windows":
        pytest.skip("Windows-specific test")

    checker = PathChecker("C:\\tmp\\testfile ")
    assert checker.has_invalid_chars is True


def test_windows_path_ending_with_period():
    """Test that Windows paths ending with period are detected as invalid."""
    if platform.system() != "Windows":
        pytest.skip("Windows-specific test")

    checker = PathChecker("C:\\tmp\\testfile.")
    assert checker.has_invalid_chars is True


def test_invalid_chars_affects_bool():
    """Test that invalid characters make PathChecker evaluate to False (dangerous)."""
    if platform.system() == "Windows":
        test_path = "C:\\tmp\\test<file>.txt"
    elif platform.system() == "Darwin":
        test_path = "/tmp/test:file.txt"
    else:  # POSIX
        test_path = "/tmp/test\x00file.txt"

    checker = PathChecker(test_path)
    # PathChecker evaluates to True when safe, False when dangerous
    assert bool(checker) is False
    assert checker.has_invalid_chars is True


def test_invalid_chars_with_raise_error():
    """Test that invalid characters trigger DangerousPathError when raise_error=True."""
    if platform.system() == "Windows":
        test_path = "C:\\tmp\\test<file>.txt"
    elif platform.system() == "Darwin":
        test_path = "/tmp/test:file.txt"
    else:  # POSIX
        test_path = "/tmp/test\x00file.txt"

    with pytest.raises(DangerousPathError):
        PathChecker(test_path, raise_error=True)


def test_call_with_invalid_chars_path():
    """Test that __call__ method detects invalid characters."""
    checker = PathChecker("/tmp/safe.txt")

    if platform.system() == "Windows":
        test_path = "C:\\tmp\\test<file>.txt"
    elif platform.system() == "Darwin":
        test_path = "/tmp/test:file.txt"
    else:  # POSIX
        test_path = "/tmp/test\x00file.txt"

    # __call__ returns True if dangerous, False if safe
    result = checker(test_path)
    assert result is True


def test_call_with_invalid_chars_and_raise_error():
    """Test that __call__ raises error for invalid characters when raise_error=True."""
    checker = PathChecker("/tmp/safe.txt")

    if platform.system() == "Windows":
        test_path = "C:\\tmp\\test<file>.txt"
    elif platform.system() == "Darwin":
        test_path = "/tmp/test:file.txt"
    else:  # POSIX
        test_path = "/tmp/test\x00file.txt"

    with pytest.raises(DangerousPathError):
        checker(test_path, raise_error=True)


def test_is_dangerous_path_with_invalid_chars():
    """Test that is_dangerous_path function detects invalid characters."""
    if platform.system() == "Windows":
        test_path = "C:\\tmp\\test<file>.txt"
    elif platform.system() == "Darwin":
        test_path = "/tmp/test:file.txt"
    else:  # POSIX
        test_path = "/tmp/test\x00file.txt"

    result = is_dangerous_path(test_path)
    assert result is True


def test_repr_with_invalid_chars():
    """Test that __repr__ correctly shows dangerous status for invalid characters."""
    if platform.system() == "Windows":
        test_path = "C:\\tmp\\test<file>.txt"
    elif platform.system() == "Darwin":
        test_path = "/tmp/test:file.txt"
    else:  # POSIX
        test_path = "/tmp/test\x00file.txt"

    checker = PathChecker(test_path)
    repr_str = repr(checker)
    assert "dangerous" in repr_str


def test_safe_path_with_special_but_valid_chars():
    """Test that paths with special but valid characters are not flagged."""
    # These characters should be safe on most systems
    if platform.system() == "Windows":
        # Windows has many restrictions; using basic safe chars for test
        test_path = "C:\\tmp\\test_file-name.txt"
    else:
        # POSIX/Darwin allow most characters except null byte and colon (Darwin)
        test_path = "/tmp/test_file-name@#$%^&().txt"

    checker = PathChecker(test_path)
    assert checker.has_invalid_chars is False
    assert bool(checker) is True  # Should be safe


def test_combined_system_path_and_invalid_chars():
    """Test that both system path and invalid chars are detected independently."""
    if platform.system() == "Windows":
        test_path = "C:\\Windows\\test<file>.txt"
    else:
        test_path = "/etc/test\x00file.txt"

    checker = PathChecker(test_path)
    # Should be dangerous for both reasons
    assert bool(checker) is False
    # At least one should be true (depends on platform and path resolution)
    assert checker.is_system_path or checker.has_invalid_chars


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--pdb"])
