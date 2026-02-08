"""Tests for PathChecker mode parameter (read/write)."""

import platform

import pytest

from bad_path import DangerousPathError, PathChecker, add_user_path, clear_user_paths


def setup_function():
    """Set up test environment."""
    clear_user_paths()


def teardown_function():
    """Clean up test environment."""
    clear_user_paths()


def test_mode_read_allows_system_paths():
    """Test that mode='read' allows reading from system paths."""
    system = platform.system()

    if system == "Windows":
        system_path = "C:\\Windows\\System32\\config\\SAM"
    else:
        system_path = "/etc/passwd"

    # Default (strict) - should be dangerous
    checker1 = PathChecker(system_path)
    assert not checker1  # Dangerous

    # Read mode - should be safe
    checker2 = PathChecker(system_path, mode="read")
    assert checker2  # Safe for reading
    assert checker2.is_system_path


def test_mode_write_strict_validation():
    """Test that mode='write' uses strict validation."""
    system = platform.system()

    if system == "Windows":
        system_path = "C:\\Windows\\System32\\test.txt"
    else:
        system_path = "/etc/passwd"

    # Write mode - should be dangerous for system paths
    checker = PathChecker(system_path, mode="write")
    assert not checker  # Dangerous for writing
    assert checker.is_system_path


def test_mode_read_allows_user_paths():
    """Test that mode='read' allows reading from user-defined paths."""
    custom_path = "/my/sensitive/config"
    add_user_path(custom_path)
    config_file = f"{custom_path}/settings.conf"

    # Default - should be dangerous
    checker1 = PathChecker(config_file)
    assert not checker1
    assert checker1.is_sensitive_path

    # Read mode - should be safe
    checker2 = PathChecker(config_file, mode="read")
    assert checker2  # Safe for reading
    assert checker2.is_sensitive_path


def test_mode_write_rejects_user_paths():
    """Test that mode='write' rejects user-defined paths."""
    custom_path = "/my/sensitive/data"
    add_user_path(custom_path)
    data_file = f"{custom_path}/important.dat"

    # Write mode - should be dangerous
    checker = PathChecker(data_file, mode="write")
    assert not checker  # Dangerous for writing
    assert checker.is_sensitive_path


def test_mode_read_allows_non_writable():
    """Test that mode='read' allows non-writable paths."""
    system = platform.system()

    if system == "Windows":
        # Use a system file that exists but isn't writable
        readonly_path = "C:\\Windows\\System32\\config"
    else:
        readonly_path = "/etc/passwd"

    # Read mode should allow non-writable paths
    checker = PathChecker(readonly_path, mode="read")
    if checker._path_obj.exists():
        assert checker  # Safe for reading even if not writable


def test_mode_none_respects_individual_flags():
    """Test that mode=None uses individual flag values."""
    system = platform.system()

    if system == "Windows":
        system_path = "C:\\Windows\\System32\\test.txt"
    else:
        system_path = "/etc/passwd"

    # mode=None with flags should work like before
    checker = PathChecker(
        system_path, mode=None, system_ok=True, not_writeable=True
    )
    assert checker  # Safe with flags


def test_mode_invalid_value_raises_error():
    """Test that invalid mode value raises ValueError."""
    with pytest.raises(ValueError) as exc_info:
        PathChecker("/tmp/test.txt", mode="invalid")
    assert "Invalid mode" in str(exc_info.value)
    assert "'invalid'" in str(exc_info.value)


def test_mode_overrides_individual_flags():
    """Test that mode parameter overrides individual flags."""
    system = platform.system()

    if system == "Windows":
        system_path = "C:\\Windows\\System32\\test.txt"
    else:
        system_path = "/etc/passwd"

    # mode='read' should override system_ok=False
    checker = PathChecker(system_path, mode="read", system_ok=False)
    assert checker  # Safe because mode='read' overrides

    # mode='write' should override system_ok=True
    checker2 = PathChecker(system_path, mode="write", system_ok=True)
    # Will be dangerous if not writable
    if not checker2._path_obj.exists() or not checker2.is_writable:
        assert not checker2


def test_mode_read_with_safe_path():
    """Test that mode='read' works with safe paths too."""
    safe_path = "/tmp/safe_file.txt"

    checker = PathChecker(safe_path, mode="read")
    assert checker  # Safe path is safe in read mode


def test_mode_write_with_safe_path():
    """Test that mode='write' works with safe paths."""
    safe_path = "/tmp/safe_file.txt"

    checker = PathChecker(safe_path, mode="write")
    assert checker  # Safe path is safe in write mode


def test_mode_read_with_raise_error():
    """Test that mode='read' with raise_error doesn't raise for system paths."""
    system = platform.system()

    if system == "Windows":
        system_path = "C:\\Windows\\System32\\config\\SAM"
    else:
        system_path = "/etc/passwd"

    # Should not raise in read mode
    checker = PathChecker(system_path, mode="read", raise_error=True)
    assert checker.is_system_path


def test_mode_write_with_raise_error():
    """Test that mode='write' with raise_error raises for system paths."""
    system = platform.system()

    if system == "Windows":
        system_path = "C:\\Windows\\System32\\test.txt"
    else:
        system_path = "/etc/passwd"

    # Should raise in write mode
    with pytest.raises(DangerousPathError):
        PathChecker(system_path, mode="write", raise_error=True)


def test_mode_read_invalid_chars_still_dangerous():
    """Test that invalid characters are dangerous even in read mode."""
    if platform.system() == "Windows":
        invalid_path = "C:\\tmp\\test<file>.txt"
    elif platform.system() == "Darwin":
        invalid_path = "/tmp/test:file.txt"
    else:  # POSIX
        invalid_path = "/tmp/test\x00file.txt"

    # Invalid characters are always dangerous
    checker = PathChecker(invalid_path, mode="read")
    assert not checker
    assert checker.has_invalid_chars


def test_mode_case_sensitive():
    """Test that mode parameter is case-sensitive."""
    # Capital case should raise error
    with pytest.raises(ValueError):
        PathChecker("/tmp/test.txt", mode="READ")

    with pytest.raises(ValueError):
        PathChecker("/tmp/test.txt", mode="Write")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--pdb"])
