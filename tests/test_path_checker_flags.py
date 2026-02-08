"""Tests for PathChecker flag parameters (system_ok, user_paths_ok, not_writeable)."""

import os
import platform
import stat
import tempfile

import pytest

from bad_path import DangerousPathError, PathChecker, add_user_path, clear_user_paths


def setup_function():
    """Set up test environment."""
    clear_user_paths()


def teardown_function():
    """Clean up test environment."""
    clear_user_paths()


def test_system_ok_allows_system_path():
    """Test that system_ok=True allows system paths."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        dangerous_path = "/etc/passwd"

    # Without system_ok, should be dangerous
    checker = PathChecker(dangerous_path)
    assert not checker  # False means dangerous
    assert checker.is_system_path

    # With system_ok=True and not_writeable=True, should be safe
    # (need not_writeable=True because /etc/passwd is not writeable)
    checker = PathChecker(dangerous_path, system_ok=True, not_writeable=True)
    assert checker  # True means safe
    assert checker.is_system_path  # Still a system path


def test_user_paths_ok_allows_user_paths():
    """Test that user_paths_ok=True allows user-defined paths."""
    test_path = "/my/custom/dangerous"
    add_user_path(test_path)
    test_file = f"{test_path}/file.txt"

    # Without user_paths_ok, should be dangerous
    checker = PathChecker(test_file)
    assert not checker  # False means dangerous
    assert checker.is_sensitive_path

    # With user_paths_ok=True, should be safe
    checker = PathChecker(test_file, user_paths_ok=True)
    assert checker  # True means safe
    assert checker.is_sensitive_path  # Still a user-defined path


def test_both_flags_together():
    """Test that both system_ok and user_paths_ok work together."""
    system = platform.system()
    test_path = "/my/custom/dangerous"
    add_user_path(test_path)

    if system == "Windows":
        system_path = "C:\\Windows\\System32\\test.txt"
    else:
        system_path = "/etc/passwd"

    user_path = f"{test_path}/file.txt"

    # Neither flag set - both should be dangerous
    checker1 = PathChecker(system_path)
    assert not checker1
    checker2 = PathChecker(user_path)
    assert not checker2

    # Only system_ok - system path still dangerous if not writeable
    checker3 = PathChecker(system_path, system_ok=True)
    # /etc/passwd is not writeable, so still dangerous without not_writeable=True
    if system != "Windows":
        assert not checker3  # Still dangerous on Unix (not writeable)

    # system_ok + not_writeable - system path safe
    checker3b = PathChecker(system_path, system_ok=True, not_writeable=True)
    assert checker3b

    checker4 = PathChecker(user_path, system_ok=True, not_writeable=True)
    assert not checker4  # User path still dangerous

    # Only user_paths_ok - user path safe, system path dangerous
    checker5 = PathChecker(system_path, user_paths_ok=True, not_writeable=True)
    assert not checker5  # System path still dangerous
    checker6 = PathChecker(user_path, user_paths_ok=True, not_writeable=True)
    assert checker6

    # All flags - both safe
    checker7 = PathChecker(system_path, system_ok=True, user_paths_ok=True, not_writeable=True)
    assert checker7
    checker8 = PathChecker(user_path, system_ok=True, user_paths_ok=True, not_writeable=True)
    assert checker8


def test_not_writeable_allows_readonly_paths():
    """Test that not_writeable=True allows read-only paths."""
    # Create a temporary file and test with different permissions
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name

    try:
        # Make file read-only
        os.chmod(tmp_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        # Without not_writeable flag, read-only file should be dangerous
        checker = PathChecker(tmp_path)
        assert not checker  # False means dangerous
        assert not checker.is_writable

        # With not_writeable=True, read-only file should be safe
        checker = PathChecker(tmp_path, not_writeable=True)
        assert checker  # True means safe
        assert not checker.is_writable  # Still not writable
    finally:
        # Clean up - make writable first to delete
        os.chmod(tmp_path, stat.S_IWUSR | stat.S_IRUSR)
        os.unlink(tmp_path)


def test_not_writeable_with_writable_file():
    """Test that not_writeable flag doesn't affect writable files."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name

    try:
        # File should be writable by default
        checker1 = PathChecker(tmp_path)
        assert checker1.is_writable

        # Both with and without flag should be safe for writable file
        checker2 = PathChecker(tmp_path, not_writeable=False)
        assert checker2

        checker3 = PathChecker(tmp_path, not_writeable=True)
        assert checker3
    finally:
        os.unlink(tmp_path)


def test_not_writeable_with_nonexistent_path():
    """Test that not_writeable flag doesn't affect non-existent paths."""
    nonexistent = "/tmp/nonexistent_file_12345.txt"

    # Non-existent path should be safe (no write check applies)
    checker1 = PathChecker(nonexistent)
    assert checker1

    checker2 = PathChecker(nonexistent, not_writeable=True)
    assert checker2


def test_flags_with_raise_error():
    """Test that flags work with raise_error parameter."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        dangerous_path = "/etc/passwd"

    # Without system_ok, should raise
    with pytest.raises(DangerousPathError):
        PathChecker(dangerous_path, raise_error=True)

    # With system_ok and not_writeable, should not raise
    checker = PathChecker(dangerous_path, raise_error=True, system_ok=True, not_writeable=True)
    assert checker.is_system_path


def test_invalid_chars_always_dangerous():
    """Test that invalid characters are dangerous regardless of flags."""
    if platform.system() == "Windows":
        test_path = "C:\\tmp\\test<file>.txt"
    elif platform.system() == "Darwin":
        test_path = "/tmp/test:file.txt"
    else:  # POSIX
        test_path = "/tmp/test\x00file.txt"

    # Invalid chars should be dangerous even with all flags enabled
    checker = PathChecker(
        test_path, system_ok=True, user_paths_ok=True, not_writeable=True
    )
    assert not checker  # Still dangerous
    assert checker.has_invalid_chars


def test_call_method_respects_flags():
    """Test that __call__ method respects the flags."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        dangerous_path = "/etc/passwd"

    # Create checker with system_ok=True and not_writeable=True
    checker = PathChecker("/tmp/safe.txt", system_ok=True, not_writeable=True)

    # Calling with a system path should return False (not dangerous) due to flags
    result = checker(dangerous_path)
    assert result is False  # __call__ returns True if dangerous


def test_flags_default_to_false():
    """Test that all flags default to False (strict mode)."""
    system = platform.system()
    test_user_path = "/my/custom/dangerous"
    add_user_path(test_user_path)

    if system == "Windows":
        system_path = "C:\\Windows\\System32\\test.txt"
    else:
        system_path = "/etc/passwd"

    # Default behavior should reject both system and user paths
    checker1 = PathChecker(system_path)
    assert not checker1

    checker2 = PathChecker(f"{test_user_path}/file.txt")
    assert not checker2


def test_repr_with_flags():
    """Test that __repr__ works correctly with flags."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        dangerous_path = "/etc/passwd"

    # Without flags - should show as dangerous
    checker1 = PathChecker(dangerous_path)
    repr1 = repr(checker1)
    assert "dangerous" in repr1

    # With system_ok and not_writeable - should show as safe
    checker2 = PathChecker(dangerous_path, system_ok=True, not_writeable=True)
    repr2 = repr(checker2)
    assert "safe" in repr2


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--pdb"])
