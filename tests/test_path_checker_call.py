"""Tests for PathChecker __call__ method."""

import os
import platform
from pathlib import Path

import pytest

from bad_path import DangerousPathError, PathChecker, add_user_path, clear_user_paths


def test_call_with_new_path_safe():
    """Test calling checker with a new safe path."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
    else:
        dangerous_path = "/etc/passwd"
        safe_path = "/tmp/test.txt"

    checker = PathChecker(dangerous_path)
    assert not checker  # Original path is dangerous (evaluates to False)

    # Check a different safe path without reloading
    result = checker(safe_path)
    assert result is False  # New path is safe (call returns False for safe)

    # Original path should still be stored
    assert checker.path == dangerous_path


def test_call_with_new_path_dangerous():
    """Test calling checker with a new dangerous path."""
    system = platform.system()

    if system == "Windows":
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        safe_path = "/tmp/test.txt"
        dangerous_path = "/etc/passwd"

    checker = PathChecker(safe_path)
    assert checker  # Original path is safe (evaluates to True)

    # Check a different dangerous path without reloading
    result = checker(dangerous_path)
    assert result is True  # New path is dangerous (call returns True for dangerous)

    # Original path should still be stored
    assert checker.path == safe_path


def test_call_without_path_reloads():
    """Test calling checker without path reloads system and user paths."""
    system = platform.system()

    # Use a custom user path
    if system == "Windows":
        custom_path = "C:\\MyCustomPath"
    else:
        custom_path = "/my/custom/path"

    # Create checker for custom path before adding it
    checker = PathChecker(f"{custom_path}/file.txt")
    assert checker  # Not dangerous yet (safe evaluates to True)

    # Add the path to user paths
    add_user_path(custom_path)

    try:
        # Call without path should reload and recheck
        result = checker()
        assert result is True  # Should now be dangerous (call returns True for dangerous)

        # Properties should also be updated
        assert checker.is_sensitive_path is True
    finally:
        clear_user_paths()


def test_call_with_path_does_not_reload():
    """Test that calling with a path does not reload user paths."""
    system = platform.system()

    if system == "Windows":
        test_path = "C:\\TestPath"
        check_path = "C:\\TestPath\\file.txt"
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "safe.txt")
    else:
        test_path = "/test/path"
        check_path = "/test/path/file.txt"
        safe_path = "/tmp/safe.txt"

    # Create checker with user paths empty
    checker = PathChecker(safe_path)
    assert checker  # Safe path (evaluates to True)

    # Store the original user paths reference
    original_user_paths = checker._user_paths

    try:
        # Add a user path after creating the checker
        add_user_path(test_path)

        # Call with a path - should use existing _user_paths (not reload)
        # So it won't see the newly added path
        result = checker(check_path)

        # The path should not be dangerous because checker didn't reload
        # and still has the old (empty) user paths
        assert result is False

        # Verify that _user_paths wasn't reloaded
        assert checker._user_paths is original_user_paths
    finally:
        clear_user_paths()


def test_call_with_pathlib_object():
    """Test calling with a Path object."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
        safe_path = Path(os.path.join(os.path.expanduser("~"), "Documents", "test.txt"))
    else:
        dangerous_path = "/etc/passwd"
        safe_path = Path("/tmp/test.txt")

    checker = PathChecker(dangerous_path)
    result = checker(safe_path)
    assert result is False


def test_call_preserves_original_state():
    """Test that calling with a path preserves the original checker state."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
    else:
        dangerous_path = "/etc/passwd"
        safe_path = "/tmp/test.txt"

    checker = PathChecker(dangerous_path)
    original_is_system = checker.is_system_path
    original_is_sensitive = checker.is_sensitive_path
    original_bool = bool(checker)

    # Call with a different path
    checker(safe_path)

    # Original state should be preserved
    assert checker.is_system_path == original_is_system
    assert checker.is_sensitive_path == original_is_sensitive
    assert bool(checker) == original_bool
    assert checker.path == dangerous_path


def test_call_updates_properties_when_no_path():
    """Test that calling without path updates the checker properties."""
    system = platform.system()

    if system == "Windows":
        custom_path = "C:\\CustomDangerous"
    else:
        custom_path = "/custom/dangerous"

    # Create checker
    checker = PathChecker(f"{custom_path}/file.txt")
    assert checker  # Should be safe initially (True)
    assert not checker.is_sensitive_path

    # Add user path
    add_user_path(custom_path)

    try:
        # Call without path to reload
        result = checker()

        # Should be dangerous now (result from __call__ returns True if dangerous)
        assert result is True
        assert checker.is_sensitive_path is True
        assert bool(checker) is False  # Boolean context is False for dangerous
    finally:
        clear_user_paths()


def test_call_with_user_defined_path():
    """Test calling with path checks against user-defined paths."""
    system = platform.system()

    if system == "Windows":
        custom_path = "C:\\MySensitive"
        test_file = f"{custom_path}\\secret.txt"
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
    else:
        custom_path = "/my/sensitive"
        test_file = f"{custom_path}/secret.txt"
        safe_path = "/tmp/test.txt"

    # Add user path
    add_user_path(custom_path)

    try:
        # Create checker with safe path
        checker = PathChecker(safe_path)
        assert checker  # Safe path (evaluates to True)

        # Check the user-defined dangerous path
        result = checker(test_file)
        assert result is True  # Should be dangerous (call returns True for dangerous)
    finally:
        clear_user_paths()


def test_constructor_raise_error_on_dangerous_system_path():
    """Test that raise_error=True in constructor raises exception for dangerous paths."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        dangerous_path = "/etc/passwd"

    with pytest.raises(DangerousPathError) as exc_info:
        PathChecker(dangerous_path, raise_error=True)

    assert "dangerous location" in str(exc_info.value)


def test_constructor_raise_error_on_dangerous_user_path():
    """Test that raise_error=True in constructor raises exception for user paths."""
    custom_path = "/my/custom/dangerous"
    add_user_path(custom_path)

    try:
        with pytest.raises(DangerousPathError) as exc_info:
            PathChecker(f"{custom_path}/file.txt", raise_error=True)

        assert "dangerous location" in str(exc_info.value)
    finally:
        clear_user_paths()


def test_constructor_raise_error_false_on_safe_path():
    """Test that raise_error=True in constructor doesn't raise for safe paths."""
    if platform.system() == "Windows":
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
    else:
        safe_path = "/tmp/test.txt"

    # Should not raise an exception
    checker = PathChecker(safe_path, raise_error=True)
    assert checker  # Safe path (evaluates to True)


def test_call_raise_error_on_dangerous_path():
    """Test that raise_error=True in __call__ raises exception for dangerous paths."""
    system = platform.system()

    if system == "Windows":
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        safe_path = "/tmp/test.txt"
        dangerous_path = "/etc/passwd"

    # Create checker with safe path
    checker = PathChecker(safe_path)

    # Call with dangerous path and raise_error=True
    with pytest.raises(DangerousPathError) as exc_info:
        checker(dangerous_path, raise_error=True)

    assert "dangerous location" in str(exc_info.value)


def test_call_raise_error_on_recheck_with_user_path():
    """Test raise_error=True in __call__ raises exception on recheck after adding user path."""
    system = platform.system()

    if system == "Windows":
        custom_path = "C:\\CustomDangerous"
    else:
        custom_path = "/custom/dangerous"

    # Create checker with a path that will become dangerous
    checker = PathChecker(f"{custom_path}/file.txt")
    assert checker  # Initially safe (evaluates to True)

    # Add user path
    add_user_path(custom_path)

    try:
        # Recheck with raise_error=True (no path argument, so rechecks original)
        with pytest.raises(DangerousPathError) as exc_info:
            checker(raise_error=True)

        assert "dangerous location" in str(exc_info.value)
    finally:
        clear_user_paths()


def test_call_raise_error_false_on_safe_path():
    """Test that raise_error=True in __call__ doesn't raise for safe paths."""
    system = platform.system()

    if system == "Windows":
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
    else:
        safe_path = "/tmp/test.txt"

    # Create checker
    checker = PathChecker(safe_path)

    # Call with raise_error=True on safe path - should not raise
    result = checker(safe_path, raise_error=True)
    assert result is False


def test_raise_error_default_false_in_constructor():
    """Test that raise_error defaults to False in constructor."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        dangerous_path = "/etc/passwd"

    # Should not raise even though path is dangerous (default raise_error=False)
    checker = PathChecker(dangerous_path)
    assert not checker  # Path is dangerous (evaluates to False) but no exception raised


def test_raise_error_default_false_in_call():
    """Test that raise_error defaults to False in __call__."""
    system = platform.system()

    if system == "Windows":
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        safe_path = "/tmp/test.txt"
        dangerous_path = "/etc/passwd"

    # Create checker with safe path
    checker = PathChecker(safe_path)

    # Call with dangerous path but default raise_error=False
    result = checker(dangerous_path)  # Should not raise
    assert result is True  # Path is dangerous but no exception raised


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--pdb"])
