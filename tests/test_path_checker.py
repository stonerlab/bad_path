"""Tests for PathChecker class."""

import os
import platform
from pathlib import Path

import pytest

from bad_path import PathChecker, add_user_path, clear_user_paths
from bad_path.checker import BasePathChecker


def test_instantiation_with_string():
    """Test creating PathChecker with a string path."""
    checker = PathChecker("/tmp/test.txt")
    assert isinstance(checker, BasePathChecker)


def test_instantiation_with_pathlib():
    """Test creating PathChecker with a Path object."""
    checker = PathChecker(Path("/tmp/test.txt"))
    assert isinstance(checker, BasePathChecker)


def test_bool_false_for_safe_path():
    """Test that PathChecker evaluates to True for safe paths."""
    if platform.system() == "Windows":
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
    else:
        safe_path = "/tmp/test.txt"

    checker = PathChecker(safe_path)
    assert checker  # Should be True/truthy for safe paths


def test_bool_true_for_dangerous_path():
    """Test that PathChecker evaluates to False for dangerous paths."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        dangerous_path = "/etc/passwd"

    checker = PathChecker(dangerous_path)
    assert not checker  # Should be False/falsy for dangerous paths


def test_is_system_path_property_safe():
    """Test is_system_path property returns False for safe paths."""
    if platform.system() == "Windows":
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
    else:
        safe_path = "/tmp/test.txt"

    checker = PathChecker(safe_path)
    assert checker.is_system_path is False


def test_is_system_path_property_dangerous():
    """Test is_system_path property returns True for dangerous paths."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        dangerous_path = "/etc/passwd"

    checker = PathChecker(dangerous_path)
    assert checker.is_system_path is True


def test_is_sensitive_path_property_safe():
    """Test is_sensitive_path property returns False for safe paths."""
    if platform.system() == "Windows":
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
    else:
        safe_path = "/tmp/test.txt"

    checker = PathChecker(safe_path)
    assert checker.is_sensitive_path is False


def test_is_sensitive_path_property_dangerous():
    """Test is_sensitive_path property returns False for system paths."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        dangerous_path = "/etc/passwd"

    checker = PathChecker(dangerous_path)
    # System paths should NOT show as sensitive (user-defined)
    assert checker.is_sensitive_path is False


def test_path_property():
    """Test that path property returns the original path."""
    test_path = "/tmp/test.txt"
    checker = PathChecker(test_path)
    assert checker.path == test_path


def test_repr():
    """Test string representation of PathChecker."""
    test_path = "/tmp/test.txt"
    checker = PathChecker(test_path)
    repr_str = repr(checker)
    assert "PathChecker" in repr_str
    assert test_path in repr_str
    assert "safe" in repr_str or "dangerous" in repr_str


def test_can_use_in_if_statement_safe():
    """Test using PathChecker in if statement with safe path."""
    if platform.system() == "Windows":
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
    else:
        safe_path = "/tmp/test.txt"

    checker = PathChecker(safe_path)
    if not checker:
        pytest.fail("Safe path should evaluate to True")


def test_can_use_in_if_statement_dangerous():
    """Test using PathChecker in if statement with dangerous path."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        dangerous_path = "/etc/passwd"

    checker = PathChecker(dangerous_path)
    is_safe = checker  # Should be False for dangerous path
    assert not is_safe


def test_provides_details_about_danger():
    """Test that PathChecker provides details about why path is dangerous."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        dangerous_path = "/etc/passwd"

    checker = PathChecker(dangerous_path)
    # Can check both that it's dangerous and get details
    assert not checker  # It's dangerous (evaluates to False)
    assert checker.is_system_path  # It's a system path
    assert not checker.is_sensitive_path  # It's NOT a user-defined path


def test_with_user_defined_path():
    """Test PathChecker with user-defined dangerous paths."""
    # Setup
    test_path = "/my/custom/dangerous"
    add_user_path(test_path)

    try:
        checker = PathChecker(f"{test_path}/file.txt")
        assert not checker  # Should be dangerous (evaluates to False)
        assert not checker.is_system_path  # Not a system path
        assert checker.is_sensitive_path  # IS a user-defined path
    finally:
        # Cleanup
        clear_user_paths()


def test_exact_dangerous_path():
    """Test PathChecker with exact match to dangerous path."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows"
    else:
        dangerous_path = "/etc"

    checker = PathChecker(dangerous_path)
    assert not checker  # Dangerous path evaluates to False


def test_distinction_system_vs_user_paths():
    """Test that is_system_path and is_sensitive_path are properly distinguished."""
    system = platform.system()

    # Test with a system path
    if system == "Windows":
        system_path = "C:\\Windows\\System32\\test.txt"
    else:
        system_path = "/etc/passwd"

    checker_system = PathChecker(system_path)
    assert checker_system.is_system_path is True
    assert checker_system.is_sensitive_path is False

    # Test with a user-defined path (use platform-agnostic path)
    if system == "Windows":
        user_path = "C:\\CustomSensitive\\Data"
    else:
        user_path = "/custom/sensitive/data"
    add_user_path(user_path)

    try:
        checker_user = PathChecker(f"{user_path}/file.txt")
        assert checker_user.is_system_path is False
        assert checker_user.is_sensitive_path is True
    finally:
        clear_user_paths()


def test_both_system_and_user_path():
    """Test a path that is both a system path and user-defined."""
    system = platform.system()

    if system == "Windows":
        path_to_add = "C:\\Windows"
    else:
        path_to_add = "/etc"

    # Add a system path as user-defined too
    add_user_path(path_to_add)

    try:
        checker = PathChecker(f"{path_to_add}/test.txt")
        # Should be flagged as both
        assert checker.is_system_path is True
        assert checker.is_sensitive_path is True
        assert not checker  # Should be dangerous (evaluates to False)
    finally:
        clear_user_paths()


def test_only_user_defined_not_system():
    """Test that user-defined paths work for non-system locations."""
    system = platform.system()

    # Use platform-specific non-system paths
    if system == "Windows":
        custom_path = os.path.join(os.path.expanduser("~"), "MySensitiveProject")
    elif system == "Darwin":
        # On macOS, use /Users path (not /home which may resolve to /var)
        custom_path = "/Users/testuser/my_sensitive_project"
    else:
        custom_path = "/home/user/my_sensitive_project"
    add_user_path(custom_path)

    try:
        checker = PathChecker(f"{custom_path}/secret.txt")
        assert not checker  # Should be dangerous (evaluates to False)
        assert checker.is_system_path is False  # Not a system path
        assert checker.is_sensitive_path is True  # But is user-defined
    finally:
        clear_user_paths()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--pdb"])
