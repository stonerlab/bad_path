"""Tests for is_system_path function."""

import os
import platform
from pathlib import Path

import pytest

from bad_path import is_system_path


def test_with_string_path():
    """Test with a string path."""
    result = is_system_path("/tmp/test.txt")
    assert isinstance(result, bool)


def test_with_path_object():
    """Test with a Path object."""
    result = is_system_path(Path("/tmp/test.txt"))
    assert isinstance(result, bool)


def test_safe_path_returns_false():
    """Test that a safe path returns False."""
    # /tmp and /home are generally safe on Unix systems
    # For Windows, use a user directory
    if platform.system() == "Windows":
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
    else:
        safe_path = "/tmp/test.txt"

    result = is_system_path(safe_path)
    assert result is False


def test_dangerous_path_returns_true():
    """Test that a dangerous path returns True."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        dangerous_path = "/etc/passwd"

    result = is_system_path(dangerous_path)
    assert result is True


def test_exact_dangerous_path():
    """Test exact match with a dangerous path."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows"
    else:
        dangerous_path = "/etc"

    result = is_system_path(dangerous_path)
    assert result is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--pdb"])
