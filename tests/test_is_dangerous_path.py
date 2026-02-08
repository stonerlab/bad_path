"""Tests for is_dangerous_path function."""

import os
import platform

import pytest

from bad_path import DangerousPathError, is_dangerous_path


def test_returns_bool_by_default():
    """Test that is_dangerous_path returns a bool by default."""
    result = is_dangerous_path("/tmp/test.txt")
    assert isinstance(result, bool)


def test_raise_error_on_dangerous_path():
    """Test that raise_error=True raises exception for dangerous paths."""
    system = platform.system()

    if system == "Windows":
        dangerous_path = "C:\\Windows\\System32\\test.txt"
    else:
        dangerous_path = "/etc/passwd"

    with pytest.raises(DangerousPathError) as exc_info:
        is_dangerous_path(dangerous_path, raise_error=True)

    assert "dangerous system location" in str(exc_info.value)


def test_no_error_on_safe_path():
    """Test that raise_error=True doesn't raise exception for safe paths."""
    if platform.system() == "Windows":
        safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
    else:
        safe_path = "/tmp/test.txt"

    result = is_dangerous_path(safe_path, raise_error=True)
    assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--pdb"])
