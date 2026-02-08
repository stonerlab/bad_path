"""Tests for get_dangerous_paths function."""

import platform

import pytest

from bad_path import get_dangerous_paths


def test_returns_list():
    """Test that get_dangerous_paths returns a list."""
    paths = get_dangerous_paths()
    assert isinstance(paths, list)
    assert len(paths) > 0


def test_returns_strings():
    """Test that all returned paths are strings."""
    paths = get_dangerous_paths()
    assert all(isinstance(p, str) for p in paths)


def test_platform_specific_paths():
    """Test that paths are appropriate for the current platform."""
    paths = get_dangerous_paths()
    system = platform.system()

    if system == "Windows":
        assert any("Windows" in p for p in paths)
    elif system == "Darwin":
        assert any("/System" in p or "/Library" in p for p in paths)
    else:  # Linux
        assert any("/etc" in p or "/bin" in p for p in paths)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--pdb"])
