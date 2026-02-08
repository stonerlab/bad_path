"""Tests for is_sensitive_path function (alias)."""

import pytest

from bad_path import is_sensitive_path, is_system_path


def test_is_alias_of_is_system_path():
    """Test that is_sensitive_path behaves like is_system_path."""
    test_path = "/tmp/test.txt"
    assert is_sensitive_path(test_path) == is_system_path(test_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--pdb"])
