"""Tests for user-defined path management functions."""

from pathlib import Path

import pytest

from bad_path import (
    DangerousPathError,
    add_user_path,
    clear_user_paths,
    get_dangerous_paths,
    get_user_paths,
    is_dangerous_path,
    is_system_path,
    remove_user_path,
)


def setup_function():
    """Clear user paths before each test."""
    clear_user_paths()


def teardown_function():
    """Clear user paths after each test."""
    clear_user_paths()


def test_add_user_path_string():
    """Test adding a user path as string."""
    test_path = "/custom/dangerous/path"
    add_user_path(test_path)
    assert test_path in get_user_paths()


def test_add_user_path_pathlib():
    """Test adding a user path as Path object."""
    test_path = Path("/custom/dangerous/path")
    add_user_path(test_path)
    assert str(test_path) in get_user_paths()


def test_add_duplicate_path():
    """Test that adding duplicate path doesn't create duplicates."""
    test_path = "/custom/path"
    add_user_path(test_path)
    add_user_path(test_path)
    assert get_user_paths().count(test_path) == 1


def test_remove_user_path():
    """Test removing a user path."""
    test_path = "/custom/path"
    add_user_path(test_path)
    assert test_path in get_user_paths()
    remove_user_path(test_path)
    assert test_path not in get_user_paths()


def test_remove_nonexistent_path():
    """Test that removing non-existent path raises ValueError."""
    with pytest.raises(ValueError) as exc_info:
        remove_user_path("/nonexistent/path")
    assert "not in the user-defined paths list" in str(exc_info.value)


def test_clear_user_paths():
    """Test clearing all user paths."""
    add_user_path("/path1")
    add_user_path("/path2")
    add_user_path("/path3")
    assert len(get_user_paths()) == 3
    clear_user_paths()
    assert len(get_user_paths()) == 0


def test_get_user_paths_returns_copy():
    """Test that get_user_paths returns a copy."""
    add_user_path("/test/path")
    paths = get_user_paths()
    paths.append("/another/path")
    # Original list should not be modified
    assert "/another/path" not in get_user_paths()


def test_user_paths_in_dangerous_paths():
    """Test that user paths are included in get_dangerous_paths."""
    test_path = "/my/custom/dangerous/path"
    add_user_path(test_path)
    dangerous_paths = get_dangerous_paths()
    assert test_path in dangerous_paths


def test_user_paths_merged_with_system_paths():
    """Test that user paths are merged with system paths."""
    initial_count = len(get_dangerous_paths())
    add_user_path("/custom/path1")
    add_user_path("/custom/path2")
    merged_paths = get_dangerous_paths()
    # Should have original system paths plus 2 new user paths
    assert len(merged_paths) == initial_count + 2


def test_no_duplicates_in_merged_paths():
    """Test that duplicate paths are removed when merging."""
    dangerous_paths = get_dangerous_paths()
    # Try to add a system path as user path
    if dangerous_paths:
        system_path = dangerous_paths[0]
        add_user_path(system_path)
        # Should not increase count since it's a duplicate
        assert len(get_dangerous_paths()) == len(dangerous_paths)


def test_is_system_path_with_user_path():
    """Test that is_system_path detects user-defined paths."""
    test_path = "/my/custom/dangerous"
    add_user_path(test_path)
    # Test exact path
    assert is_system_path(test_path) is True
    # Test subdirectory
    assert is_system_path(f"{test_path}/subdir/file.txt") is True


def test_is_dangerous_path_with_user_path():
    """Test that is_dangerous_path detects user-defined paths."""
    test_path = "/my/custom/dangerous"
    add_user_path(test_path)
    assert is_dangerous_path(f"{test_path}/file.txt") is True


def test_user_path_with_raise_error():
    """Test that user paths trigger DangerousPathError when raise_error=True."""
    test_path = "/my/custom/dangerous"
    add_user_path(test_path)
    with pytest.raises(DangerousPathError):
        is_dangerous_path(f"{test_path}/file.txt", raise_error=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--pdb"])
