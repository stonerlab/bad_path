"""
Tests for the bad_path package.
"""

import os
import platform
from pathlib import Path

import pytest

from bad_path import (
    DangerousPathError,
    add_user_path,
    clear_user_paths,
    get_dangerous_paths,
    get_user_paths,
    is_dangerous_path,
    is_sensitive_path,
    is_system_path,
    remove_user_path,
)


class TestGetDangerousPaths:
    """Tests for get_dangerous_paths function."""

    def test_returns_list(self):
        """Test that get_dangerous_paths returns a list."""
        paths = get_dangerous_paths()
        assert isinstance(paths, list)
        assert len(paths) > 0

    def test_returns_strings(self):
        """Test that all returned paths are strings."""
        paths = get_dangerous_paths()
        assert all(isinstance(p, str) for p in paths)

    def test_platform_specific_paths(self):
        """Test that paths are appropriate for the current platform."""
        paths = get_dangerous_paths()
        system = platform.system()

        if system == "Windows":
            assert any("Windows" in p for p in paths)
        elif system == "Darwin":
            assert any("/System" in p or "/Library" in p for p in paths)
        else:  # Linux
            assert any("/etc" in p or "/bin" in p for p in paths)


class TestIsSystemPath:
    """Tests for is_system_path function."""

    def test_with_string_path(self):
        """Test with a string path."""
        result = is_system_path("/tmp/test.txt")
        assert isinstance(result, bool)

    def test_with_path_object(self):
        """Test with a Path object."""
        result = is_system_path(Path("/tmp/test.txt"))
        assert isinstance(result, bool)

    def test_safe_path_returns_false(self):
        """Test that a safe path returns False."""
        # /tmp and /home are generally safe on Unix systems
        # For Windows, use a user directory
        if platform.system() == "Windows":
            safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
        else:
            safe_path = "/tmp/test.txt"

        result = is_system_path(safe_path)
        assert result is False

    def test_dangerous_path_returns_true(self):
        """Test that a dangerous path returns True."""
        system = platform.system()

        if system == "Windows":
            dangerous_path = "C:\\Windows\\System32\\test.txt"
        else:
            dangerous_path = "/etc/passwd"

        result = is_system_path(dangerous_path)
        assert result is True

    def test_exact_dangerous_path(self):
        """Test exact match with a dangerous path."""
        system = platform.system()

        if system == "Windows":
            dangerous_path = "C:\\Windows"
        else:
            dangerous_path = "/etc"

        result = is_system_path(dangerous_path)
        assert result is True


class TestIsSensitivePath:
    """Tests for is_sensitive_path function (alias)."""

    def test_is_alias_of_is_system_path(self):
        """Test that is_sensitive_path behaves like is_system_path."""
        test_path = "/tmp/test.txt"
        assert is_sensitive_path(test_path) == is_system_path(test_path)


class TestIsDangerousPath:
    """Tests for is_dangerous_path function."""

    def test_returns_bool_by_default(self):
        """Test that is_dangerous_path returns a bool by default."""
        result = is_dangerous_path("/tmp/test.txt")
        assert isinstance(result, bool)

    def test_raise_error_on_dangerous_path(self):
        """Test that raise_error=True raises exception for dangerous paths."""
        system = platform.system()

        if system == "Windows":
            dangerous_path = "C:\\Windows\\System32\\test.txt"
        else:
            dangerous_path = "/etc/passwd"

        with pytest.raises(DangerousPathError) as exc_info:
            is_dangerous_path(dangerous_path, raise_error=True)

        assert "dangerous system location" in str(exc_info.value)

    def test_no_error_on_safe_path(self):
        """Test that raise_error=True doesn't raise exception for safe paths."""
        if platform.system() == "Windows":
            safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
        else:
            safe_path = "/tmp/test.txt"

        result = is_dangerous_path(safe_path, raise_error=True)
        assert result is False


class TestDangerousPathError:
    """Tests for DangerousPathError exception."""

    def test_is_exception(self):
        """Test that DangerousPathError is an Exception."""
        assert issubclass(DangerousPathError, Exception)

    def test_can_be_raised(self):
        """Test that DangerousPathError can be raised."""
        with pytest.raises(DangerousPathError):
            raise DangerousPathError("Test error")

    def test_error_message(self):
        """Test that DangerousPathError carries a message."""
        message = "Test error message"
        with pytest.raises(DangerousPathError) as exc_info:
            raise DangerousPathError(message)
        assert str(exc_info.value) == message


class TestUserDefinedPaths:
    """Tests for user-defined path management functions."""

    def setup_method(self):
        """Clear user paths before each test."""
        clear_user_paths()

    def teardown_method(self):
        """Clear user paths after each test."""
        clear_user_paths()

    def test_add_user_path_string(self):
        """Test adding a user path as string."""
        test_path = "/custom/dangerous/path"
        add_user_path(test_path)
        assert test_path in get_user_paths()

    def test_add_user_path_pathlib(self):
        """Test adding a user path as Path object."""
        test_path = Path("/custom/dangerous/path")
        add_user_path(test_path)
        assert str(test_path) in get_user_paths()

    def test_add_duplicate_path(self):
        """Test that adding duplicate path doesn't create duplicates."""
        test_path = "/custom/path"
        add_user_path(test_path)
        add_user_path(test_path)
        assert get_user_paths().count(test_path) == 1

    def test_remove_user_path(self):
        """Test removing a user path."""
        test_path = "/custom/path"
        add_user_path(test_path)
        assert test_path in get_user_paths()
        remove_user_path(test_path)
        assert test_path not in get_user_paths()

    def test_remove_nonexistent_path(self):
        """Test that removing non-existent path raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            remove_user_path("/nonexistent/path")
        assert "not in the user-defined paths list" in str(exc_info.value)

    def test_clear_user_paths(self):
        """Test clearing all user paths."""
        add_user_path("/path1")
        add_user_path("/path2")
        add_user_path("/path3")
        assert len(get_user_paths()) == 3
        clear_user_paths()
        assert len(get_user_paths()) == 0

    def test_get_user_paths_returns_copy(self):
        """Test that get_user_paths returns a copy."""
        add_user_path("/test/path")
        paths = get_user_paths()
        paths.append("/another/path")
        # Original list should not be modified
        assert "/another/path" not in get_user_paths()

    def test_user_paths_in_dangerous_paths(self):
        """Test that user paths are included in get_dangerous_paths."""
        test_path = "/my/custom/dangerous/path"
        add_user_path(test_path)
        dangerous_paths = get_dangerous_paths()
        assert test_path in dangerous_paths

    def test_user_paths_merged_with_system_paths(self):
        """Test that user paths are merged with system paths."""
        initial_count = len(get_dangerous_paths())
        add_user_path("/custom/path1")
        add_user_path("/custom/path2")
        merged_paths = get_dangerous_paths()
        # Should have original system paths plus 2 new user paths
        assert len(merged_paths) == initial_count + 2

    def test_no_duplicates_in_merged_paths(self):
        """Test that duplicate paths are removed when merging."""
        dangerous_paths = get_dangerous_paths()
        # Try to add a system path as user path
        if dangerous_paths:
            system_path = dangerous_paths[0]
            add_user_path(system_path)
            # Should not increase count since it's a duplicate
            assert len(get_dangerous_paths()) == len(dangerous_paths)

    def test_is_system_path_with_user_path(self):
        """Test that is_system_path detects user-defined paths."""
        test_path = "/my/custom/dangerous"
        add_user_path(test_path)
        # Test exact path
        assert is_system_path(test_path) is True
        # Test subdirectory
        assert is_system_path(f"{test_path}/subdir/file.txt") is True

    def test_is_dangerous_path_with_user_path(self):
        """Test that is_dangerous_path detects user-defined paths."""
        test_path = "/my/custom/dangerous"
        add_user_path(test_path)
        assert is_dangerous_path(f"{test_path}/file.txt") is True

    def test_user_path_with_raise_error(self):
        """Test that user paths trigger DangerousPathError when raise_error=True."""
        test_path = "/my/custom/dangerous"
        add_user_path(test_path)
        with pytest.raises(DangerousPathError):
            is_dangerous_path(f"{test_path}/file.txt", raise_error=True)

