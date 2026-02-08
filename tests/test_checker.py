"""Tests for the bad_path package.

This module contains comprehensive test coverage for path checking functionality,
including platform-specific tests for Windows, macOS (Darwin), and POSIX systems.
"""

import os
import platform
from pathlib import Path

import pytest

from bad_path import (
    DangerousPathError,
    PathChecker,
    add_user_path,
    clear_user_paths,
    get_dangerous_paths,
    get_user_paths,
    is_dangerous_path,
    is_sensitive_path,
    is_system_path,
    remove_user_path,
)
from bad_path.checker import BasePathChecker


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


class TestPathChecker:
    """Tests for PathChecker class."""

    def test_instantiation_with_string(self):
        """Test creating PathChecker with a string path."""
        checker = PathChecker("/tmp/test.txt")
        assert isinstance(checker, BasePathChecker)

    def test_instantiation_with_pathlib(self):
        """Test creating PathChecker with a Path object."""
        checker = PathChecker(Path("/tmp/test.txt"))
        assert isinstance(checker, BasePathChecker)

    def test_bool_false_for_safe_path(self):
        """Test that PathChecker evaluates to True for safe paths."""
        if platform.system() == "Windows":
            safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
        else:
            safe_path = "/tmp/test.txt"

        checker = PathChecker(safe_path)
        assert checker  # Should be True/truthy for safe paths

    def test_bool_true_for_dangerous_path(self):
        """Test that PathChecker evaluates to False for dangerous paths."""
        system = platform.system()

        if system == "Windows":
            dangerous_path = "C:\\Windows\\System32\\test.txt"
        else:
            dangerous_path = "/etc/passwd"

        checker = PathChecker(dangerous_path)
        assert not checker  # Should be False/falsy for dangerous paths

    def test_is_system_path_property_safe(self):
        """Test is_system_path property returns False for safe paths."""
        if platform.system() == "Windows":
            safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
        else:
            safe_path = "/tmp/test.txt"

        checker = PathChecker(safe_path)
        assert checker.is_system_path is False

    def test_is_system_path_property_dangerous(self):
        """Test is_system_path property returns True for dangerous paths."""
        system = platform.system()

        if system == "Windows":
            dangerous_path = "C:\\Windows\\System32\\test.txt"
        else:
            dangerous_path = "/etc/passwd"

        checker = PathChecker(dangerous_path)
        assert checker.is_system_path is True

    def test_is_sensitive_path_property_safe(self):
        """Test is_sensitive_path property returns False for safe paths."""
        if platform.system() == "Windows":
            safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
        else:
            safe_path = "/tmp/test.txt"

        checker = PathChecker(safe_path)
        assert checker.is_sensitive_path is False

    def test_is_sensitive_path_property_dangerous(self):
        """Test is_sensitive_path property returns False for system paths."""
        system = platform.system()

        if system == "Windows":
            dangerous_path = "C:\\Windows\\System32\\test.txt"
        else:
            dangerous_path = "/etc/passwd"

        checker = PathChecker(dangerous_path)
        # System paths should NOT show as sensitive (user-defined)
        assert checker.is_sensitive_path is False

    def test_path_property(self):
        """Test that path property returns the original path."""
        test_path = "/tmp/test.txt"
        checker = PathChecker(test_path)
        assert checker.path == test_path

    def test_repr(self):
        """Test string representation of PathChecker."""
        test_path = "/tmp/test.txt"
        checker = PathChecker(test_path)
        repr_str = repr(checker)
        assert "PathChecker" in repr_str
        assert test_path in repr_str
        assert "safe" in repr_str or "dangerous" in repr_str

    def test_can_use_in_if_statement_safe(self):
        """Test using PathChecker in if statement with safe path."""
        if platform.system() == "Windows":
            safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
        else:
            safe_path = "/tmp/test.txt"

        checker = PathChecker(safe_path)
        if not checker:
            pytest.fail("Safe path should evaluate to True")

    def test_can_use_in_if_statement_dangerous(self):
        """Test using PathChecker in if statement with dangerous path."""
        system = platform.system()

        if system == "Windows":
            dangerous_path = "C:\\Windows\\System32\\test.txt"
        else:
            dangerous_path = "/etc/passwd"

        checker = PathChecker(dangerous_path)
        is_safe = checker  # Should be False for dangerous path
        assert not is_safe

    def test_provides_details_about_danger(self):
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

    def test_with_user_defined_path(self):
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

    def test_exact_dangerous_path(self):
        """Test PathChecker with exact match to dangerous path."""
        system = platform.system()

        if system == "Windows":
            dangerous_path = "C:\\Windows"
        else:
            dangerous_path = "/etc"

        checker = PathChecker(dangerous_path)
        assert not checker  # Dangerous path evaluates to False

    def test_distinction_system_vs_user_paths(self):
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

    def test_both_system_and_user_path(self):
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

    def test_only_user_defined_not_system(self):
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


class TestPathCheckerCall:
    """Tests for PathChecker __call__ method."""

    def test_call_with_new_path_safe(self):
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

    def test_call_with_new_path_dangerous(self):
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

    def test_call_without_path_reloads(self):
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

    def test_call_with_path_does_not_reload(self):
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

    def test_call_with_pathlib_object(self):
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

    def test_call_preserves_original_state(self):
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

    def test_call_updates_properties_when_no_path(self):
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

    def test_call_with_user_defined_path(self):
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

    def test_constructor_raise_error_on_dangerous_system_path(self):
        """Test that raise_error=True in constructor raises exception for dangerous paths."""
        system = platform.system()

        if system == "Windows":
            dangerous_path = "C:\\Windows\\System32\\test.txt"
        else:
            dangerous_path = "/etc/passwd"

        with pytest.raises(DangerousPathError) as exc_info:
            PathChecker(dangerous_path, raise_error=True)

        assert "dangerous location" in str(exc_info.value)

    def test_constructor_raise_error_on_dangerous_user_path(self):
        """Test that raise_error=True in constructor raises exception for user paths."""
        custom_path = "/my/custom/dangerous"
        add_user_path(custom_path)

        try:
            with pytest.raises(DangerousPathError) as exc_info:
                PathChecker(f"{custom_path}/file.txt", raise_error=True)

            assert "dangerous location" in str(exc_info.value)
        finally:
            clear_user_paths()

    def test_constructor_raise_error_false_on_safe_path(self):
        """Test that raise_error=True in constructor doesn't raise for safe paths."""
        if platform.system() == "Windows":
            safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
        else:
            safe_path = "/tmp/test.txt"

        # Should not raise an exception
        checker = PathChecker(safe_path, raise_error=True)
        assert checker  # Safe path (evaluates to True)

    def test_call_raise_error_on_dangerous_path(self):
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

    def test_call_raise_error_on_recheck_with_user_path(self):
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

    def test_call_raise_error_false_on_safe_path(self):
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

    def test_raise_error_default_false_in_constructor(self):
        """Test that raise_error defaults to False in constructor."""
        system = platform.system()

        if system == "Windows":
            dangerous_path = "C:\\Windows\\System32\\test.txt"
        else:
            dangerous_path = "/etc/passwd"

        # Should not raise even though path is dangerous (default raise_error=False)
        checker = PathChecker(dangerous_path)
        assert not checker  # Path is dangerous (evaluates to False) but no exception raised

    def test_raise_error_default_false_in_call(self):
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


class TestPathAccessibility:
    """Tests for path accessibility checking."""

    def test_is_readable_with_readable_file(self, tmp_path):
        """Test is_readable returns True for readable files."""
        # Create a temporary file
        test_file = tmp_path / "test_file.txt"
        test_file.write_text("test content")

        checker = PathChecker(test_file)
        assert checker.is_readable is True

    def test_is_readable_with_nonexistent_file(self, tmp_path):
        """Test is_readable returns False for non-existent files."""
        test_file = tmp_path / "nonexistent.txt"

        checker = PathChecker(test_file)
        assert checker.is_readable is False

    def test_is_writable_with_writable_file(self, tmp_path):
        """Test is_writable returns True for writable files."""
        # Create a temporary file
        test_file = tmp_path / "test_file.txt"
        test_file.write_text("test content")

        checker = PathChecker(test_file)
        assert checker.is_writable is True

    def test_is_writable_with_nonexistent_file(self, tmp_path):
        """Test is_writable returns False for non-existent files."""
        test_file = tmp_path / "nonexistent.txt"

        checker = PathChecker(test_file)
        assert checker.is_writable is False

    def test_is_writable_with_readonly_file(self, tmp_path):
        """Test is_writable returns False for read-only files."""
        # Create a temporary file and make it read-only
        test_file = tmp_path / "readonly.txt"
        test_file.write_text("test content")
        test_file.chmod(0o444)  # Read-only

        checker = PathChecker(test_file)
        assert checker.is_writable is False

        # Cleanup: restore write permission for cleanup
        test_file.chmod(0o644)

    def test_is_creatable_with_writable_parent(self, tmp_path):
        """Test is_creatable returns True when parent is writable."""
        test_file = tmp_path / "new_file.txt"

        checker = PathChecker(test_file)
        assert checker.is_creatable is True

    def test_is_creatable_with_existing_file(self, tmp_path):
        """Test is_creatable returns False for existing files."""
        test_file = tmp_path / "existing.txt"
        test_file.write_text("test content")

        checker = PathChecker(test_file)
        assert checker.is_creatable is False

    def test_is_creatable_with_nonexistent_parent(self, tmp_path):
        """Test is_creatable returns False when parent doesn't exist."""
        test_file = tmp_path / "nonexistent_dir" / "new_file.txt"

        checker = PathChecker(test_file)
        assert checker.is_creatable is False

    def test_accessibility_with_system_path(self):
        """Test accessibility checks work with system paths."""
        system = platform.system()

        if system == "Windows":
            test_path = "C:\\Windows\\System32\\test.txt"
        else:
            test_path = "/etc/passwd"

        checker = PathChecker(test_path)
        # The path should be dangerous (evaluates to False in boolean context)
        assert bool(checker) is False
        # Accessibility depends on actual permissions, just check it doesn't crash
        assert isinstance(checker.is_readable, bool)
        assert isinstance(checker.is_writable, bool)
        assert isinstance(checker.is_creatable, bool)

    def test_accessibility_with_user_defined_path(self, tmp_path):
        """Test accessibility checks with user-defined dangerous paths."""
        test_dir = tmp_path / "custom_dangerous"
        test_dir.mkdir()
        test_file = test_dir / "test.txt"
        test_file.write_text("test")

        # Add as user-defined dangerous path
        add_user_path(str(test_dir))

        try:
            checker = PathChecker(test_file)
            # Should be dangerous due to user-defined path (evaluates to False)
            assert bool(checker) is False
            # But still accessible
            assert checker.is_readable is True
            assert checker.is_writable is True
        finally:
            clear_user_paths()


class TestInvalidCharacters:
    """Tests for invalid character detection in paths."""

    def test_has_invalid_chars_property_exists(self):
        """Test that PathChecker has a has_invalid_chars property."""
        checker = PathChecker("/tmp/test.txt")
        assert hasattr(checker, "has_invalid_chars")
        assert isinstance(checker.has_invalid_chars, bool)

    def test_posix_safe_path_no_invalid_chars(self):
        """Test that a safe POSIX path has no invalid characters."""
        if platform.system() == "Windows":
            pytest.skip("POSIX-specific test")

        checker = PathChecker("/tmp/test_file.txt")
        assert checker.has_invalid_chars is False

    def test_posix_null_byte_is_invalid(self):
        """Test that null byte is detected as invalid on POSIX systems."""
        if platform.system() == "Windows":
            pytest.skip("POSIX-specific test")

        checker = PathChecker("/tmp/test\x00file.txt")
        assert checker.has_invalid_chars is True

    def test_darwin_colon_is_invalid(self):
        """Test that colon is detected as invalid on macOS."""
        if platform.system() != "Darwin":
            pytest.skip("macOS-specific test")

        checker = PathChecker("/tmp/test:file.txt")
        assert checker.has_invalid_chars is True

    def test_darwin_null_byte_is_invalid(self):
        """Test that null byte is detected as invalid on macOS."""
        if platform.system() != "Darwin":
            pytest.skip("macOS-specific test")

        checker = PathChecker("/tmp/test\x00file.txt")
        assert checker.has_invalid_chars is True

    def test_darwin_var_folders_safe(self):
        """Test that /var/folders (temp files) is safe on macOS."""
        if platform.system() != "Darwin":
            pytest.skip("macOS-specific test")

        # /var/folders is used for temporary files and should be safe
        checker = PathChecker("/var/folders/test/file.txt")
        assert checker  # Should be safe
        assert not checker.is_system_path

    def test_darwin_var_subdirs_dangerous(self):
        """Test that /var subdirectories (except folders) are dangerous on macOS."""
        if platform.system() != "Darwin":
            pytest.skip("macOS-specific test")

        # These /var subdirectories should be dangerous
        dangerous_paths = [
            "/var/root/test.txt",
            "/var/db/test.db",
            "/var/log/system.log",
        ]
        for path in dangerous_paths:
            checker = PathChecker(path)
            assert not checker  # Should be dangerous
            assert checker.is_system_path

    def test_windows_invalid_chars(self):
        """Test that Windows invalid characters are detected."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        invalid_chars = ['<', '>', ':', '"', '|', '?', '*']
        for char in invalid_chars:
            checker = PathChecker(f"C:\\tmp\\test{char}file.txt")
            assert checker.has_invalid_chars is True, f"Character '{char}' should be invalid"

    def test_windows_control_chars_are_invalid(self):
        """Test that Windows control characters are detected as invalid."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        # Test a few control characters
        for i in [0, 1, 10, 31]:
            checker = PathChecker(f"C:\\tmp\\test{chr(i)}file.txt")
            assert checker.has_invalid_chars is True, f"Control character {i} should be invalid"

    def test_windows_reserved_names(self):
        """Test that Windows reserved names are detected as invalid."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        reserved_names = ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"]
        for name in reserved_names:
            # Test uppercase
            checker = PathChecker(f"C:\\tmp\\{name}")
            assert checker.has_invalid_chars is True, f"Reserved name '{name}' should be invalid"

            # Test lowercase (case-insensitive)
            checker = PathChecker(f"C:\\tmp\\{name.lower()}")
            msg = f"Reserved name '{name.lower()}' should be invalid"
            assert checker.has_invalid_chars is True, msg

            # Test with extension
            checker = PathChecker(f"C:\\tmp\\{name}.txt")
            msg = f"Reserved name '{name}.txt' should be invalid"
            assert checker.has_invalid_chars is True, msg

    def test_windows_path_ending_with_space(self):
        """Test that Windows paths ending with space are detected as invalid."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        checker = PathChecker("C:\\tmp\\testfile ")
        assert checker.has_invalid_chars is True

    def test_windows_path_ending_with_period(self):
        """Test that Windows paths ending with period are detected as invalid."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        checker = PathChecker("C:\\tmp\\testfile.")
        assert checker.has_invalid_chars is True

    def test_invalid_chars_affects_bool(self):
        """Test that invalid characters make PathChecker evaluate to False (dangerous)."""
        if platform.system() == "Windows":
            test_path = "C:\\tmp\\test<file>.txt"
        elif platform.system() == "Darwin":
            test_path = "/tmp/test:file.txt"
        else:  # POSIX
            test_path = "/tmp/test\x00file.txt"

        checker = PathChecker(test_path)
        # PathChecker evaluates to True when safe, False when dangerous
        assert bool(checker) is False
        assert checker.has_invalid_chars is True

    def test_invalid_chars_with_raise_error(self):
        """Test that invalid characters trigger DangerousPathError when raise_error=True."""
        if platform.system() == "Windows":
            test_path = "C:\\tmp\\test<file>.txt"
        elif platform.system() == "Darwin":
            test_path = "/tmp/test:file.txt"
        else:  # POSIX
            test_path = "/tmp/test\x00file.txt"

        with pytest.raises(DangerousPathError):
            PathChecker(test_path, raise_error=True)

    def test_call_with_invalid_chars_path(self):
        """Test that __call__ method detects invalid characters."""
        checker = PathChecker("/tmp/safe.txt")

        if platform.system() == "Windows":
            test_path = "C:\\tmp\\test<file>.txt"
        elif platform.system() == "Darwin":
            test_path = "/tmp/test:file.txt"
        else:  # POSIX
            test_path = "/tmp/test\x00file.txt"

        # __call__ returns True if dangerous, False if safe
        result = checker(test_path)
        assert result is True

    def test_call_with_invalid_chars_and_raise_error(self):
        """Test that __call__ raises error for invalid characters when raise_error=True."""
        checker = PathChecker("/tmp/safe.txt")

        if platform.system() == "Windows":
            test_path = "C:\\tmp\\test<file>.txt"
        elif platform.system() == "Darwin":
            test_path = "/tmp/test:file.txt"
        else:  # POSIX
            test_path = "/tmp/test\x00file.txt"

        with pytest.raises(DangerousPathError):
            checker(test_path, raise_error=True)

    def test_is_dangerous_path_with_invalid_chars(self):
        """Test that is_dangerous_path function detects invalid characters."""
        if platform.system() == "Windows":
            test_path = "C:\\tmp\\test<file>.txt"
        elif platform.system() == "Darwin":
            test_path = "/tmp/test:file.txt"
        else:  # POSIX
            test_path = "/tmp/test\x00file.txt"

        result = is_dangerous_path(test_path)
        assert result is True

    def test_repr_with_invalid_chars(self):
        """Test that __repr__ correctly shows dangerous status for invalid characters."""
        if platform.system() == "Windows":
            test_path = "C:\\tmp\\test<file>.txt"
        elif platform.system() == "Darwin":
            test_path = "/tmp/test:file.txt"
        else:  # POSIX
            test_path = "/tmp/test\x00file.txt"

        checker = PathChecker(test_path)
        repr_str = repr(checker)
        assert "dangerous" in repr_str

    def test_safe_path_with_special_but_valid_chars(self):
        """Test that paths with special but valid characters are not flagged."""
        # These characters should be safe on most systems
        if platform.system() == "Windows":
            # Windows has many restrictions; using basic safe chars for test
            test_path = "C:\\tmp\\test_file-name.txt"
        else:
            # POSIX/Darwin allow most characters except null byte and colon (Darwin)
            test_path = "/tmp/test_file-name@#$%^&().txt"

        checker = PathChecker(test_path)
        assert checker.has_invalid_chars is False
        assert bool(checker) is True  # Should be safe

    def test_combined_system_path_and_invalid_chars(self):
        """Test that both system path and invalid chars are detected independently."""
        if platform.system() == "Windows":
            test_path = "C:\\Windows\\test<file>.txt"
        else:
            test_path = "/etc/test\x00file.txt"

        checker = PathChecker(test_path)
        # Should be dangerous for both reasons
        assert bool(checker) is False
        # At least one should be true (depends on platform and path resolution)
        assert checker.is_system_path or checker.has_invalid_chars


class TestPathCheckerFlags:
    """Tests for PathChecker flag parameters (system_ok, user_paths_ok, not_writeable)."""

    def setup_method(self):
        """Set up test environment."""
        clear_user_paths()

    def teardown_method(self):
        """Clean up test environment."""
        clear_user_paths()

    def test_system_ok_allows_system_path(self):
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

    def test_user_paths_ok_allows_user_paths(self):
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

    def test_both_flags_together(self):
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

    def test_not_writeable_allows_readonly_paths(self):
        """Test that not_writeable=True allows read-only paths."""
        # Create a temporary file and test with different permissions
        import stat
        import tempfile

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

    def test_not_writeable_with_writable_file(self):
        """Test that not_writeable flag doesn't affect writable files."""
        import tempfile

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

    def test_not_writeable_with_nonexistent_path(self):
        """Test that not_writeable flag doesn't affect non-existent paths."""
        nonexistent = "/tmp/nonexistent_file_12345.txt"

        # Non-existent path should be safe (no write check applies)
        checker1 = PathChecker(nonexistent)
        assert checker1

        checker2 = PathChecker(nonexistent, not_writeable=True)
        assert checker2

    def test_flags_with_raise_error(self):
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

    def test_invalid_chars_always_dangerous(self):
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

    def test_call_method_respects_flags(self):
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

    def test_flags_default_to_false(self):
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

    def test_repr_with_flags(self):
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


class TestPathCheckerMode:
    """Tests for PathChecker mode parameter (read/write)."""

    def setup_method(self):
        """Set up test environment."""
        clear_user_paths()

    def teardown_method(self):
        """Clean up test environment."""
        clear_user_paths()

    def test_mode_read_allows_system_paths(self):
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

    def test_mode_write_strict_validation(self):
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

    def test_mode_read_allows_user_paths(self):
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

    def test_mode_write_rejects_user_paths(self):
        """Test that mode='write' rejects user-defined paths."""
        custom_path = "/my/sensitive/data"
        add_user_path(custom_path)
        data_file = f"{custom_path}/important.dat"

        # Write mode - should be dangerous
        checker = PathChecker(data_file, mode="write")
        assert not checker  # Dangerous for writing
        assert checker.is_sensitive_path

    def test_mode_read_allows_non_writable(self):
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

    def test_mode_none_respects_individual_flags(self):
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

    def test_mode_invalid_value_raises_error(self):
        """Test that invalid mode value raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            PathChecker("/tmp/test.txt", mode="invalid")
        assert "Invalid mode" in str(exc_info.value)
        assert "'invalid'" in str(exc_info.value)

    def test_mode_overrides_individual_flags(self):
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

    def test_mode_read_with_safe_path(self):
        """Test that mode='read' works with safe paths too."""
        safe_path = "/tmp/safe_file.txt"

        checker = PathChecker(safe_path, mode="read")
        assert checker  # Safe path is safe in read mode

    def test_mode_write_with_safe_path(self):
        """Test that mode='write' works with safe paths."""
        safe_path = "/tmp/safe_file.txt"

        checker = PathChecker(safe_path, mode="write")
        assert checker  # Safe path is safe in write mode

    def test_mode_read_with_raise_error(self):
        """Test that mode='read' with raise_error doesn't raise for system paths."""
        system = platform.system()

        if system == "Windows":
            system_path = "C:\\Windows\\System32\\config\\SAM"
        else:
            system_path = "/etc/passwd"

        # Should not raise in read mode
        checker = PathChecker(system_path, mode="read", raise_error=True)
        assert checker.is_system_path

    def test_mode_write_with_raise_error(self):
        """Test that mode='write' with raise_error raises for system paths."""
        system = platform.system()

        if system == "Windows":
            system_path = "C:\\Windows\\System32\\test.txt"
        else:
            system_path = "/etc/passwd"

        # Should raise in write mode
        with pytest.raises(DangerousPathError):
            PathChecker(system_path, mode="write", raise_error=True)

    def test_mode_read_invalid_chars_still_dangerous(self):
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

    def test_mode_case_sensitive(self):
        """Test that mode parameter is case-sensitive."""
        # Capital case should raise error
        with pytest.raises(ValueError):
            PathChecker("/tmp/test.txt", mode="READ")

        with pytest.raises(ValueError):
            PathChecker("/tmp/test.txt", mode="Write")

