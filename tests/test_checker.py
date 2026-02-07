"""
Tests for the bad_path package.
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
        assert isinstance(checker, PathChecker)

    def test_instantiation_with_pathlib(self):
        """Test creating PathChecker with a Path object."""
        checker = PathChecker(Path("/tmp/test.txt"))
        assert isinstance(checker, PathChecker)

    def test_bool_false_for_safe_path(self):
        """Test that PathChecker evaluates to False for safe paths."""
        if platform.system() == "Windows":
            safe_path = os.path.join(os.path.expanduser("~"), "Documents", "test.txt")
        else:
            safe_path = "/tmp/test.txt"

        checker = PathChecker(safe_path)
        assert not checker  # Should be False/falsy

    def test_bool_true_for_dangerous_path(self):
        """Test that PathChecker evaluates to True for dangerous paths."""
        system = platform.system()

        if system == "Windows":
            dangerous_path = "C:\\Windows\\System32\\test.txt"
        else:
            dangerous_path = "/etc/passwd"

        checker = PathChecker(dangerous_path)
        assert checker  # Should be True/truthy

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
        if checker:
            pytest.fail("Safe path should not evaluate to True")

    def test_can_use_in_if_statement_dangerous(self):
        """Test using PathChecker in if statement with dangerous path."""
        system = platform.system()

        if system == "Windows":
            dangerous_path = "C:\\Windows\\System32\\test.txt"
        else:
            dangerous_path = "/etc/passwd"

        checker = PathChecker(dangerous_path)
        is_dangerous = False
        if checker:
            is_dangerous = True
        assert is_dangerous

    def test_provides_details_about_danger(self):
        """Test that PathChecker provides details about why path is dangerous."""
        system = platform.system()

        if system == "Windows":
            dangerous_path = "C:\\Windows\\System32\\test.txt"
        else:
            dangerous_path = "/etc/passwd"

        checker = PathChecker(dangerous_path)
        # Can check both that it's dangerous and get details
        assert checker  # It's dangerous
        assert checker.is_system_path  # It's a system path
        assert not checker.is_sensitive_path  # It's NOT a user-defined path

    def test_with_user_defined_path(self):
        """Test PathChecker with user-defined dangerous paths."""
        # Setup
        test_path = "/my/custom/dangerous"
        add_user_path(test_path)

        try:
            checker = PathChecker(f"{test_path}/file.txt")
            assert checker  # Should be dangerous
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
        assert checker

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
            assert checker  # Should be dangerous
        finally:
            clear_user_paths()

    def test_only_user_defined_not_system(self):
        """Test that user-defined paths work for non-system locations."""
        system = platform.system()

        # Use platform-specific non-system paths
        if system == "Windows":
            custom_path = os.path.join(os.path.expanduser("~"), "MySensitiveProject")
        else:
            custom_path = "/home/user/my_sensitive_project"
        add_user_path(custom_path)

        try:
            checker = PathChecker(f"{custom_path}/secret.txt")
            assert checker  # Should be dangerous
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
        assert checker  # Original path is dangerous

        # Check a different safe path without reloading
        result = checker(safe_path)
        assert result is False  # New path is safe

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
        assert not checker  # Original path is safe

        # Check a different dangerous path without reloading
        result = checker(dangerous_path)
        assert result is True  # New path is dangerous

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
        assert not checker  # Not dangerous yet

        # Add the path to user paths
        add_user_path(custom_path)

        try:
            # Call without path should reload and recheck
            result = checker()
            assert result is True  # Should now be dangerous

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
        assert not checker  # Safe path

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
        assert not checker
        assert not checker.is_sensitive_path

        # Add user path
        add_user_path(custom_path)

        try:
            # Call without path to reload
            result = checker()

            # Should be dangerous now
            assert result is True
            assert checker.is_sensitive_path is True
            assert bool(checker) is True
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
            assert not checker

            # Check the user-defined dangerous path
            result = checker(test_file)
            assert result is True  # Should be dangerous
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
        assert not checker

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
        assert not checker  # Initially safe

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
        assert checker  # Path is dangerous but no exception raised

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


