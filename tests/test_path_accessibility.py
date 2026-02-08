"""Tests for path accessibility checking."""

import platform

import pytest

from bad_path import PathChecker, add_user_path, clear_user_paths


def test_is_readable_with_readable_file(tmp_path):
    """Test is_readable returns True for readable files."""
    # Create a temporary file
    test_file = tmp_path / "test_file.txt"
    test_file.write_text("test content")

    checker = PathChecker(test_file)
    assert checker.is_readable is True


def test_is_readable_with_nonexistent_file(tmp_path):
    """Test is_readable returns False for non-existent files."""
    test_file = tmp_path / "nonexistent.txt"

    checker = PathChecker(test_file)
    assert checker.is_readable is False


def test_is_writable_with_writable_file(tmp_path):
    """Test is_writable returns True for writable files."""
    # Create a temporary file
    test_file = tmp_path / "test_file.txt"
    test_file.write_text("test content")

    checker = PathChecker(test_file)
    assert checker.is_writable is True


def test_is_writable_with_nonexistent_file(tmp_path):
    """Test is_writable returns False for non-existent files."""
    test_file = tmp_path / "nonexistent.txt"

    checker = PathChecker(test_file)
    assert checker.is_writable is False


def test_is_writable_with_readonly_file(tmp_path):
    """Test is_writable returns False for read-only files."""
    # Create a temporary file and make it read-only
    test_file = tmp_path / "readonly.txt"
    test_file.write_text("test content")
    test_file.chmod(0o444)  # Read-only

    checker = PathChecker(test_file)
    assert checker.is_writable is False

    # Cleanup: restore write permission for cleanup
    test_file.chmod(0o644)


def test_is_creatable_with_writable_parent(tmp_path):
    """Test is_creatable returns True when parent is writable."""
    test_file = tmp_path / "new_file.txt"

    checker = PathChecker(test_file)
    assert checker.is_creatable is True


def test_is_creatable_with_existing_file(tmp_path):
    """Test is_creatable returns False for existing files."""
    test_file = tmp_path / "existing.txt"
    test_file.write_text("test content")

    checker = PathChecker(test_file)
    assert checker.is_creatable is False


def test_is_creatable_with_nonexistent_parent(tmp_path):
    """Test is_creatable returns False when parent doesn't exist."""
    test_file = tmp_path / "nonexistent_dir" / "new_file.txt"

    checker = PathChecker(test_file)
    assert checker.is_creatable is False


def test_accessibility_with_system_path():
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


def test_accessibility_with_user_defined_path(tmp_path):
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


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--pdb"])
