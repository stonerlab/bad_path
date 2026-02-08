"""Tests for PathChecker cwd_only parameter (path traversal protection)."""

import os
import tempfile
from pathlib import Path

import pytest

from bad_path import DangerousPathError, PathChecker


def test_cwd_only_default_false():
    """Test that cwd_only defaults to False, allowing paths outside CWD."""
    # Path outside CWD should be safe without cwd_only flag
    parent_path = Path.cwd().parent / "test.txt"
    checker = PathChecker(parent_path)
    # Should be safe (assuming it's not a system path)
    assert checker or checker.is_system_path  # Either safe or flagged for other reasons


def test_cwd_only_blocks_parent_directory():
    """Test that cwd_only=True blocks paths in parent directory."""
    parent_path = Path.cwd().parent / "test.txt"
    checker = PathChecker(parent_path, cwd_only=True)
    assert not checker  # Should be dangerous due to being outside CWD


def test_cwd_only_blocks_relative_parent():
    """Test that cwd_only=True blocks relative parent paths."""
    checker = PathChecker("../test.txt", cwd_only=True)
    assert not checker  # Should be dangerous


def test_cwd_only_blocks_multiple_parent():
    """Test that cwd_only=True blocks paths with multiple parent traversals."""
    checker = PathChecker("../../test.txt", cwd_only=True)
    assert not checker  # Should be dangerous

    checker = PathChecker("../../../etc/passwd", cwd_only=True)  # nosec B108
    assert not checker  # Should be dangerous


def test_cwd_only_allows_cwd_file():
    """Test that cwd_only=True allows files in CWD."""
    cwd_path = Path.cwd() / "test.txt"
    checker = PathChecker(cwd_path, cwd_only=True)
    assert checker  # Should be safe


def test_cwd_only_allows_cwd_subdirectory():
    """Test that cwd_only=True allows paths in CWD subdirectories."""
    subdir_path = Path.cwd() / "subdir" / "test.txt"
    checker = PathChecker(subdir_path, cwd_only=True)
    assert checker  # Should be safe


def test_cwd_only_allows_deep_subdirectory():
    """Test that cwd_only=True allows paths in deep subdirectories."""
    deep_path = Path.cwd() / "a" / "b" / "c" / "test.txt"
    checker = PathChecker(deep_path, cwd_only=True)
    assert checker  # Should be safe


def test_cwd_only_allows_relative_subdirectory():
    """Test that cwd_only=True allows relative paths to subdirectories."""
    checker = PathChecker("subdir/test.txt", cwd_only=True)
    assert checker  # Should be safe

    checker = PathChecker("./subdir/test.txt", cwd_only=True)
    assert checker  # Should be safe


def test_cwd_only_blocks_absolute_path_outside_cwd():
    """Test that cwd_only=True blocks absolute paths outside CWD."""
    with tempfile.TemporaryDirectory() as tmpdir:  # nosec B108
        if Path(tmpdir).resolve() != Path.cwd().resolve():
            # Only test if temp dir is actually outside CWD
            outside_path = Path(tmpdir) / "test.txt"
            checker = PathChecker(outside_path, cwd_only=True)
            assert not checker  # Should be dangerous


def test_cwd_only_with_raise_error():
    """Test that cwd_only=True raises DangerousPathError with raise_error=True."""
    parent_path = Path.cwd().parent / "test.txt"
    with pytest.raises(DangerousPathError):
        PathChecker(parent_path, cwd_only=True, raise_error=True)


def test_cwd_only_false_allows_parent():
    """Test that cwd_only=False (default) allows parent paths."""
    parent_path = Path.cwd().parent / "test.txt"
    checker = PathChecker(parent_path, cwd_only=False)
    # Should be safe unless it's a system path
    assert checker or checker.is_system_path


def test_cwd_only_with_system_ok():
    """Test that cwd_only works independently of system_ok flag."""
    # Path outside CWD should be dangerous with cwd_only=True
    # even if it's allowed by system_ok
    parent_path = Path.cwd().parent / "test.txt"
    checker = PathChecker(parent_path, cwd_only=True, system_ok=True, not_writeable=True)
    assert not checker  # Still dangerous due to cwd_only


def test_cwd_only_with_user_paths_ok():
    """Test that cwd_only works independently of user_paths_ok flag."""
    parent_path = Path.cwd().parent / "test.txt"
    checker = PathChecker(parent_path, cwd_only=True, user_paths_ok=True)
    assert not checker  # Still dangerous due to cwd_only


def test_cwd_only_call_method():
    """Test that cwd_only works with __call__ method."""
    checker = PathChecker("/tmp/safe.txt", cwd_only=True)  # nosec B108

    # Check a path outside CWD using __call__
    parent_path = Path.cwd().parent / "test.txt"
    is_dangerous = checker(parent_path)
    assert is_dangerous  # Should be dangerous

    # Check a path inside CWD using __call__
    cwd_path = Path.cwd() / "test.txt"
    is_dangerous = checker(cwd_path)
    assert not is_dangerous  # Should be safe


def test_cwd_only_call_method_with_raise_error():
    """Test that cwd_only works with __call__ method and raise_error."""
    checker = PathChecker("/tmp/safe.txt", cwd_only=True)  # nosec B108

    parent_path = Path.cwd().parent / "test.txt"
    with pytest.raises(DangerousPathError):
        checker(parent_path, raise_error=True)


def test_cwd_only_with_nonexistent_path():
    """Test that cwd_only works with nonexistent paths."""
    # Nonexistent path in CWD should be safe
    cwd_path = Path.cwd() / "nonexistent" / "test.txt"
    checker = PathChecker(cwd_path, cwd_only=True)
    assert checker  # Should be safe

    # Nonexistent path outside CWD should be dangerous
    parent_path = Path.cwd().parent / "nonexistent" / "test.txt"
    checker = PathChecker(parent_path, cwd_only=True)
    assert not checker  # Should be dangerous


def test_cwd_only_with_current_directory():
    """Test that cwd_only allows the current directory itself."""
    checker = PathChecker(Path.cwd(), cwd_only=True)
    assert checker  # Should be safe


def test_cwd_only_with_dot_path():
    """Test that cwd_only allows '.' (current directory)."""
    checker = PathChecker(".", cwd_only=True)
    assert checker  # Should be safe


def test_cwd_only_complex_traversal():
    """Test cwd_only with complex path traversal patterns."""
    # Path that goes up and then down, but ends up outside CWD
    complex_path = "../../somewhere/else/file.txt"
    checker = PathChecker(complex_path, cwd_only=True)
    assert not checker  # Should be dangerous

    # Path that goes up and down but stays in CWD (if it resolves within)
    # This is hard to test portably, so we'll just ensure the logic works
    complex_path = "./subdir/../file.txt"
    checker = PathChecker(complex_path, cwd_only=True)
    assert checker  # Should be safe as it resolves to CWD


def test_cwd_only_with_symlink():
    """Test cwd_only with symbolic links (if supported)."""
    with tempfile.TemporaryDirectory() as tmpdir:  # nosec B108
        # Create a file outside CWD
        outside_file = Path(tmpdir) / "outside.txt"
        outside_file.write_text("test")

        # Create a symlink in CWD pointing to outside file
        symlink_path = Path.cwd() / "link_to_outside.txt"
        try:
            symlink_path.symlink_to(outside_file)

            # With cwd_only, the symlink itself is in CWD, but it resolves outside
            # The resolved path should be outside CWD, so it should be dangerous
            checker = PathChecker(symlink_path, cwd_only=True)
            # The behavior depends on whether the symlink resolves outside CWD
            # Since symlink points outside, resolved path is outside
            if Path.cwd().resolve() not in symlink_path.resolve().parents:
                assert not checker  # Should be dangerous if resolved outside CWD

        except (OSError, NotImplementedError):
            # Symlinks not supported on this platform
            pytest.skip("Symbolic links not supported on this platform")
        finally:
            # Clean up
            if symlink_path.exists() or symlink_path.is_symlink():
                symlink_path.unlink()


def test_cwd_only_repr():
    """Test that __repr__ works correctly with cwd_only flag."""
    parent_path = Path.cwd().parent / "test.txt"

    # Without cwd_only - may be safe
    checker1 = PathChecker(parent_path)
    repr1 = repr(checker1)
    # Either safe or dangerous depending on if it's a system path
    assert "PathChecker" in repr1

    # With cwd_only - should be dangerous
    checker2 = PathChecker(parent_path, cwd_only=True)
    repr2 = repr(checker2)
    assert "dangerous" in repr2


def test_cwd_only_with_mode():
    """Test that cwd_only flag is independent of mode parameter."""
    parent_path = Path.cwd().parent / "test.txt"

    # Even with mode="read", cwd_only should still restrict
    checker = PathChecker(parent_path, mode="read", cwd_only=True)
    assert not checker  # Should be dangerous due to cwd_only

    # With mode="write", cwd_only should still restrict
    checker = PathChecker(parent_path, mode="write", cwd_only=True)
    assert not checker  # Should be dangerous due to cwd_only
