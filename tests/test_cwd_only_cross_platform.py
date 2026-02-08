"""Platform-agnostic tests for cwd_only flag to verify cross-platform compatibility."""

import platform
from pathlib import Path

import pytest

from bad_path import PathChecker


def test_cwd_only_with_platform_specific_paths():
    """Test cwd_only flag with platform-specific path formats."""
    system = platform.system()

    # Test with platform-appropriate path separators
    if system == "Windows":
        # Windows-style paths
        subdir_path = Path.cwd() / "subdir\\file.txt"
        checker = PathChecker(subdir_path, cwd_only=True)
        assert checker  # Should be safe (within CWD)

        # Windows absolute path outside CWD
        outside_path = "C:\\Users\\test\\file.txt"
        checker = PathChecker(outside_path, cwd_only=True)
        # Will be dangerous if not within CWD
        if not str(Path(outside_path).resolve()).startswith(str(Path.cwd().resolve())):
            assert not checker
    else:
        # Unix-style paths (Linux/macOS)
        subdir_path = Path.cwd() / "subdir/file.txt"
        checker = PathChecker(subdir_path, cwd_only=True)
        assert checker  # Should be safe (within CWD)


def test_cwd_only_resolves_paths_correctly():
    """Test that cwd_only correctly resolves relative paths on all platforms."""
    # Test with various relative path formats
    test_cases = [
        (".", True),  # Current directory
        ("./file.txt", True),  # File in current directory
        ("subdir/file.txt", True),  # File in subdirectory
        ("./subdir/../file.txt", True),  # Complex but stays in CWD
        ("../file.txt", False),  # Parent directory
    ]

    for path, should_be_safe in test_cases:
        checker = PathChecker(path, cwd_only=True)
        if should_be_safe:
            assert checker, f"Path '{path}' should be safe with cwd_only=True"
        else:
            assert not checker, f"Path '{path}' should be dangerous with cwd_only=True"


def test_cwd_only_independent_of_platform_paths():
    """Test that cwd_only works independently of platform-specific system paths."""
    system = platform.system()

    # Create a path that might be a system path on this platform
    if system == "Windows":
        # Windows system path outside CWD
        system_path = "C:\\Windows\\System32\\test.txt"
    elif system == "Darwin":
        # macOS system path outside CWD
        system_path = "/System/Library/test.txt"
    else:
        # Linux system path outside CWD
        system_path = "/etc/passwd"

    # With cwd_only, it should be dangerous because it's outside CWD
    # regardless of whether it's a system path
    checker = PathChecker(system_path, cwd_only=True, system_ok=True, not_writeable=True)
    # Should still be dangerous due to cwd_only (if not within CWD)
    if not str(Path(system_path).resolve()).startswith(str(Path.cwd().resolve())):
        assert not checker


def test_cwd_only_with_absolute_vs_relative():
    """Test cwd_only with both absolute and relative path formats."""
    cwd = Path.cwd()

    # Absolute path within CWD
    abs_within = cwd / "test.txt"
    checker = PathChecker(abs_within, cwd_only=True)
    assert checker  # Should be safe

    # Relative path within CWD
    rel_within = "test.txt"
    checker = PathChecker(rel_within, cwd_only=True)
    assert checker  # Should be safe

    # Absolute path outside CWD
    abs_outside = cwd.parent / "test.txt"
    checker = PathChecker(abs_outside, cwd_only=True)
    assert not checker  # Should be dangerous

    # Relative path outside CWD
    rel_outside = "../test.txt"
    checker = PathChecker(rel_outside, cwd_only=True)
    assert not checker  # Should be dangerous


def test_cwd_only_path_normalization():
    """Test that cwd_only handles path normalization correctly across platforms."""
    # Paths with redundant separators and dots
    test_paths = [
        "./././file.txt",  # Multiple dots
        "subdir/./file.txt",  # Dot in middle
        "subdir//file.txt",  # Double separator (if on Windows)
    ]

    for path in test_paths:
        # All these should resolve within CWD
        checker = PathChecker(path, cwd_only=True)
        assert checker, f"Path '{path}' should be safe (within CWD)"


def test_cwd_only_with_deep_nesting():
    """Test cwd_only with deeply nested paths."""
    # Very deep subdirectory path
    deep_path = Path.cwd() / "a" / "b" / "c" / "d" / "e" / "f" / "g" / "file.txt"
    checker = PathChecker(deep_path, cwd_only=True)
    assert checker  # Should be safe

    # Path that goes up from deep nesting but stays in CWD
    nested_path = "a/b/c/../../d/file.txt"
    checker = PathChecker(nested_path, cwd_only=True)
    assert checker  # Should be safe (resolves to cwd/a/d/file.txt)


def test_cwd_only_documentation_examples():
    """Test the examples from the documentation work correctly."""
    # Example 1: Block path traversal
    checker = PathChecker("../../../etc/passwd", cwd_only=True)
    assert not checker  # Should be dangerous

    # Example 2: Block paths outside CWD
    checker = PathChecker("/tmp/file.txt", cwd_only=True)
    # Should be dangerous if /tmp is not within CWD
    if not str(Path("/tmp/file.txt").resolve()).startswith(str(Path.cwd().resolve())):
        assert not checker

    # Example 3: Allow paths within CWD
    checker = PathChecker("./data/file.txt", cwd_only=True)
    assert checker  # Should be safe


if __name__ == "__main__":
    # Run the tests manually for debugging
    pytest.main([__file__, "-v", "--pdb"])
