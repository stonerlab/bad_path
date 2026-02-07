"""A Python package to identify potentially dangerous file paths.

This package provides functions to test whether a supplied file path points to a
system-sensitive location, taking into account different OS platforms. The package
includes platform-specific checkers for Windows, macOS (Darwin), and POSIX systems,
along with support for user-defined sensitive paths.
"""

__version__ = "0.1.0"

from .checker import (
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

__all__ = [
    "PathChecker",
    "is_dangerous_path",
    "is_system_path",
    "is_sensitive_path",
    "get_dangerous_paths",
    "DangerousPathError",
    "add_user_path",
    "remove_user_path",
    "clear_user_paths",
    "get_user_paths",
]
