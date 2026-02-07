"""
Core functionality for checking dangerous file paths.
"""

import platform
from pathlib import Path
from typing import List, Union


class DangerousPathError(Exception):
    """Exception raised when a dangerous path is detected."""

    pass


# Module-level list of user-defined dangerous paths
_user_defined_paths: List[str] = []


def add_user_path(path: Union[str, Path]) -> None:
    """
    Add a user-defined path to the list of dangerous paths.

    Args:
        path: The path to add (string or Path object)
    """
    path_str = str(path)
    if path_str not in _user_defined_paths:
        _user_defined_paths.append(path_str)


def remove_user_path(path: Union[str, Path]) -> None:
    """
    Remove a user-defined path from the list of dangerous paths.

    Args:
        path: The path to remove (string or Path object)

    Raises:
        ValueError: If the path is not in the user-defined paths list
    """
    path_str = str(path)
    if path_str in _user_defined_paths:
        _user_defined_paths.remove(path_str)
    else:
        raise ValueError(f"Path '{path_str}' is not in the user-defined paths list")


def clear_user_paths() -> None:
    """
    Clear all user-defined dangerous paths.
    """
    _user_defined_paths.clear()


def get_user_paths() -> List[str]:
    """
    Get the list of user-defined dangerous paths.

    Returns:
        List of user-defined dangerous path patterns.
    """
    return _user_defined_paths.copy()


def get_dangerous_paths() -> List[str]:
    """
    Get a list of dangerous/sensitive paths based on the current OS.
    Includes both system paths and user-defined paths.

    Returns:
        List of dangerous path patterns for the current operating system,
        combined with user-defined paths (duplicates removed).
    """
    match platform.system():
        case "Windows":
            from .platforms.windows import system_paths
        case "Darwin":
            from .platforms.darwin import system_paths
        case _:  # Linux and other Unix-like systems
            from .platforms.posix import system_paths

    # Merge system paths and user-defined paths using sets to avoid duplicates
    all_paths = set(system_paths) | set(_user_defined_paths)
    return list(all_paths)


def is_system_path(path: Union[str, Path]) -> bool:
    """
    Check if a path is within a system directory.

    Args:
        path: The file path to check (string or Path object)

    Returns:
        True if the path is within a system directory, False otherwise.
    """
    path_obj = Path(path).resolve()
    dangerous_paths = get_dangerous_paths()

    for dangerous in dangerous_paths:
        try:
            dangerous_obj = Path(dangerous).resolve()
            # Check if path is the dangerous path or a subdirectory of it
            if path_obj == dangerous_obj or dangerous_obj in path_obj.parents:
                return True
        except (OSError, ValueError):
            # Handle cases where path resolution fails
            continue

    return False


def is_sensitive_path(path: Union[str, Path]) -> bool:
    """
    Check if a path points to a sensitive location.

    This is an alias for is_system_path() for backwards compatibility
    and semantic clarity.

    Args:
        path: The file path to check (string or Path object)

    Returns:
        True if the path is sensitive, False otherwise.
    """
    return is_system_path(path)


def is_dangerous_path(path: Union[str, Path], raise_error: bool = False) -> bool:
    """
    Check if a path is dangerous (points to a system-sensitive location).

    Args:
        path: The file path to check (string or Path object)
        raise_error: If True, raise DangerousPathError instead of returning True

    Returns:
        True if the path is dangerous, False otherwise.

    Raises:
        DangerousPathError: If raise_error is True and the path is dangerous.
    """
    is_dangerous = is_system_path(path)

    if is_dangerous and raise_error:
        raise DangerousPathError(f"Path '{path}' points to a dangerous system location")

    return is_dangerous
