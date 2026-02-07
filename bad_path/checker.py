"""
Core functionality for checking dangerous file paths.
"""

import platform
from pathlib import Path
from typing import List, Union


class DangerousPathError(Exception):
    """Exception raised when a dangerous path is detected."""

    pass


def get_dangerous_paths() -> List[str]:
    """
    Get a list of dangerous/sensitive paths based on the current OS.

    Returns:
        List of dangerous path patterns for the current operating system.
    """
    match platform.system():
        case "Windows":
            from .platforms.windows import system_paths
        case "Darwin":
            from .platforms.darwin import system_paths
        case _:  # Linux and other Unix-like systems
            from .platforms.posix import system_paths
    
    return system_paths


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
