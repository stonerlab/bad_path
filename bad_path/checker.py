"""
Core functionality for checking dangerous file paths.
"""

import platform
from pathlib import Path
from typing import List, Optional, Union


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


class PathChecker:
    """
    A class to check if a path is dangerous and provide details about why.

    The class can be used in boolean context where it evaluates to True
    if the path is dangerous, False otherwise.

    The class distinguishes between platform-specific system paths and
    user-defined sensitive paths through separate properties.

    Example:
        checker = PathChecker("/etc/passwd")
        if checker:
            print(f"Dangerous path! System path: {checker.is_system_path}")
            print(f"User-defined: {checker.is_sensitive_path}")
    """

    def __init__(self, path: Union[str, Path], raise_error: bool = False):
        """
        Initialize the PathChecker with a path to check.

        Args:
            path: The file path to check (string or Path object)
            raise_error: If True, raise DangerousPathError if the path is dangerous

        Raises:
            DangerousPathError: If raise_error is True and the path is dangerous.
        """
        self._path = path
        self._path_obj = Path(path).resolve()
        self._raise_error = raise_error

        # Load paths and check the initial path
        self._load_and_check_paths()

        # Raise error if requested and path is dangerous
        if self._raise_error and (self._is_system_path or self._is_user_path):
            raise DangerousPathError(f"Path '{path}' points to a dangerous location")

    def _load_and_check_paths(self) -> None:
        """
        Load system and user paths, then check the current path against them.
        """
        # Get system paths separately from user paths
        match platform.system():
            case "Windows":
                from .platforms.windows import system_paths
            case "Darwin":
                from .platforms.darwin import system_paths
            case _:  # Linux and other Unix-like systems
                from .platforms.posix import system_paths

        self._system_paths = system_paths
        self._user_paths = get_user_paths()

        # Check both types
        self._is_system_path = self._check_against_paths(self._system_paths)
        self._is_user_path = self._check_against_paths(self._user_paths)

    def _check_against_paths(self, paths: List[str], path_obj: Optional[Path] = None) -> bool:
        """
        Internal method to check if a path matches any in the given list.

        Args:
            paths: List of paths to check against
            path_obj: Optional Path object to check. If not provided, uses self._path_obj

        Returns:
            True if the path matches any in the list, False otherwise.
        """
        if path_obj is None:
            path_obj = self._path_obj

        for dangerous in paths:
            try:
                dangerous_obj = Path(dangerous).resolve()
                # Check if path is the dangerous path or a subdirectory of it
                if path_obj == dangerous_obj or dangerous_obj in path_obj.parents:
                    return True
            except (OSError, ValueError):
                # Handle cases where path resolution fails
                continue
        return False

    def __call__(self, path: Optional[Union[str, Path]] = None, raise_error: bool = False) -> bool:
        """
        Check a path for danger, with optional path reload.

        Args:
            path: Optional path to check. If provided, checks the new path against
                  existing system and user paths (without reloading). If not provided,
                  rechecks the original path against reloaded system and user paths.
            raise_error: If True, raise DangerousPathError if the path is dangerous

        Returns:
            True if the path is dangerous, False otherwise.

        Raises:
            DangerousPathError: If raise_error is True and the path is dangerous.

        Example:
            checker = PathChecker("/etc/passwd")
            # Check a different path without reloading
            is_dangerous = checker("/home/user/file.txt")
            # Recheck original path with reloaded paths
            is_dangerous = checker()
            # Check with error raising
            checker("/etc/passwd", raise_error=True)  # Raises DangerousPathError
        """
        if path is not None:
            # Check the new path against existing paths (no reload)
            path_obj = Path(path).resolve()

            # Check against existing paths
            is_sys_path = self._check_against_paths(self._system_paths, path_obj)
            is_usr_path = self._check_against_paths(self._user_paths, path_obj)

            is_dangerous = is_sys_path or is_usr_path

            if is_dangerous and raise_error:
                raise DangerousPathError(f"Path '{path}' points to a dangerous location")

            return is_dangerous
        else:
            # Reload paths and check the original path
            self._load_and_check_paths()
            is_dangerous = self._is_system_path or self._is_user_path

            if is_dangerous and raise_error:
                raise DangerousPathError(f"Path '{self._path}' points to a dangerous location")

            return is_dangerous

    def __bool__(self) -> bool:
        """
        Return True if the path is dangerous, False otherwise.

        A path is considered dangerous if it matches either a platform-specific
        system path or a user-defined sensitive path.

        This allows the class to be used in boolean context:
            if PathChecker("/etc/passwd"):
                print("Dangerous!")

        Returns:
            True if the path is dangerous, False otherwise.
        """
        return self._is_system_path or self._is_user_path

    @property
    def is_system_path(self) -> bool:
        """
        Check if the path is within a platform-specific system directory.

        This checks against OS-specific dangerous paths like /etc, /bin on
        Linux/Unix, C:\\Windows on Windows, or /System on macOS.

        Returns:
            True if the path is within a platform system directory, False otherwise.
        """
        return self._is_system_path

    @property
    def is_sensitive_path(self) -> bool:
        """
        Check if the path matches a user-defined sensitive location.

        This checks against paths added by the user via add_user_path().

        Returns:
            True if the path matches a user-defined sensitive path, False otherwise.
        """
        return self._is_user_path

    @property
    def path(self) -> Union[str, Path]:
        """
        Get the original path that was checked.

        Returns:
            The original path supplied to the constructor.
        """
        return self._path

    def __repr__(self) -> str:
        """
        Return a string representation of the PathChecker.

        Returns:
            String representation showing path and danger status.
        """
        is_dangerous = self._is_system_path or self._is_user_path
        status = "dangerous" if is_dangerous else "safe"
        return f"PathChecker('{self._path}', {status})"


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
