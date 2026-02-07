"""Core functionality for checking dangerous file paths.

This module provides the main PathChecker class and supporting functions for identifying
dangerous or sensitive file paths. It includes platform-specific implementations for
Windows, macOS (Darwin), and POSIX systems, along with support for user-defined paths
and validation of platform-specific invalid characters.
"""

import os
import platform
from abc import ABC, abstractmethod
from pathlib import Path


class DangerousPathError(PermissionError):
    """Exception raised when a dangerous path is detected."""

    pass


# Module-level list of user-defined dangerous paths
_user_defined_paths: list[str] = []


# ============================================================================
# Functions for User Paths
# ============================================================================


def add_user_path(path: str | Path) -> None:
    """Add a user-defined path to the list of dangerous paths.

    Args:
        path (str | Path):
            The path to add as a dangerous location.

    Examples:
        >>> add_user_path("/home/user/sensitive")
        >>> add_user_path(Path("/var/app/data"))
    """
    path_str = str(path)
    if path_str not in _user_defined_paths:
        _user_defined_paths.append(path_str)


def remove_user_path(path: str | Path) -> None:
    """Remove a user-defined path from the list of dangerous paths.

    Args:
        path (str | Path):
            The path to remove from the dangerous locations list.

    Raises:
        ValueError:
            If the path is not in the user-defined paths list.

    Examples:
        >>> add_user_path("/home/user/sensitive")
        >>> remove_user_path("/home/user/sensitive")
    """
    path_str = str(path)
    if path_str in _user_defined_paths:
        _user_defined_paths.remove(path_str)
    else:
        raise ValueError(f"Path '{path_str}' is not in the user-defined paths list")


def clear_user_paths() -> None:
    """Clear all user-defined dangerous paths.

    Examples:
        >>> add_user_path("/home/user/sensitive")
        >>> clear_user_paths()
        >>> get_user_paths()
        []
    """
    _user_defined_paths.clear()


def get_user_paths() -> list[str]:
    """Get the list of user-defined dangerous paths.

    Returns:
        (list[str]):
            A copy of the list of user-defined dangerous path patterns.

    Examples:
        >>> add_user_path("/home/user/sensitive")
        >>> paths = get_user_paths()
        >>> "/home/user/sensitive" in paths
        True
    """
    return _user_defined_paths.copy()


def get_dangerous_paths() -> list[str]:
    """Get a list of dangerous and sensitive paths based on the current OS.

    Includes both platform-specific system paths and user-defined paths.

    Returns:
        (list[str]):
            List of dangerous path patterns for the current operating system,
            combined with user-defined paths (duplicates removed).

    Examples:
        >>> paths = get_dangerous_paths()
        >>> any("/etc" in p or "etc" in p for p in paths)  # POSIX/Darwin
        True
        >>> add_user_path("/custom/path")
        >>> "/custom/path" in get_dangerous_paths()
        True
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


# ============================================================================
# Function Interface for Checking Paths
# ============================================================================


def is_system_path(path: str | Path) -> bool:
    """Check if a path is within a system directory.

    Args:
        path (str | Path):
            The file path to check.

    Returns:
        (bool):
            True if the path is within a system directory, False otherwise.

    Notes:
        Despite the name, this function checks BOTH system paths and user-defined
        paths for backward compatibility (originally used get_dangerous_paths() which
        returns both). Use PathChecker class for fine-grained control.

    Examples:
        >>> is_system_path("/etc/passwd")  # On POSIX systems
        True
        >>> is_system_path("/home/user/file.txt")
        False
    """
    checker = PathChecker(path)
    return checker.is_system_path or checker.is_sensitive_path


def is_sensitive_path(path: str | Path) -> bool:
    """Check if a path points to a sensitive location.

    This is an alias for is_system_path() for backwards compatibility
    and semantic clarity.

    Args:
        path (str | Path):
            The file path to check.

    Returns:
        (bool):
            True if the path is sensitive, False otherwise.

    Notes:
        This function checks BOTH system and user-defined paths (same as is_system_path)
        for backward compatibility. Use PathChecker class for fine-grained control.

    Examples:
        >>> is_sensitive_path("/etc/passwd")  # On POSIX systems
        True
        >>> add_user_path("/custom/sensitive")
        >>> is_sensitive_path("/custom/sensitive/file.txt")
        True
    """
    checker = PathChecker(path)
    return checker.is_system_path or checker.is_sensitive_path


def is_dangerous_path(path: str | Path, raise_error: bool = False) -> bool:
    """Check if a path is dangerous (points to a system-sensitive location).

    Args:
        path (str | Path):
            The file path to check.

    Keyword Parameters:
        raise_error (bool):
            If True, raise DangerousPathError instead of returning True.
            Defaults to False.

    Returns:
        (bool):
            True if the path is dangerous, False otherwise.

    Raises:
        DangerousPathError:
            If raise_error is True and the path is dangerous.

    Examples:
        >>> is_dangerous_path("/home/user/file.txt")
        False
        >>> is_dangerous_path("/etc/passwd")  # On POSIX systems
        True
        >>> is_dangerous_path("/etc/passwd", raise_error=True)  # doctest: +SKIP
        Traceback (most recent call last):
            ...
        DangerousPathError: Path '/etc/passwd' points to a dangerous system location
    """
    try:
        checker = PathChecker(path, raise_error=raise_error)
        # Invert PathChecker's boolean (True when safe)
        # to match function name (returns True when dangerous)
        return not bool(checker)
    except DangerousPathError:
        # PathChecker raises with message "dangerous location"
        # But for backward compatibility, we need "dangerous system location"
        raise DangerousPathError(f"Path '{path}' points to a dangerous system location")


# ============================================================================
# Base Class
# ============================================================================


class BasePathChecker(ABC):
    """Base class for platform-specific path checkers.

    A class to check if a path is dangerous and provide details about why.
    The class can be used in boolean context where it evaluates to True
    if the path is safe (not dangerous), False otherwise.

    The class distinguishes between platform-specific system paths and
    user-defined sensitive paths through separate properties.

    Args:
        path (str | Path):
            The file path to check.

    Keyword Parameters:
        raise_error (bool):
            If True, raise DangerousPathError if the path is dangerous.
            Defaults to False.

    Raises:
        DangerousPathError:
            If raise_error is True and the path is dangerous.

    Attributes:
        is_system_path (bool):
            True if the path is within a platform system directory.
        is_sensitive_path (bool):
            True if the path matches a user-defined sensitive location.
        has_invalid_chars (bool):
            True if the path contains invalid characters for the platform.
        is_readable (bool):
            True if the path exists and is readable.
        is_writable (bool):
            True if the path exists and is writable.
        is_creatable (bool):
            True if the path doesn't exist and can be created.
        path (str | Path):
            The original path that was checked.

    Examples:
        >>> checker = PathChecker("/etc/passwd")  # doctest: +SKIP
        >>> if not checker:
        ...     print(f"Dangerous path! System path: {checker.is_system_path}")
        ...     print(f"User-defined: {checker.is_sensitive_path}")
        Dangerous path! System path: True
        User-defined: False
    """

    def __init__(self, path: str | Path, raise_error: bool = False):
        """Initialise the PathChecker with a path to check."""
        self._path = path
        self._raise_error = raise_error

        # Load platform-specific invalid characters first (before resolve)
        self._load_invalid_chars()

        # Check for invalid characters before attempting to resolve the path
        # (some invalid chars like null byte will cause resolve to fail)
        self._has_invalid_chars = self._check_invalid_chars()

        # Try to resolve the path, but handle errors gracefully
        try:
            self._path_obj = Path(path).resolve()
        except (ValueError, OSError):
            # If path contains invalid characters that prevent resolution,
            # create a non-resolved Path object
            self._path_obj = Path(path)

        # Load paths and check the initial path
        self._load_and_check_paths()

        # Raise error if requested and path is dangerous
        is_dangerous = (
            self._is_system_path or self._is_user_path or self._has_invalid_chars
        )
        if self._raise_error and is_dangerous:
            raise DangerousPathError(f"Path '{path}' points to a dangerous location")

    @abstractmethod
    def _load_invalid_chars(self) -> None:
        """Load platform-specific invalid characters and reserved names."""
        pass

    @abstractmethod
    def _load_and_check_paths(self) -> None:
        """Load system and user paths, then check the current path against them."""
        pass

    def _check_against_paths(self, paths: list[str], path_obj: Path | None = None) -> bool:
        """Check if a path matches any in the given list.

        Args:
            paths (list[str]):
                List of paths to check against.

        Keyword Parameters:
            path_obj (Path | None):
                Optional Path object to check. If not provided, uses self._path_obj.
                Defaults to None.

        Returns:
            (bool):
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

    def _check_invalid_chars(self, path_str: str | None = None) -> bool:
        """Check if a path contains invalid characters for the platform.

        This base implementation checks for simple invalid character presence.
        Platform-specific subclasses (like WindowsPathChecker) may override this
        to add additional validation logic (e.g., drive letters, reserved names).

        Keyword Parameters:
            path_str (str | None):
                Optional path string to check. If not provided, uses self._path.
                Defaults to None.

        Returns:
            (bool):
                True if the path contains invalid characters, False otherwise.
        """
        if path_str is None:
            path_str = str(self._path)

        # Check for invalid characters
        for char in self._invalid_chars:
            if char in path_str:
                return True

        return False

    def __call__(self, path: str | Path | None = None, raise_error: bool = False) -> bool:
        """Check a path for danger, with optional path reload.

        Note: Unlike the boolean context (which returns True for safe paths),
        this method returns True if the path IS dangerous.

        Keyword Parameters:
            path (str | Path | None):
                Optional path to check. If provided, checks the new path against
                existing system and user paths (without reloading). If not provided,
                rechecks the original path against reloaded system and user paths.
                Defaults to None.
            raise_error (bool):
                If True, raise DangerousPathError if the path is dangerous.
                Defaults to False.

        Returns:
            (bool):
                True if the path is dangerous, False if safe.

        Raises:
            DangerousPathError:
                If raise_error is True and the path is dangerous.

        Examples:
            >>> checker = PathChecker("/home/user/file.txt")
            >>> checker("/etc/passwd")  # Check different path  # doctest: +SKIP
            True
            >>> checker()  # Recheck original with reloaded paths
            False
            >>> checker("/etc/passwd", raise_error=True)  # doctest: +SKIP
            Traceback (most recent call last):
                ...
            DangerousPathError: Path '/etc/passwd' points to a dangerous location
        """
        if path is not None:
            # Check for invalid characters first
            has_invalid = self._check_invalid_chars(str(path))

            # Try to resolve the path
            try:
                path_obj = Path(path).resolve()
            except (ValueError, OSError):
                # If path contains invalid characters that prevent resolution,
                # create a non-resolved Path object
                path_obj = Path(path)

            # Check against existing paths
            is_sys_path = self._check_against_paths(self._system_paths, path_obj)
            is_usr_path = self._check_against_paths(self._user_paths, path_obj)

            is_dangerous = is_sys_path or is_usr_path or has_invalid

            if is_dangerous and raise_error:
                raise DangerousPathError(f"Path '{path}' points to a dangerous location")

            return is_dangerous
        else:
            # Reload paths and check the original path
            self._load_and_check_paths()
            is_dangerous = self._is_system_path or self._is_user_path or self._has_invalid_chars

            if is_dangerous and raise_error:
                raise DangerousPathError(f"Path '{self._path}' points to a dangerous location")

            return is_dangerous

    def __bool__(self) -> bool:
        """Return True if the path is safe (not dangerous), False otherwise.

        A path is considered dangerous if it matches either a platform-specific
        system path, a user-defined sensitive path, or contains invalid characters.

        This allows the class to be used in boolean context.

        Returns:
            (bool):
                True if the path is safe (not dangerous), False otherwise.

        Examples:
            >>> if PathChecker("/tmp/myfile.txt"):  # doctest: +SKIP
            ...     print("Safe path!")
            Safe path!
        """
        return not (self._is_system_path or self._is_user_path or self._has_invalid_chars)

    @property
    def is_system_path(self) -> bool:
        """Check if the path is within a platform-specific system directory.

        This checks against OS-specific dangerous paths like /etc, /bin on
        Linux/Unix, C:\\Windows on Windows, or /System on macOS.

        Returns:
            (bool):
                True if the path is within a platform system directory, False otherwise.
        """
        return self._is_system_path

    @property
    def is_sensitive_path(self) -> bool:
        """Check if the path matches a user-defined sensitive location.

        This checks against paths added by the user via add_user_path().

        Returns:
            (bool):
                True if the path matches a user-defined sensitive path, False otherwise.
        """
        return self._is_user_path

    @property
    def path(self) -> str | Path:
        """Get the original path that was checked.

        Returns:
            (str | Path):
                The original path supplied to the constructor.
        """
        return self._path

    @property
    def has_invalid_chars(self) -> bool:
        """Check if the path contains invalid characters for the current platform.

        This checks for platform-specific invalid characters (e.g., <, >, :, ", etc. on Windows,
        null byte on POSIX systems, colon on macOS). Also checks for reserved names on Windows.

        Returns:
            (bool):
                True if the path contains invalid characters, False otherwise.
        """
        return self._has_invalid_chars

    @property
    def is_readable(self) -> bool:
        """Check if the path is accessible for read operations.

        For existing files and directories, checks read permission.
        For non-existing paths, returns False.

        Returns:
            (bool):
                True if the path exists and is readable, False otherwise.
        """
        try:
            # Check if path exists and is readable
            return os.access(self._path_obj, os.R_OK)
        except (OSError, ValueError):
            return False

    @property
    def is_writable(self) -> bool:
        """Check if the path is accessible for write operations.

        For existing files and directories, checks write permission.
        For non-existing paths, returns False (use is_creatable instead).

        Returns:
            (bool):
                True if the path exists and is writable, False otherwise.
        """
        try:
            # Check if path exists and is writable
            return os.access(self._path_obj, os.W_OK)
        except (OSError, ValueError):
            return False

    @property
    def is_creatable(self) -> bool:
        """Check if the path can be created (for non-existing paths).

        For non-existing paths, checks if the parent directory exists and is writable.
        For existing paths, returns False (use is_writable instead).

        Returns:
            (bool):
                True if the path doesn't exist and can be created, False otherwise.
        """
        try:
            # If path exists, it's not creatable (it already exists)
            if self._path_obj.exists():
                return False

            # Check if parent directory exists and is writable
            parent = self._path_obj.parent
            return parent.exists() and os.access(parent, os.W_OK | os.X_OK)
        except (OSError, ValueError):
            return False

    def __repr__(self) -> str:
        """Return a string representation of the PathChecker.

        Returns:
            (str):
                String representation showing path and safety status.
        """
        is_safe = not (self._is_system_path or self._is_user_path or self._has_invalid_chars)
        status = "safe" if is_safe else "dangerous"
        return f"PathChecker('{self._path}', {status})"


# ============================================================================
# Platform Classes
# ============================================================================


class WindowsPathChecker(BasePathChecker):
    """Windows-specific PathChecker implementation.

    Handles Windows-specific path validation including drive letters, reserved names,
    and Windows-specific invalid characters.
    """

    def _load_invalid_chars(self) -> None:
        """Load Windows-specific invalid characters and reserved names."""
        from .platforms.windows import invalid_chars, reserved_names
        self._invalid_chars = invalid_chars
        self._reserved_names = reserved_names

    def _load_and_check_paths(self) -> None:
        """Load system and user paths, then check the current path against them."""
        from .platforms.windows import system_paths
        self._system_paths = system_paths
        self._user_paths = get_user_paths()

        # Check both types
        self._is_system_path = self._check_against_paths(self._system_paths)
        self._is_user_path = self._check_against_paths(self._user_paths)

    def _check_invalid_chars(self, path_str: str | None = None) -> bool:
        """Check for Windows-specific invalid characters.

        Includes special handling for:
        - Drive letter colons (C:, D:, etc.)
        - Reserved names (CON, PRN, AUX, etc.)
        - Paths ending with space or period

        Keyword Parameters:
            path_str (str | None):
                Optional path string to check. If not provided, uses self._path.
                Defaults to None.

        Returns:
            (bool):
                True if the path contains invalid characters, False otherwise.
        """
        if path_str is None:
            path_str = str(self._path)

        # Check for invalid characters
        for char in self._invalid_chars:
            if char in path_str:
                # Special handling for colon on Windows (valid in drive letters like C:)
                if char == ":":
                    # Check if colon is part of a drive letter (e.g., C:, D:)
                    # Valid pattern: single letter followed by colon at start of path
                    if len(path_str) >= 2 and path_str[1] == ":" and path_str[0].isalpha():
                        # This is a valid drive letter if it's the only colon
                        if path_str.count(":") == 1:
                            continue  # This is a valid drive letter colon
                return True

        # Check for reserved names (case-insensitive)
        # Extract the filename from the path using string operations
        # to avoid Path() issues with invalid characters
        # Split by both forward slash and backslash
        path_parts = path_str.replace("\\", "/").split("/")
        if path_parts:
            filename = path_parts[-1]

            # Extract name without extension
            if "." in filename:
                name_without_ext = filename.rsplit(".", 1)[0].upper()
            else:
                name_without_ext = filename.upper()

            # Check if the name (without extension) is a reserved name
            if name_without_ext in self._reserved_names:
                return True

            # Check if filename ends with space or period (invalid in Windows)
            if filename and (filename.endswith(" ") or filename.endswith(".")):
                return True

        return False


class DarwinPathChecker(BasePathChecker):
    """Darwin (macOS)-specific PathChecker implementation.

    Handles macOS-specific path validation including restrictions on colons
    in file names and macOS system directories.
    """

    def _load_invalid_chars(self) -> None:
        """Load Darwin-specific invalid characters."""
        from .platforms.darwin import invalid_chars
        self._invalid_chars = invalid_chars
        self._reserved_names = []

    def _load_and_check_paths(self) -> None:
        """Load system and user paths, then check the current path against them."""
        from .platforms.darwin import system_paths
        self._system_paths = system_paths
        self._user_paths = get_user_paths()

        # Check both types
        self._is_system_path = self._check_against_paths(self._system_paths)
        self._is_user_path = self._check_against_paths(self._user_paths)


class PosixPathChecker(BasePathChecker):
    """POSIX (Linux and Unix)-specific PathChecker implementation.

    Handles POSIX-compliant path validation for Linux and other Unix-like systems.
    """

    def _load_invalid_chars(self) -> None:
        """Load POSIX-specific invalid characters."""
        from .platforms.posix import invalid_chars
        self._invalid_chars = invalid_chars
        self._reserved_names = []

    def _load_and_check_paths(self) -> None:
        """Load system and user paths, then check the current path against them."""
        from .platforms.posix import system_paths
        self._system_paths = system_paths
        self._user_paths = get_user_paths()

        # Check both types
        self._is_system_path = self._check_against_paths(self._system_paths)
        self._is_user_path = self._check_against_paths(self._user_paths)


# ============================================================================
# PathChecker Class
# ============================================================================


# Factory function to create the appropriate PathChecker based on platform
def _create_path_checker(path: str | Path, raise_error: bool = False) -> BasePathChecker:
    """Create a platform-specific PathChecker instance.

    Args:
        path (str | Path):
            The file path to check.

    Keyword Parameters:
        raise_error (bool):
            If True, raise DangerousPathError if the path is dangerous.
            Defaults to False.

    Returns:
        (BasePathChecker):
            A platform-specific PathChecker instance.

    Raises:
        DangerousPathError:
            If raise_error is True and the path is dangerous.
    """
    match platform.system():
        case "Windows":
            return WindowsPathChecker(path, raise_error)
        case "Darwin":
            return DarwinPathChecker(path, raise_error)
        case _:  # Linux and other Unix-like systems
            return PosixPathChecker(path, raise_error)


# PathChecker is the public API - it's a callable class that acts as a factory
class PathChecker:
    """A class to check if a path is dangerous and provide details about why.

    This is a factory that creates platform-specific PathChecker instances
    based on the current operating system.

    The class can be used in boolean context where it evaluates to True
    if the path is safe (not dangerous), False otherwise.

    The class distinguishes between platform-specific system paths and
    user-defined sensitive paths through separate properties.

    Args:
        path (str | Path):
            The file path to check.

    Keyword Parameters:
        raise_error (bool):
            If True, raise DangerousPathError if the path is dangerous.
            Defaults to False.

    Raises:
        DangerousPathError:
            If raise_error is True and the path is dangerous.

    Attributes:
        is_system_path (bool):
            True if the path is within a platform system directory.
        is_sensitive_path (bool):
            True if the path matches a user-defined sensitive location.
        has_invalid_chars (bool):
            True if the path contains invalid characters for the platform.
        is_readable (bool):
            True if the path exists and is readable.
        is_writable (bool):
            True if the path exists and is writable.
        is_creatable (bool):
            True if the path doesn't exist and can be created.
        path (str | Path):
            The original path that was checked.

    Examples:
        >>> checker = PathChecker("/etc/passwd")  # doctest: +SKIP
        >>> if not checker:
        ...     print(f"Dangerous path! System path: {checker.is_system_path}")
        ...     print(f"User-defined: {checker.is_sensitive_path}")
        Dangerous path! System path: True
        User-defined: False
    """

    def __new__(cls, path: str | Path, raise_error: bool = False) -> BasePathChecker:
        """Create a platform-specific PathChecker instance."""
        return _create_path_checker(path, raise_error)
