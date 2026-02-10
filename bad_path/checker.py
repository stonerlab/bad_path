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
            from .platforms.windows.paths import (
                system_paths,
            )  # pylint: disable=import-outside-toplevel
        case "Darwin":
            from .platforms.darwin.paths import (
                system_paths,
            )  # pylint: disable=import-outside-toplevel
        case _:  # Linux and other Unix-like systems
            from .platforms.posix.paths import (
                system_paths,
            )  # pylint: disable=import-outside-toplevel

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
        mode (str | None):
            Validation mode for common use cases: "read", "write", or None.
            Use "read" when validating paths for read operations (allows
            reading from system directories and user-defined paths). Use
            "write" when validating paths for write operations (strict
            validation to prevent overwriting critical files). Use None
            to manually control validation via individual flags. When
            mode is specified, it overrides the system_ok, user_paths_ok,
            and not_writeable flags. Defaults to None.
        system_ok (bool):
            If True, allow paths within system directories. Defaults to False.
        user_paths_ok (bool):
            If True, allow paths within user-defined sensitive locations.
            Defaults to False.
        not_writeable (bool):
            If True, allow paths that are readable but not writeable.
            Defaults to False.
        cwd_only (bool):
            If True, only allow paths within the current working directory
            to prevent path traversal attacks. Paths that resolve outside
            the CWD (e.g., '../../../etc/passwd') are considered dangerous.
            Defaults to False.

    Raises:
        DangerousPathError:
            If raise_error is True and the path is dangerous.
        ValueError:
            If mode is not None, "read", or "write".

    Notes:
        When mode is specified, individual flag parameters (system_ok,
        user_paths_ok, not_writeable) are ignored in favour of the mode's
        preset values.

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
        >>> # Strict validation (default) - dangerous for system paths
        >>> checker = PathChecker("/etc/passwd")  # doctest: +SKIP
        >>> if not checker:
        ...     print(f"Dangerous path! System path: {checker.is_system_path}")
        Dangerous path! System path: True
        >>> # Read mode - allow reading system configuration files
        >>> checker = PathChecker("/etc/passwd", mode="read")  # doctest: +SKIP
        >>> if checker:
        ...     print("Safe for reading!")
        Safe for reading!
        >>> # Write mode - strict validation to prevent overwriting
        >>> checker = PathChecker("/tmp/myfile.txt", mode="write")  # doctest: +SKIP
        >>> if checker:
        ...     print("Safe for writing!")
        Safe for writing!
    """

    def __init__(
        self,
        path: str | Path,
        raise_error: bool = False,
        mode: str | None = None,
        system_ok: bool = False,
        user_paths_ok: bool = False,
        not_writeable: bool = False,
        cwd_only: bool = False,
    ):
        """Initialise the PathChecker with a path to check."""
        self._path = path
        self._raise_error = raise_error
        self._mode = mode

        # Handle mode parameter
        match mode:
            case "read":
                # For reading: allow system paths, user paths, and non-writable paths
                self._system_ok = True
                self._user_paths_ok = True
                self._not_writeable = True
            case "write":
                # For writing: strict validation (default flags)
                self._system_ok = False
                self._user_paths_ok = False
                self._not_writeable = False
            case None:
                # No mode specified - use individual flags
                self._system_ok = system_ok
                self._user_paths_ok = user_paths_ok
                self._not_writeable = not_writeable
            case _:
                raise ValueError(
                    f"Invalid mode '{mode}'. Must be None, 'read', or 'write'."
                )

        # Handle cwd_only flag (independent of mode)
        self._cwd_only = cwd_only

        # Load platform-specific invalid characters first (before resolve)
        self._load_invalid_chars()

        # Try to resolve the path, but handle errors gracefully
        try:
            self._path_obj = Path(path).resolve()
        except (ValueError, OSError):
            # If path contains invalid characters that prevent resolution,
            # create a non-resolved Path object
            self._path_obj = Path(path)

        # Check for invalid characters before attempting to resolve the path
        # (some invalid chars like null byte will cause resolve to fail)
        self._has_invalid_chars = self._check_invalid_chars()

        # Load paths and check the initial path
        self._load_and_check_paths()

        # Raise error if requested and path is dangerous
        is_dangerous = self._is_dangerous()
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

    def _is_dangerous(self) -> bool:
        """Check if the path is dangerous based on current settings.

        Returns:
            (bool):
                True if the path is dangerous considering all flags, False otherwise.
        """
        # Check system paths (unless allowed)
        if self._is_system_path and not self._system_ok:
            return True

        # Check user paths (unless allowed)
        if self._is_user_path and not self._user_paths_ok:
            return True

        # Check invalid characters (always dangerous)
        if self._has_invalid_chars:
            return True

        # Check writeability
        if not self._not_writeable:
            # If not_writeable is False, non-writable existing paths are considered dangerous
            if self._path_obj.exists() and not self.is_writable:
                return True

        # Check CWD restriction
        if self._cwd_only and self._check_cwd_traversal():
            return True

        return False

    def _check_cwd_traversal(self, path_obj: Path | None = None) -> bool:
        """Check if a path traverses outside the current working directory.

        Keyword Parameters:
            path_obj (Path | None):
                Optional Path object to check. If not provided, uses self._path_obj.
                Defaults to None.

        Returns:
            (bool):
                True if the path is outside CWD (dangerous), False otherwise.
        """
        if path_obj is None:
            path_obj = self._path_obj

        try:
            cwd = Path.cwd().resolve()

            # Check if path equals CWD (handles "." case)
            # Use case-sensitive comparison for Linux/macOS
            if path_obj == cwd:
                return False  # Path is CWD itself (safe)

            # Also try samefile() if paths exist (handles symlinks, etc.)
            try:
                if path_obj.exists() and cwd.exists() and path_obj.samefile(cwd):
                    return False  # Same file/directory (safe)
            except (OSError, ValueError, AttributeError):
                # samefile() not available or failed, continue with relative_to
                pass

            # Try to express path_obj relative to cwd
            # If this succeeds, the path is within CWD
            path_obj.relative_to(cwd)
            return False  # Path is within CWD (safe)
        except ValueError:
            # relative_to raised ValueError, so path is outside CWD
            return True  # Path is outside CWD (dangerous)
        except (OSError, RuntimeError):
            # If other resolution fails, treat as dangerous
            return True

    def _check_against_paths(
        self, paths: list[str], path_obj: Path | None = None
    ) -> bool:
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

    def __call__(
        self, path: str | Path | None = None, raise_error: bool = False
    ) -> bool:
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

            # Evaluate danger based on settings
            is_dangerous = has_invalid  # Invalid chars are always dangerous
            if is_sys_path and not self._system_ok:
                is_dangerous = True
            if is_usr_path and not self._user_paths_ok:
                is_dangerous = True

            # Check writeability
            if not self._not_writeable:
                if path_obj.exists() and not os.access(path_obj, os.W_OK):
                    is_dangerous = True

            # Check CWD restriction
            if self._cwd_only and self._check_cwd_traversal(path_obj):
                is_dangerous = True

            if is_dangerous and raise_error:
                raise DangerousPathError(
                    f"Path '{path}' points to a dangerous location"
                )

            return is_dangerous
        else:
            # Reload paths and check the original path
            self._load_and_check_paths()
            is_dangerous = self._is_dangerous()

            if is_dangerous and raise_error:
                raise DangerousPathError(
                    f"Path '{self._path}' points to a dangerous location"
                )

            return is_dangerous

    def __bool__(self) -> bool:
        """Return True if the path is safe (not dangerous), False otherwise.

        A path is considered dangerous if it matches either a platform-specific
        system path, a user-defined sensitive path, or contains invalid characters.
        The danger assessment can be modified by the system_ok, user_paths_ok, and
        not_writeable flags.

        This allows the class to be used in boolean context.

        Returns:
            (bool):
                True if the path is safe (not dangerous), False otherwise.

        Examples:
            >>> if PathChecker("/tmp/myfile.txt"):  # doctest: +SKIP
            ...     print("Safe path!")
            Safe path!
        """
        return not self._is_dangerous()

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
        is_safe = not self._is_dangerous()
        status = "safe" if is_safe else "dangerous"
        return f"PathChecker('{self._path}', {status})"


# ============================================================================
# Platform Classes
# ============================================================================

# Platform-specific checker implementations have been moved to:
# - bad_path.platforms.checkers.windows (WindowsPathChecker)
# - bad_path.platforms.checkers.darwin (DarwinPathChecker)
# - bad_path.platforms.checkers.posix (PosixPathChecker)


# ============================================================================
# PathChecker Class
# ============================================================================


# Factory function to create the appropriate PathChecker based on platform
def _create_path_checker(
    path: str | Path,
    raise_error: bool = False,
    mode: str | None = None,
    system_ok: bool = False,
    user_paths_ok: bool = False,
    not_writeable: bool = False,
    cwd_only: bool = False,
) -> BasePathChecker:
    """Create a platform-specific PathChecker instance.

    Args:
        path (str | Path):
            The file path to check.

    Keyword Parameters:
        raise_error (bool):
            If True, raise DangerousPathError if the path is dangerous.
            Defaults to False.
        mode (str | None):
            Validation mode: "read", "write", or None. Defaults to None.
        system_ok (bool):
            If True, allow paths within system directories. Defaults to False.
        user_paths_ok (bool):
            If True, allow paths within user-defined sensitive locations.
            Defaults to False.
        not_writeable (bool):
            If True, allow paths that are readable but not writeable.
            Defaults to False.
        cwd_only (bool):
            If True, only allow paths within the current working directory
            to prevent path traversal attacks. Paths that resolve outside
            the CWD (e.g., '../../../etc/passwd') are considered dangerous.
            Defaults to False.

    Returns:
        (BasePathChecker):
            A platform-specific PathChecker instance.

    Raises:
        DangerousPathError:
            If raise_error is True and the path is dangerous.
        ValueError:
            If mode is not None, "read", or "write".
    """
    match platform.system():
        case "Windows":
            from .platforms.windows.checker import (  # pylint: disable=import-outside-toplevel
                WindowsPathChecker,
            )

            return WindowsPathChecker(
                path,
                raise_error,
                mode,
                system_ok,
                user_paths_ok,
                not_writeable,
                cwd_only,
            )
        case "Darwin":
            from .platforms.darwin.checker import (  # pylint: disable=import-outside-toplevel
                DarwinPathChecker,
            )

            return DarwinPathChecker(
                path,
                raise_error,
                mode,
                system_ok,
                user_paths_ok,
                not_writeable,
                cwd_only,
            )
        case _:  # Linux and other Unix-like systems
            from .platforms.posix.checker import (  # pylint: disable=import-outside-toplevel
                PosixPathChecker,
            )

            return PosixPathChecker(
                path,
                raise_error,
                mode,
                system_ok,
                user_paths_ok,
                not_writeable,
                cwd_only,
            )


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
        mode (str | None):
            Validation mode for common use cases: "read", "write", or None.
            Use "read" when validating paths for read operations (allows
            reading from system directories and user-defined paths). Use
            "write" when validating paths for write operations (strict
            validation to prevent overwriting critical files). Use None
            to manually control validation via individual flags. When
            mode is specified, it overrides the system_ok, user_paths_ok,
            and not_writeable flags. Defaults to None.
        system_ok (bool):
            If True, allow paths within system directories. Defaults to False.
        user_paths_ok (bool):
            If True, allow paths within user-defined sensitive locations.
            Defaults to False.
        not_writeable (bool):
            If True, allow paths that are readable but not writeable.
            Defaults to False.
        cwd_only (bool):
            If True, only allow paths within the current working directory
            to prevent path traversal attacks. Paths that resolve outside
            the CWD (e.g., '../../../etc/passwd') are considered dangerous.
            Defaults to False.

    Raises:
        DangerousPathError:
            If raise_error is True and the path is dangerous.
        ValueError:
            If mode is not None, "read", or "write".

    Notes:
        When mode is specified, individual flag parameters (system_ok,
        user_paths_ok, not_writeable) are ignored in favour of the mode's
        preset values.

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
        >>> # Default strict validation - dangerous for system paths
        >>> checker = PathChecker("/etc/passwd")  # doctest: +SKIP
        >>> if not checker:
        ...     print(f"Dangerous path! System path: {checker.is_system_path}")
        Dangerous path! System path: True
        >>> # Read mode - convenient for validating read operations
        >>> checker = PathChecker("/etc/passwd", mode="read")  # doctest: +SKIP
        >>> if checker:
        ...     print("Safe to read from this path!")
        Safe to read from this path!
        >>> # Write mode - strict validation to prevent overwriting critical files
        >>> checker = PathChecker("/tmp/myfile.txt", mode="write")  # doctest: +SKIP
        >>> if checker:
        ...     print("Safe to write to this path!")
        Safe to write to this path!
        >>> # Manual flag control (backward compatible)
        >>> checker = PathChecker(
        ...     "/etc/passwd", system_ok=True, not_writeable=True
        ... )  # doctest: +SKIP
        >>> if checker:
        ...     print("Safe with custom flags!")
        Safe with custom flags!
        >>> # Path traversal protection
        >>> checker = PathChecker("../../../etc/passwd", cwd_only=True)  # doctest: +SKIP
        >>> if not checker:
        ...     print("Dangerous: path traversal attempt detected!")
        Dangerous: path traversal attempt detected!
    """

    def __new__(
        cls,
        path: str | Path,
        raise_error: bool = False,
        mode: str | None = None,
        system_ok: bool = False,
        user_paths_ok: bool = False,
        not_writeable: bool = False,
        cwd_only: bool = False,
    ) -> BasePathChecker:
        """Create a platform-specific PathChecker instance."""
        return _create_path_checker(
            path, raise_error, mode, system_ok, user_paths_ok, not_writeable, cwd_only
        )
