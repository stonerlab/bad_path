"""Windows-specific path checker implementation.

This module provides the WindowsPathChecker class for validating paths on Windows systems.
"""

from pathlib import Path

from ...checker import BasePathChecker, get_user_paths


class WindowsPathChecker(BasePathChecker):
    """Windows-specific PathChecker implementation.

    Handles Windows-specific path validation including drive letters, reserved names,
    and Windows-specific invalid characters.
    """

    def _load_invalid_chars(self) -> None:
        """Load Windows-specific invalid characters and reserved names."""
        from .paths import (  # pylint: disable=import-outside-toplevel
            invalid_chars,
            reserved_names,
        )

        self._invalid_chars = invalid_chars
        self._reserved_names = reserved_names

    def _load_and_check_paths(self) -> None:
        """Load system and user paths, then check the current path against them."""
        from .paths import (  # pylint: disable=import-outside-toplevel
            system_paths,
        )

        self._system_paths = system_paths
        self._user_paths = get_user_paths()

        # Check both types
        self._is_system_path = self._check_against_paths(self._system_paths)
        self._is_user_path = self._check_against_paths(self._user_paths)

    def _check_cwd_traversal(self, path_obj: Path | None = None) -> bool:
        """Check if a path traverses outside the current working directory.

        Windows-specific implementation with case-insensitive comparison.

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
            # Use case-insensitive string comparison for Windows
            if str(path_obj).lower() == str(cwd).lower():
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
            path_str = str(self._path_obj)

        # Check for invalid characters
        for char in self._invalid_chars:
            if char in path_str:
                # Special handling for colon on Windows (valid in drive letters like C:)
                if char == ":":
                    # Check if colon is part of a drive letter (e.g., C:, D:)
                    # Valid pattern: single letter followed by colon at start of path
                    if (
                        len(path_str) >= 2
                        and path_str[1] == ":"
                        and path_str[0].isalpha()
                    ):
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
