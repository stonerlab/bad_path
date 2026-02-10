"""POSIX (Linux and Unix)-specific path checker implementation.

This module provides the PosixPathChecker class for validating paths on POSIX-compliant systems.
"""

from ...checker import BasePathChecker, get_user_paths


class PosixPathChecker(BasePathChecker):
    """POSIX (Linux and Unix)-specific PathChecker implementation.

    Handles POSIX-compliant path validation for Linux and other Unix-like systems.
    """

    def _load_invalid_chars(self) -> None:
        """Load POSIX-specific invalid characters."""
        from .paths import (  # pylint: disable=import-outside-toplevel
            invalid_chars,
        )

        self._invalid_chars = invalid_chars
        self._reserved_names = []

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
