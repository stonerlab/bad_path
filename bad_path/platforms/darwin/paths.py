"""Darwin (macOS) dangerous and sensitive paths.

This module defines system paths and invalid characters specific to macOS (Darwin).
It includes both POSIX-standard paths and macOS-specific directories like /System
and /Library that should be protected.
"""

# Common sensitive paths for POSIX-based systems
common_paths = [
    "/etc",
    "/bin",
    "/sbin",
    "/boot",
    "/sys",
    "/proc",
    "/dev",
]

system_paths = common_paths + [
    "/System",
    "/Library",
    "/private/etc",  # System configuration (don't use /private to allow /private/tmp)
    # /private/var subdirectories (don't use /private/var to allow
    # /private/var/folders for temp files)
    "/private/var/root",  # Root user's home directory
    "/private/var/db",  # System databases
    "/private/var/log",  # System logs
    "/private/var/audit",  # Audit logs
    "/private/var/vm",  # Virtual memory swap
    "/private/var/backups",  # System backups
    # /var subdirectories (don't use /var to allow /var/folders for temp files)
    "/var/root",  # Root user's home directory
    "/var/db",  # System databases
    "/var/log",  # System logs
    "/var/audit",  # Audit logs
    "/var/vm",  # Virtual memory swap
    "/var/backups",  # System backups
    "/usr",
    "/Applications",
]

# Invalid characters in macOS file names
# Note: macOS is POSIX-based but also has restrictions from legacy Mac OS.
# The null byte (\0) and colon (:) are forbidden in file names.
invalid_chars = [
    "\0",  # Null byte - strictly forbidden in POSIX
    ":",  # Colon - problematic in macOS (was path separator in legacy Mac OS)
]
