"""
Darwin (macOS) dangerous/sensitive paths.
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
    "/private/var",  # System variables, logs, and caches (excludes /private/tmp which is safe)
    "/var",
    "/usr",
    "/Applications",
]

# Invalid characters in macOS file names
# Note: macOS is POSIX-based but also has restrictions from legacy Mac OS.
# The null byte (\0) and colon (:) are forbidden in file names.
invalid_chars = [
    "\0",  # Null byte - strictly forbidden in POSIX
    ":",   # Colon - problematic in macOS (was path separator in legacy Mac OS)
]
