"""
POSIX (Linux and Unix-like systems) dangerous/sensitive paths.
"""

# Common sensitive paths across all POSIX platforms
system_paths = [
    "/etc",
    "/bin",
    "/sbin",
    "/boot",
    "/sys",
    "/proc",
    "/dev",
    "/root",
    "/lib",
    "/lib64",
    "/usr",
    "/var",
    "/opt",
]

# Invalid characters in POSIX file names
# Note: The null byte (\0) is the only character that is strictly forbidden in POSIX file names.
# The forward slash (/) is allowed in full paths but not within individual file name components.
invalid_chars = [
    "\0",  # Null byte - strictly forbidden
]
