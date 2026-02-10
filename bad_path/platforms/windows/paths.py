"""Windows dangerous and sensitive paths.

This module defines system paths, invalid characters, and reserved file names specific
to Windows. It includes Windows system directories, file naming restrictions, and
reserved device names that require special handling.
"""

import os

system_paths = [
    "C:\\Windows",
    "C:\\Windows\\System32",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    os.environ.get("WINDIR", "C:\\Windows"),
    os.environ.get("SYSTEMROOT", "C:\\Windows"),
]

# Invalid characters in Windows file names
# Note: Windows has strict restrictions on characters that can be used in file names.
# These characters are forbidden: < > : " / \ | ? *
# Note: / and \ are path separators but are invalid within filename components
# Additionally, control characters (0-31) and DEL (127) are invalid.
invalid_chars = [
    "<",  # Less than
    ">",  # Greater than
    ":",  # Colon (except for drive letters like C:)
    '"',  # Double quote
    "|",  # Pipe
    "?",  # Question mark
    "*",  # Asterisk
] + [
    chr(i) for i in range(32)
]  # Control characters 0-31

# Note: Forward slash (/) and backslash (\) are path separators in Windows.
# They are technically invalid within individual filename components, but we don't
# check them here as they're commonly used in full paths. The Path library will
# handle them appropriately as separators.

# Reserved file names in Windows (case-insensitive)
# These names cannot be used as file names, even with extensions
reserved_names = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
]
