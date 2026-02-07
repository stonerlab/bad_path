"""
Windows dangerous/sensitive paths.
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
