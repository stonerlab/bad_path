# bad_path

[![Tests](https://github.com/stonerlab/bad_path/actions/workflows/tests.yml/badge.svg)](https://github.com/stonerlab/bad_path/actions/workflows/tests.yml)
[![Coverage Status](https://coveralls.io/repos/github/stonerlab/bad_path/badge.svg?branch=main)](https://coveralls.io/github/stonerlab/bad_path?branch=main)
[![Codacy coverage](https://app.codacy.com/project/badge/Coverage/68df7b8d1d044f17887b7d0df56b4aef)](https://app.codacy.com/gh/stonerlab/bad_path/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)
[![Documentation](https://github.com/stonerlab/bad_path/actions/workflows/docs.yml/badge.svg)](https://stonerlab.github.io/bad_path/)
[![PyPI version](https://badge.fury.io/py/bad-path.svg)](https://badge.fury.io/py/bad-path)
[![Anaconda Version](https://anaconda.org/phygbu/bad_path/badges/version.svg)](https://anaconda.org/phygbu/bad_path/badges/version.svg)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/68df7b8d1d044f17887b7d0df56b4aef)](https://app.codacy.com/gh/stonerlab/bad_path/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Platform](https://anaconda.org/phygbu/bad_path/badges/platforms.svg)](https://anaconda.org/phygbu/bad_path/badges/platforms.svg)
[![License](https://anaconda.org/phygbu/bad_path/badges/license.svg)](https://anaconda.org/phygbu/bad_path/badges/license.svg)

A Python package to identify potentially dangerous file paths.

## Overview

`bad_path` provides functions to test whether a supplied file path points to a system-sensitive location, taking
into account different OS platforms (Windows, macOS, Linux).

## Installation

### From PyPI

```bash
pip install bad_path
```

### From Conda

```bash
conda install -c phygbu bad_path
# or
mamba install -c phygbu bad_path
```

### From Source

```bash
git clone https://github.com/stonerlab/bad_path.git
cd bad_path
pip install -e .
```

## Quick Start

```python
from bad_path import is_dangerous_path, DangerousPathError

# Check if a path is dangerous
if is_dangerous_path("/etc/passwd"):
    print("Warning: This path points to a sensitive location!")

# Raise an exception for dangerous paths
try:
    is_dangerous_path("/etc/passwd", raise_error=True)
except DangerousPathError as e:
    print(f"Error: {e}")

# Use the PathChecker class for more details
from bad_path import PathChecker

checker = PathChecker("/etc/passwd")
if not checker:
    print(f"Dangerous path detected!")
    print(f"Platform system path: {checker.is_system_path}")
    print(f"User-defined sensitive path: {checker.is_sensitive_path}")

# Check path accessibility
checker = PathChecker("/tmp/myfile.txt")
if checker:
    print("Safe path!")
print(f"Readable: {checker.is_readable}")
print(f"Writable: {checker.is_writable}")
print(f"Creatable: {checker.is_creatable}")
```

## Features

- ✅ Cross-platform support (Windows, macOS, Linux)
- ✅ Simple API for checking dangerous paths
- ✅ Object-oriented `PathChecker` class with detailed information
- ✅ Path accessibility checks (read, write, create permissions)
- ✅ **Invalid character detection** (platform-specific)
- ✅ **Path traversal protection** (optional `cwd_only` flag)
- ✅ Customizable error handling
- ✅ Lightweight with no external dependencies
- ✅ Works with both strings and `pathlib.Path` objects
- ✅ User-defined dangerous paths support

## Usage Examples

### Basic Path Checking

```python
from bad_path import is_dangerous_path

# Simple boolean check
if is_dangerous_path("/etc/passwd"):
    print("This is a dangerous system path!")

if not is_dangerous_path("/tmp/myfile.txt"):
    print("Safe to use!")
```

### Read vs Write Validation

The `mode` parameter makes it easy to validate paths for different purposes:

```python
from bad_path import PathChecker

# Validate for reading - allows system configuration files
checker = PathChecker("/etc/passwd", mode="read")
if checker:
    print("Safe to read from this path!")
    # Read the file...

# Validate for writing - strict validation
checker = PathChecker("/tmp/output.txt", mode="write")
if checker:
    print("Safe to write to this path!")
    # Write to the file...

# Attempting to write to system paths is blocked
checker = PathChecker("/etc/myconfig.txt", mode="write")
if not checker:
    print("Blocked: Cannot write to system paths!")
```

### Checking Path Accessibility

```python
from bad_path import PathChecker

# Check if a file is readable
checker = PathChecker("/etc/passwd")
if checker.is_readable:
    print("File can be read")

# Check if a file is writable
checker = PathChecker("/tmp/test.txt")
if checker.is_writable:
    print("File can be written to")

# Check if a new file can be created
checker = PathChecker("/tmp/newfile.txt")
if checker.is_creatable:
    print("File can be created in this location")
```

### Combining Safety and Accessibility Checks

```python
from bad_path import PathChecker

def safe_to_write(filepath):
    """Check if a path is both safe and writable."""
    checker = PathChecker(filepath)
    
    # PathChecker evaluates to True for safe paths
    if not checker:
        return False  # Dangerous location
    
    # Must be writable or creatable
    return checker.is_writable or checker.is_creatable

# Usage
safe_to_write("/tmp/myfile.txt")  # True - safe and creatable
safe_to_write("/etc/passwd")       # False - dangerous location
```

### Checking for Invalid Characters

```python
from bad_path import PathChecker

# Check if a path contains invalid characters for the platform
checker = PathChecker("/tmp/test\x00file.txt")  # Null byte is invalid on all platforms
print(f"Has invalid characters: {checker.has_invalid_chars}")  # True
print(f"Is safe: {bool(checker)}")  # False - dangerous due to invalid char

# Platform-specific invalid characters:
# - POSIX (Linux): null byte (\0)
# - macOS (Darwin): null byte (\0) and colon (:)
# - Windows: < > : " | ? * and control characters (0-31)
#            Also checks for reserved names: CON, PRN, AUX, NUL, COM1-9, LPT1-9

# Windows example - reserved name check
checker = PathChecker("C:\\tmp\\CON.txt")  # CON is a reserved name
print(f"Has invalid characters: {checker.has_invalid_chars}")  # True on Windows

# Paths ending with space or period are invalid on Windows
checker = PathChecker("C:\\tmp\\file. ")
print(f"Has invalid characters: {checker.has_invalid_chars}")  # True on Windows
```

### Path Traversal Protection

The `cwd_only` flag provides protection against path traversal attacks by restricting paths to the current working
directory and its subdirectories. This is disabled by default to maintain backward compatibility.

```python
from bad_path import PathChecker

# Enable path traversal protection
checker = PathChecker("../../../etc/passwd", cwd_only=True)
if not checker:
    print("Blocked: Path traversal attempt detected!")

# Paths outside CWD are blocked
checker = PathChecker("/tmp/file.txt", cwd_only=True)
if not checker:
    print("Blocked: Path is outside current working directory!")

# Paths within CWD and its subdirectories are allowed
checker = PathChecker("./data/file.txt", cwd_only=True)
if checker:
    print("Safe: Path is within current working directory")

# Works with raise_error for automatic exception handling
from bad_path import DangerousPathError
try:
    checker = PathChecker("../../sensitive.txt", cwd_only=True, raise_error=True)
except DangerousPathError as e:
    print(f"Error: {e}")
```

Use cases for `cwd_only`:

- Web applications handling user-provided file paths
- CLI tools that should only operate on files in the current project
- Sandboxed environments where file access should be restricted
- Any scenario where you need to prevent directory traversal attacks

```python
# Example: Secure file handler for a web application
def handle_user_file_request(user_path):
    """Safely handle user-provided file paths."""
    # Validate the path is within CWD to prevent traversal attacks
    checker = PathChecker(user_path, cwd_only=True, raise_error=True)
    
    # Additional checks
    if not checker.is_readable:
        raise PermissionError("File is not readable")
    
    # Safe to proceed with file operations
    with open(checker.path, 'r') as f:
        return f.read()
```

## Documentation

Full documentation is available at [https://stonerlab.github.io/bad_path/](https://stonerlab.github.io/bad_path/)

## Development

For development, install with the optional development dependencies:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

Build documentation:

```bash
cd docs
make html
```

## License

MIT License - see [LICENSE](LICENSE) file for details.
