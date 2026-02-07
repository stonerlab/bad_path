# bad_path

[![Tests](https://github.com/gb119/bad_path/actions/workflows/tests.yml/badge.svg)](https://github.com/gb119/bad_path/actions/workflows/tests.yml)
[![Documentation](https://github.com/gb119/bad_path/actions/workflows/docs.yml/badge.svg)](https://gb119.github.io/bad_path/)
[![PyPI version](https://badge.fury.io/py/bad-path.svg)](https://badge.fury.io/py/bad-path)

A Python package to identify potentially dangerous file paths.

## Overview

`bad_path` provides functions to test whether a supplied file path points to a system-sensitive location, taking into account different OS platforms (Windows, macOS, Linux).

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
git clone https://github.com/gb119/bad_path.git
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

## Documentation

Full documentation is available at [https://gb119.github.io/bad_path/](https://gb119.github.io/bad_path/)

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
