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
if checker:
    print(f"Dangerous path detected!")
    print(f"Platform system path: {checker.is_system_path}")
    print(f"User-defined sensitive path: {checker.is_sensitive_path}")
```

## Features

- ✅ Cross-platform support (Windows, macOS, Linux)
- ✅ Simple API for checking dangerous paths
- ✅ Object-oriented `PathChecker` class with detailed information
- ✅ Customizable error handling
- ✅ Lightweight with no external dependencies
- ✅ Works with both strings and `pathlib.Path` objects
- ✅ User-defined dangerous paths support

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
