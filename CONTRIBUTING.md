# Contributing to bad_path

Thank you for considering contributing to bad_path! This document provides guidelines for
contributing to the project.

## Code of Conduct

Please be respectful and constructive in all interactions with the project and its
contributors.

## Getting Started

### Development Setup

1. Fork the repository on GitHub
2. Clone your fork locally:

   ```bash
   git clone https://github.com/YOUR_USERNAME/bad_path.git
   cd bad_path
   ```

3. Install the package with development dependencies:

   ```bash
   pip install -e ".[dev]"
   ```

4. Install pre-commit hooks:

   ```bash
   pre-commit install
   ```

   This will automatically run black (Python formatter with line-length=119) and markdownlint
   before each commit.

5. Create a branch for your changes:

   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

### Running Tests

Run the test suite:

```bash
pytest
```

Run tests with coverage:

```bash
pytest --cov=bad_path --cov-report=term-missing
```

### Code Quality

Format code with black (line-length=119):

```bash
black .
```

Check code with ruff:

```bash
ruff check .
```

Format code with ruff (if needed):

```bash
ruff format .
```

Run pre-commit hooks manually on all files:

```bash
pre-commit run --all-files
```

### Building Documentation

Build the documentation locally:

```bash
cd docs
make html
```

The built documentation will be in `docs/_build/html/`.

## Coding Standards

### Python Style

- Follow PEP 8 style guide
- Use Python 3.10+ features (type unions with |, match/case statements)
- Line length: 119 characters for black formatting, 100 characters for ruff
- Use black for automatic code formatting
- Use ruff for linting and additional formatting

### Docstrings

- Follow Google-style docstrings
- Use British English spelling in documentation
- Document all public classes, methods, and functions
- Include examples in docstrings for public APIs

### Type Hints

- Use type hints for all function signatures
- Use modern Python 3.10+ syntax (e.g., `list[str]` instead of `List[str]`)
- Use `str | Path` for union types instead of `Union[str, Path]`

### Testing

- Write tests for all new features
- Maintain or improve test coverage (target: 85%+)
- Test platform-specific behaviour where applicable
- Use descriptive test names that explain what is being tested

## Pull Request Process

1. **Create an Issue First**: For significant changes, create an issue to discuss the
   proposed changes before starting work.

2. **Make Your Changes**:
   - Write clear, concise commit messages
   - Keep commits focused and atomic
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**:
   - Run the full test suite
   - Check code quality with ruff
   - Format code with black (or run pre-commit hooks)
   - Build documentation to check for errors
   - Test on multiple platforms if possible

4. **Submit Pull Request**:
   - Fill out the PR template completely
   - Reference related issues
   - Describe what changes you made and why
   - Include screenshots for UI changes (if applicable)

5. **Code Review**:
   - Address reviewer feedback promptly
   - Make requested changes in new commits
   - Once approved, your PR will be merged

## What to Contribute

### Good First Issues

Look for issues tagged with `good first issue` or `help wanted`.

### Areas for Contribution

- **Bug Fixes**: Report and fix bugs
- **Documentation**: Improve docs, add examples, fix typos
- **Tests**: Increase test coverage, add edge case tests
- **Features**: Implement new features (discuss first in an issue)
- **Performance**: Optimise slow code paths
- **Platform Support**: Improve cross-platform compatibility

### Priority Areas (from Code Review)

1. Add static type checking (mypy) to CI/CD
2. Increase test coverage to 85%+
3. Optimise path matching for large user path lists
4. Add Unicode normalisation for security
5. Add more real-world usage examples

## Reporting Bugs

When reporting bugs, please include:

- Python version and operating system
- bad_path version
- Minimal code to reproduce the issue
- Expected vs actual behaviour
- Any error messages or stack traces

## Feature Requests

When requesting features, please include:

- Use case: Why is this feature needed?
- Proposed API: How should it work?
- Alternatives: Are there other ways to achieve this?
- Impact: Who would benefit from this feature?

## Questions?

If you have questions about contributing, feel free to:

- Open an issue with the `question` label
- Check existing issues and documentation

## Licence

By contributing to bad_path, you agree that your contributions will be licensed under the
MIT Licence.
