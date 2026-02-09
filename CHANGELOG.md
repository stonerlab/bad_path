# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Comprehensive code review document (CODE_REVIEW.md)
- CHANGELOG.md file for tracking changes
- docs/_static directory for Sphinx documentation

## [0.1.0] - 2026-02-07

### Initial Release

- Initial release
- Cross-platform path checking for Windows, macOS, and Linux
- PathChecker class with boolean context support
- Invalid character detection for platform-specific restrictions
- Path accessibility checks (is_readable, is_writable, is_creatable)
- User-defined dangerous paths support
- Comprehensive documentation with Sphinx
- 73% test coverage with 90 tests
- CI/CD workflows for testing, documentation, and package building

[Unreleased]: https://github.com/stonerlab/bad_path/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/stonerlab/bad_path/releases/tag/v0.1.0
