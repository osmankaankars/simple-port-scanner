# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-02-03
### Added
- Multi-target scanning (host lists, host files, CIDR, ranges) with safety limits.
- IPv6 support and async scanning engine with thread fallback.
- Retry/backoff and rate-limit profiles.
- Optional banner grabbing for open ports.
- Config file support, richer JSON/CSV outputs, and CLI install (`portscan`).
- Tests, ruff linting, and GitHub Actions CI.

## [1.0.0] - 2026-02-03
### Added
- Initial release with TCP connect scanning, presets, and output formats.
