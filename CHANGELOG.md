# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive integration tests against real Tor instance
- Docker Compose setup for running Tor in CI/testing environments
- GitHub Actions CI workflow with linting, testing, and integration tests
- Configuration management example (`config.rs`)

### Changed
- MSRV bumped to 1.71 (required by tokio/mio dependencies)

### Fixed
- Password authentication now correctly quotes passwords per Tor protocol spec

## [0.1.1] - 2025-01-12

### Added
- Complete Tor Control Protocol v1 implementation
- Async client (`TorClient`) using Tokio
- All authentication methods: NULL, password, cookie, SAFECOOKIE
- Configuration management: `get_conf`, `set_conf`, `reset_conf`, `save_conf`, `load_conf`
- Circuit control: `extend_circuit`, `close_circuit`, `get_circuit_status`
- Stream control: `close_stream`, `attach_stream`, `get_stream_status`
- Event subscription and monitoring for 28+ event types
- Onion service management: `add_onion`, `del_onion`
- Signal support: NEWNYM, RELOAD, SHUTDOWN, DUMP, DEBUG, HALT, CLEARDNSCACHE, HEARTBEAT, ACTIVE, DORMANT
- Address mapping and DNS resolution
- Process ownership control: `take_ownership`, `drop_ownership`, `drop_guards`
- Test utilities module with mock response helpers
- Four working examples: basic, new_identity, events, onion_service

### Security
- No unsafe code (enforced with `#![deny(unsafe_code)]`)
- SAFECOOKIE authentication with HMAC verification

## [0.1.0] - 2025-01-10

### Added
- Initial release
- Basic connection and authentication
- Core type definitions

[Unreleased]: https://github.com/josh/tor-control-rs/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/josh/tor-control-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/josh/tor-control-rs/releases/tag/v0.1.0
