# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial Relay stale-cache worker-death fuzzer CLI.
- PHP CLI-server router with `/pid`, `/get`, `/warm`, `/tracked`, and `/many`
  endpoints.
- Deterministic option parsing with seed support.
- Built-in Redis RESP client for driver-side `SET`, `GET`, `INCR`, `DEL`, and
  `PING`.
- Built-in HTTP JSON client for talking to the PHP CLI server.
- Worker discovery through endpoint responses.
- Worker killing with configurable signal mix.
- Persistent stale-value verification with retry and delay controls.
- Progress watchdog, server output capture, request statistics, and diagnostic
  ring buffers.
- JSON failure reproducer output and best-effort replay mode.
- Local agent notes for this fuzzer project.

