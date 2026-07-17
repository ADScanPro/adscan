# Changelog

All notable changes to ADscan are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

### Changed

### Fixed

### Removed

## [10.0.0] - 2026-07-17

### Added

### Changed

### Fixed

### Removed

## [9.2.1] - 2026-06-29

### Added

### Changed

### Fixed

### Removed

## [9.2.0] - 2026-06-23

### Added

### Changed

### Fixed

### Removed

## [9.1.1] - 2026-06-09

### Added

### Changed

### Fixed

### Removed

## [9.1.0] - 2026-06-04

### Added

### Changed

### Fixed

### Removed

## [9.0.1] - 2026-05-31

### Added
- Automatic credential recovery when a discovered account is not found in the
  domain: the recovered secret is fuzzy-matched against enumerated users and
  verified live, with a lockout-safe password-spray fallback to identify the
  account the secret actually belongs to.

### Changed

### Fixed
- WinRM Kerberos authentication now reuses the workspace TGT ticket cache (or
  mints one from the recovered password), fixing "matching credential not
  found" failures in environments without a local Kerberos credential cache.
- MSSQL Kerberos logins now target the domain KDC explicitly, fixing
  authentication when the runtime cannot resolve the KDC via DNS.

### Removed

## [9.0.0] - 2026-05-20

### Added
- S4U2Self elevation for machine account credentials with notifier callbacks
- LSA secrets parsing: Kerberos password, security questions, DefaultPassword
- AES-256 key derivation for machine account SMB/Kerberos authentication
- Backup Operators escalation path via RRP with S4U2Self elevation
- Machine account credential persistence and DC short hostname resolution
- Winlogon DefaultUserName retrieval in LSA secret parsing
- Clock-skew patches applied before all Kerberos calls

### Fixed
- AP-REQ uses clock-skew-adjusted time in construct_apreq_from_ticket
- Stale history entries suppressed in LSA secrets parsing
- Trailing null bytes stripped from Winlogon DefaultUserName

## [8.0.0] - 2026-04-26

### Added
- Major release — see GitHub release notes for full details

## [7.2.0] - 2026-04-19

### Added
- See GitHub release notes for details

## [7.1.0] - 2026-04-15

### Added
- See GitHub release notes for details

## [7.0.0] - 2026-04-13

### Added
- See GitHub release notes for details

## [6.5.0] - 2026-04-09

### Added
- See GitHub release notes for details

[Unreleased]: https://github.com/ADScanPro/adscan/compare/v10.0.0...HEAD
[10.0.0]: https://github.com/ADScanPro/adscan/compare/v9.2.1...v10.0.0
[9.2.1]: https://github.com/ADScanPro/adscan/compare/v9.2.0...v9.2.1
[9.2.0]: https://github.com/ADScanPro/adscan/compare/v9.1.1...v9.2.0
[9.1.1]: https://github.com/ADScanPro/adscan/compare/v9.1.0...v9.1.1
[9.1.0]: https://github.com/ADScanPro/adscan/compare/v9.0.1...v9.1.0
[9.0.1]: https://github.com/ADScanPro/adscan/compare/v9.0.0...v9.0.1
[9.0.0]: https://github.com/ADScanPro/adscan/compare/v8.0.0...v9.0.0
[8.0.0]: https://github.com/ADScanPro/adscan/compare/v7.2.0...v8.0.0
[7.2.0]: https://github.com/ADScanPro/adscan/compare/v7.1.0...v7.2.0
[7.1.0]: https://github.com/ADScanPro/adscan/compare/v7.0.0...v7.1.0
[7.0.0]: https://github.com/ADScanPro/adscan/compare/v6.5.0...v7.0.0
[6.5.0]: https://github.com/ADScanPro/adscan/releases/tag/v6.5.0
