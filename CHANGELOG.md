# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

-   **Added** for new features.
-   **Changed** for changes in existing functionality.
-   **Deprecated** for soon-to-be removed features.
-   **Removed** for now removed features.
-   **Fixed** for any bug fixes.
-   **Security** in case of vulnerabilities.

## [Unreleased]
### Added
- Added route4me to sponsorship page

### Removed
-   Removed CVE-2023-23397 due to unreliability of check

## 1.2 - 2024-04-24
### Added
-   Added GitHub action to compile executable on release
-   Added 2023-23397
-   Added 2022-34718

### Removed
-   Removed unused imports

### Changed
-   Updated min .NET version to 4.5
-   Updated CVE-2021-44228 to have a max depth for scanning files
-   Updated Task calls so it works with Empire

## 1.1 - 2024-03-13
### Added
-   Added CVE-2021-26855 (ProxyLogon) scan
-   Added CVE 2021-36934 (HiveNightmare)
-   Added CVE-2021-26857
-   Added CVE-2021-26858
-   Added CVE-2021-27065
-   Added 22H1 and 23H2 support

### Removed
-   Remove redundant lists within program

### Changed
-   Updated Windows version check to return build number if not supported but still run

### Fixed
-   Fix issue where CVE-2022-22965 incorrectly reported vulnerable if localhost failed to connect
-   Fix issue where CVE-2023-36664 was not correctly enumerating files for version number
