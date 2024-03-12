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
-   Added CVE-2021-26855 (ProxyLogon) scan
-   Added CVE 2021-36934 (HiveNightmare)
-	Added CVE-2021-26855 (ProxyLogon) scan
-   Added CVE-2021-26857
-   Added CVE-2021-26858
-   Added CVE-2021-27065
-   Added 22H1 and 23H2 support

### Removed
-	Remove redundant lists within program

### Changed**
-   Updated Windows version check to return build number if not supported but still run

### Fixed
-   Fix issue where CVE-2022-22965 incorrectly reported vulnerable if localhost failed to connect
-   Fix issue where CVE-2023-36664 was not correctly enumerating files for version number
