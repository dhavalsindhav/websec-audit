# Changelog

All notable changes to the WebSec-Audit package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2025-06-24

### Added
- Email Verification module for checking email address validity
- Blacklist Status Checker for domain reputation verification
- Cookie Security Analysis module for evaluating cookie configurations
- Email Security module for analyzing SPF, DMARC, DKIM, MTA-STS, and BIMI records
- Enhanced TLS/SSL Analysis with improved compatibility and reliability

### Changed
- Refactored TLS/SSL scanner to remove problematic dependencies
- Improved backend modules with better error handling and performance
- Updated documentation with examples for new modules

## [1.0.0] - 2025-06-19

### Added
- Initial release of WebSec-Audit
- Security Headers Analysis module
- Form Detection module
- Sensitive File Detection module
- Subdomain Enumeration module
- Technology Detection module
- Library Vulnerability Scanning module
- Web Application Firewall Detection module
- TLS/SSL Configuration Analysis module (Node.js only)
- Port Scanning module (Node.js only)
- DNS Record Analysis module (Node.js only)
- Historical Content Analysis via Wayback Machine API
- Browser and Node.js compatible architecture
- Comprehensive documentation and examples
