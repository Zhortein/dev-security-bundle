# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of Zhortein Dev Security Bundle
- ProfilerAccessSubscriber for restricting Symfony Profiler and Web Debug Toolbar access
- RestrictedAccessSubscriber for restricting routes marked with `#[RestrictedToDevWhitelist]` attribute
- Support for IP-based and CIDR-based whitelisting
- Support for reverse DNS hostname pattern matching with wildcard support
- Configuration option to enable/disable bundle globally
- Configuration option to log blocked access attempts
- Comprehensive documentation and usage examples
- Comprehensive logging test suite (ProfilerAccessSubscriberLoggingTest, RestrictedAccessSubscriberLoggingTest)
- Performance regression tests for audit trail validation
- 20 new unit tests for logging functionality and performance monitoring

### Security
- Protects sensitive debugging tools from unauthorized access
- Prevents accidental exposure of sensitive information in development environments
- Audit trail logging with configurable verbosity for security monitoring

## [1.0.0-alpha] - Initial Release

### Added
- Base security bundle for Symfony development environments
- Whitelist-based access control for Profiler and Web Debug Toolbar
- Attribute-based route restriction with `#[RestrictedToDevWhitelist]`
- IP and CIDR range support
- Reverse DNS hostname pattern matching
- Audit logging for blocked attempts
- Zero additional dependencies beyond Symfony

### Features
- ✅ Restricts Symfony Web Debug Toolbar & Profiler to allowed IPs / CIDR / hostnames
- ✅ Logs blocked attempts for audit
- ✅ Optional `#[RestrictedToDevWhitelist]` attribute to secure sensitive routes
- ✅ Works out of the box with minimal configuration
