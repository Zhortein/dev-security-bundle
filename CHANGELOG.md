# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2024-12-19

### Fixed
- Remove tautologous `assertTrue(true)` assertions that trigger PHPStan warnings
- Create `tests/Integration` directory to fix PHPUnit test discovery
- Add `expectNotToPerformAssertions()` to tests validating "no exception thrown" behavior
- Update PHPUnit XSD schema to 12.0 for PHPUnit 12.x compatibility
- Replace deprecated `<coverage>` element with `<source>` for code coverage filtering
- Use `includeUncoveredFiles` attribute instead of `processUncoveredFiles` for PHPUnit 12 schema
- Configure PHPUnit code coverage report format (clover) to fix coverage warnings
- Fixes PHPStan level max validation errors
- Fixes PHPUnit test directory not found error
- Fixes PHPUnit risky test warnings for tests without assertions
- Fixes PHPUnit XML schema validation errors and code coverage configuration

## [1.0.0] - 2024-12-19

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

### Infrastructure
- GitHub Actions CI/CD workflow with automated testing and static analysis
- Multi-version PHP (8.3, 8.4) test matrix
- Code coverage reporting with Codecov integration
- Security audit scanning with composer audit

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
