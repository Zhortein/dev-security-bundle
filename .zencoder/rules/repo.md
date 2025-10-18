---
description: Repository Information Overview
alwaysApply: true
---

# Zhortein Dev Security Bundle Information

## Summary
A Symfony bundle that protects development environments from accidental exposure of sensitive data by restricting access to the Web Debug Toolbar, Profiler, and debug routes to a whitelist of IPs or reverse hostnames.

## Structure
- **src/**: Core bundle code including attributes, event subscribers, and DI configuration
- **tests/**: Test files for the bundle
- **config/**: Service configuration
- **.zencoder/**: Zencoder configuration files
- **Makefile**: Docker-based development commands

## Language & Runtime
**Language**: PHP
**Version**: PHP 8.3+
**Build System**: Composer
**Package Manager**: Composer
**Framework**: Symfony 7.0+

## Dependencies
**Main Dependencies**:
- symfony/dependency-injection: ~7.0
- symfony/config: ~7.0
- symfony/http-kernel: ~7.0
- symfony/yaml: ~7.0

**Development Dependencies**:
- friendsofphp/php-cs-fixer: ^v3.75.0
- phpstan/phpstan: ^2.1
- phpstan/phpstan-doctrine: ^2.0
- phpstan/phpstan-symfony: ^2.0
- phpunit/php-code-coverage: ^12.3.1
- phpunit/phpunit: ^12.2.5
- symfony/framework-bundle: ^7.0
- symfony/phpunit-bridge: ^7.3
- symfony/test-pack: ^1.0

## Build & Installation
```bash
# Install as a dev dependency in a Symfony project
composer require --dev zhortein/dev-security-bundle

# Development setup (using Docker)
make installdeps
make dev-setup

# Run tests
make test

# Code quality checks
make phpstan
make csfixer
```

## Docker
**Configuration**: Docker-based development environment using PHP 8.3 CLI image
**Commands**:
- `make php`: Opens a PHP 8.3 shell in container
- `make installdeps`: Installs dependencies in container
- `make test`: Runs tests in container

## Testing
**Framework**: PHPUnit
**Test Location**: tests/ directory
**Run Command**:
```bash
make test
make test-unit
make test-coverage
```

## Key Components
**Main Bundle Class**: `src/ZhorteinDevSecurityBundle.php`
**Configuration**: `src/DependencyInjection/Configuration.php`
**Services**:
- `ProfilerAccessSubscriber`: Restricts access to Symfony profiler
- `RestrictedAccessSubscriber`: Handles routes with `RestrictedToDevWhitelist` attribute
**Attributes**:
- `RestrictedToDevWhitelist`: Attribute to secure sensitive routes