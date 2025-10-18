<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\Tests\Unit\DependencyInjection;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Processor;
use Zhortein\DevSecurityBundle\DependencyInjection\Configuration;

final class ConfigurationTest extends TestCase
{
    public function testDefaultConfiguration(): void
    {
        $configuration = new Configuration();
        $processor = new Processor();

        $config = $processor->processConfiguration($configuration, [[]]);

        self::assertArrayHasKey('enabled', $config);
        self::assertArrayHasKey('allowed_ips', $config);
        self::assertArrayHasKey('allowed_hosts', $config);
        self::assertArrayHasKey('log_blocked_attempts', $config);
    }

    public function testEnabledDefaultsToTrue(): void
    {
        $configuration = new Configuration();
        $processor = new Processor();

        $config = $processor->processConfiguration($configuration, [[]]);

        self::assertTrue($config['enabled']);
    }

    public function testAllowedIpsHasDefaults(): void
    {
        $configuration = new Configuration();
        $processor = new Processor();

        $config = $processor->processConfiguration($configuration, [[]]);

        self::assertIsArray($config['allowed_ips']);
        self::assertSame(['127.0.0.1', '::1', 'localhost'], $config['allowed_ips']);
    }

    public function testAllowedHostsDefaultsToEmpty(): void
    {
        $configuration = new Configuration();
        $processor = new Processor();

        $config = $processor->processConfiguration($configuration, [[]]);

        self::assertIsArray($config['allowed_hosts']);
        self::assertEmpty($config['allowed_hosts']);
    }

    public function testLogBlockedAttemptsDefaultsToTrue(): void
    {
        $configuration = new Configuration();
        $processor = new Processor();

        $config = $processor->processConfiguration($configuration, [[]]);

        self::assertTrue($config['log_blocked_attempts']);
    }

    public function testCanConfigureAllowedIps(): void
    {
        $configuration = new Configuration();
        $processor = new Processor();

        $config = $processor->processConfiguration($configuration, [[
            'allowed_ips' => ['127.0.0.1', '192.168.0.0/16'],
        ]]);

        self::assertSame(['127.0.0.1', '192.168.0.0/16'], $config['allowed_ips']);
    }

    public function testCanConfigureAllowedHosts(): void
    {
        $configuration = new Configuration();
        $processor = new Processor();

        $config = $processor->processConfiguration($configuration, [[
            'allowed_hosts' => ['*.local', 'dev.example.com'],
        ]]);

        self::assertSame(['*.local', 'dev.example.com'], $config['allowed_hosts']);
    }

    public function testCanDisableBundle(): void
    {
        $configuration = new Configuration();
        $processor = new Processor();

        $config = $processor->processConfiguration($configuration, [[
            'enabled' => false,
        ]]);

        self::assertFalse($config['enabled']);
    }

    public function testCanEnableLogging(): void
    {
        $configuration = new Configuration();
        $processor = new Processor();

        $config = $processor->processConfiguration($configuration, [[
            'log_blocked_attempts' => true,
        ]]);

        self::assertTrue($config['log_blocked_attempts']);
    }

    public function testCompleteConfiguration(): void
    {
        $configuration = new Configuration();
        $processor = new Processor();

        $config = $processor->processConfiguration($configuration, [[
            'enabled' => true,
            'allowed_ips' => ['127.0.0.1', '::1'],
            'allowed_hosts' => ['localhost'],
            'log_blocked_attempts' => true,
        ]]);

        self::assertTrue($config['enabled']);
        self::assertSame(['127.0.0.1', '::1'], $config['allowed_ips']);
        self::assertSame(['localhost'], $config['allowed_hosts']);
        self::assertTrue($config['log_blocked_attempts']);
    }
}
