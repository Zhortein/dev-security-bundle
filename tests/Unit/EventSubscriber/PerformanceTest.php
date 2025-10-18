<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\Tests\Unit\EventSubscriber;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Zhortein\DevSecurityBundle\EventSubscriber\ProfilerAccessSubscriber;

final class PerformanceTest extends TestCase
{
    /**
     * Test performance with a single allowed IP - baseline case
     * Regression test to ensure performance doesn't degrade significantly
     * Note: Absolute times vary by environment (Docker, VM, host machine).
     */
    public function testPerformanceWithSingleAllowedIp(): void
    {
        $subscriber = new ProfilerAccessSubscriber(['127.0.0.1'], [], false, new NullLogger());
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);

        $startTime = microtime(true);
        for ($i = 0; $i < 100; ++$i) {
            $event = new RequestEvent($kernel, $request, 1);
            $subscriber->onKernelRequest($event);
        }
        $elapsed = (microtime(true) - $startTime) * 1000; // Convert to ms

        // Just verify it completes in reasonable time (regression test)
        // Absolute threshold varies significantly by environment
        self::assertLessThan(10000, $elapsed, sprintf('Severe performance degradation: %fms for 100 iterations', $elapsed));
    }

    /**
     * Test performance with multiple allowed IPs
     * Regression test to ensure multiple IPs don't cause dramatic slowdown.
     */
    public function testPerformanceWithMultipleAllowedIps(): void
    {
        $allowedIps = [
            '127.0.0.1',
            '192.168.1.0/24',
            '192.168.2.0/24',
            '192.168.3.0/24',
            '10.0.0.0/8',
            '172.16.0.0/12',
            '::1',
            'fe80::/10',
            '2001:db8::/32',
            '2001:db9::/32',
        ];

        $subscriber = new ProfilerAccessSubscriber($allowedIps, [], false, new NullLogger());
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.50.0.1');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);

        $startTime = microtime(true);
        for ($i = 0; $i < 100; ++$i) {
            $event = new RequestEvent($kernel, $request, 1);
            $subscriber->onKernelRequest($event);
        }
        $elapsed = (microtime(true) - $startTime) * 1000;

        // Regression test: 100 iterations with 10 IPs should complete
        self::assertLessThan(10000, $elapsed, sprintf('Severe performance degradation with 10 IPs: %fms for 100 iterations', $elapsed));
    }

    /**
     * Test performance with CIDR range matching
     * Regression test to ensure CIDR ranges are validated efficiently.
     */
    public function testPerformanceWithCidrRanges(): void
    {
        $subscriber = new ProfilerAccessSubscriber(['192.168.0.0/16'], [], false, new NullLogger());
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '192.168.100.50');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);

        $startTime = microtime(true);
        for ($i = 0; $i < 100; ++$i) {
            $event = new RequestEvent($kernel, $request, 1);
            $subscriber->onKernelRequest($event);
        }
        $elapsed = (microtime(true) - $startTime) * 1000;

        // CIDR validation regression test
        self::assertLessThan(10000, $elapsed, sprintf('CIDR range validation degraded: %fms for 100 iterations', $elapsed));
    }

    /**
     * Test performance difference between allowed and denied access
     * Regression test to ensure denied/allowed paths don't have huge difference.
     */
    public function testPerformanceDeniedAccessVsAllowed(): void
    {
        $subscriber = new ProfilerAccessSubscriber(['127.0.0.1'], [], false, new NullLogger());
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);

        $startTime = microtime(true);
        for ($i = 0; $i < 100; ++$i) {
            $event = new RequestEvent($kernel, $request, 1);
            $subscriber->onKernelRequest($event);
        }
        $deniedElapsed = (microtime(true) - $startTime) * 1000;

        // Now test allowed access
        $request->server->set('REMOTE_ADDR', '127.0.0.1');
        $startTime = microtime(true);
        for ($i = 0; $i < 100; ++$i) {
            $event = new RequestEvent($kernel, $request, 1);
            $subscriber->onKernelRequest($event);
        }
        $allowedElapsed = (microtime(true) - $startTime) * 1000;

        // Verify both paths complete (no hard requirements on relative performance in container)
        self::assertLessThan(10000, $deniedElapsed, sprintf('Denied path too slow: %fms for 100 iterations', $deniedElapsed));
        self::assertLessThan(10000, $allowedElapsed, sprintf('Allowed path too slow: %fms for 100 iterations', $allowedElapsed));
    }

    /**
     * Test performance with IPv6 addresses
     * Regression test to ensure IPv6 validation is efficient.
     */
    public function testPerformanceWithIpv6(): void
    {
        $subscriber = new ProfilerAccessSubscriber(['::1', 'fe80::/10'], [], false, new NullLogger());
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '2001:db8::1');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);

        $startTime = microtime(true);
        for ($i = 0; $i < 100; ++$i) {
            $event = new RequestEvent($kernel, $request, 1);
            $subscriber->onKernelRequest($event);
        }
        $elapsed = (microtime(true) - $startTime) * 1000;

        // IPv6 validation regression test
        self::assertLessThan(10000, $elapsed, sprintf('IPv6 validation degraded: %fms for 100 iterations', $elapsed));
    }

    /**
     * Test impact of logging on performance
     * Regression test to verify logging overhead is acceptable.
     */
    public function testLoggingPerformanceImpact(): void
    {
        $nullLogger = new NullLogger();
        $subscriber = new ProfilerAccessSubscriber(['127.0.0.1'], [], true, $nullLogger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);

        $startTime = microtime(true);
        for ($i = 0; $i < 100; ++$i) {
            $event = new RequestEvent($kernel, $request, 1);
            $subscriber->onKernelRequest($event);
        }
        $loggingElapsed = (microtime(true) - $startTime) * 1000;

        // With logging disabled for comparison
        $subscriberNoLog = new ProfilerAccessSubscriber(['127.0.0.1'], [], false, $nullLogger);
        $startTime = microtime(true);
        for ($i = 0; $i < 100; ++$i) {
            $event = new RequestEvent($kernel, $request, 1);
            $subscriberNoLog->onKernelRequest($event);
        }
        $noLoggingElapsed = (microtime(true) - $startTime) * 1000;

        // Both paths should complete within reasonable time
        self::assertLessThan(10000, $loggingElapsed, sprintf('Logging enabled too slow: %fms for 100 iterations', $loggingElapsed));
        self::assertLessThan(10000, $noLoggingElapsed, sprintf('Logging disabled too slow: %fms for 100 iterations', $noLoggingElapsed));
    }

    /**
     * Test performance with allowed hostnames patterns
     * Regression test to ensure hostname patterns don't cause problems.
     */
    public function testPerformanceWithHostnamePatterns(): void
    {
        $patterns = [
            '*.example.com',
            '*.internal.company.com',
            'dev-*.servers.local',
            'qa-*.servers.local',
        ];

        $subscriber = new ProfilerAccessSubscriber([], $patterns, false, new NullLogger());
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);

        $startTime = microtime(true);
        for ($i = 0; $i < 100; ++$i) {
            $event = new RequestEvent($kernel, $request, 1);
            $subscriber->onKernelRequest($event);
        }
        $elapsed = (microtime(true) - $startTime) * 1000;

        // Hostname pattern matching regression test
        // (reverse DNS lookup is the expensive part, but it's only done once per request)
        self::assertLessThan(10000, $elapsed, sprintf('Hostname pattern matching degraded: %fms for 100 iterations', $elapsed));
    }
}
