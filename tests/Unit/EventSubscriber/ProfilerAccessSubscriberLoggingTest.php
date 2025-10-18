<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\Tests\Unit\EventSubscriber;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Zhortein\DevSecurityBundle\EventSubscriber\ProfilerAccessSubscriber;

final class ProfilerAccessSubscriberLoggingTest extends TestCase
{
    public function testBlockedAccessIsLoggedAtInfoLevel(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        // Expect info() to be called once with the blocked IP
        $logger->expects(self::once())
            ->method('info')
            ->with(self::stringContains('Profiler disabled for unauthorized IP 10.0.0.5'));

        $subscriber = new ProfilerAccessSubscriber(['192.168.1.1'], [], true, $logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.5');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelRequest($event);
    }

    public function testBlockedAccessIsNotLoggedWhenDisabled(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        // Expect no logging when disabled
        $logger->expects(self::never())
            ->method('info');

        $subscriber = new ProfilerAccessSubscriber(['192.168.1.1'], [], false, $logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.5');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelRequest($event);
    }

    public function testAllowedAccessIsNotLogged(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        // Expect no logging for allowed access
        $logger->expects(self::never())
            ->method('info');

        $subscriber = new ProfilerAccessSubscriber(['192.168.1.1'], [], true, $logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '192.168.1.1');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelRequest($event);
    }

    public function testLogMessageIncludesReverseHostname(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        // Expect reverse hostname in log message
        $logger->expects(self::once())
            ->method('info')
            ->with(self::matchesRegularExpression('/Profiler disabled for unauthorized IP .* \(reverse: .*\)/'));

        $subscriber = new ProfilerAccessSubscriber(['192.168.1.1'], [], true, $logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.5');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelRequest($event);
    }

    public function testLogMessageContainsReverseInformation(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        // Expect reverse hostname information to be included (whether it resolves or not)
        $logger->expects(self::once())
            ->method('info')
            ->with(self::matchesRegularExpression('/Profiler disabled for unauthorized IP .* \(reverse: .*\)/'));

        $subscriber = new ProfilerAccessSubscriber(['192.168.1.1'], [], true, $logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.5');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelRequest($event);
    }

    public function testBlockedAccessByHostPatternIsLogged(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        // Even if hostname pattern would allow, the IP doesn't - should be blocked and logged
        $logger->expects(self::once())
            ->method('info');

        $subscriber = new ProfilerAccessSubscriber([], ['*.example.com'], true, $logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.5');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelRequest($event);
    }

    public function testSubRequestIsNotLogged(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        // Sub-requests should not be logged
        $logger->expects(self::never())
            ->method('info');

        $subscriber = new ProfilerAccessSubscriber(['192.168.1.1'], [], true, $logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.5');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, 2); // SUB_REQUEST = 2

        $subscriber->onKernelRequest($event);
    }
}
