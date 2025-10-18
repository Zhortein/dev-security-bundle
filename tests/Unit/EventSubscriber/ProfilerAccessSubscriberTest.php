<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\Tests\Unit\EventSubscriber;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Zhortein\DevSecurityBundle\EventSubscriber\ProfilerAccessSubscriber;

final class ProfilerAccessSubscriberTest extends TestCase
{
    private LoggerInterface $logger;

    protected function setUp(): void
    {
        $this->logger = new NullLogger();
    }

    public function testSubscriberIsRegisteredForKernelRequestEvent(): void
    {
        $subscriber = new ProfilerAccessSubscriber([], [], false, $this->logger);
        $subscribedEvents = $subscriber::getSubscribedEvents();

        self::assertArrayHasKey(KernelEvents::REQUEST, $subscribedEvents);
        self::assertSame('onKernelRequest', $subscribedEvents[KernelEvents::REQUEST]);
    }

    public function testAllowedIpIsAuthorized(): void
    {
        $subscriber = new ProfilerAccessSubscriber(['192.168.1.1'], [], false, $this->logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '192.168.1.1');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        // Should not disable profiler
        $subscriber->onKernelRequest($event);

        self::assertFalse($request->attributes->has('_profiler'));
        self::assertFalse($request->attributes->has('_wdt'));
    }

    public function testDisallowedIpIsBlocked(): void
    {
        $subscriber = new ProfilerAccessSubscriber(['192.168.1.1'], [], false, $this->logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.5');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelRequest($event);

        self::assertTrue(false === $request->attributes->get('_profiler'));
        self::assertTrue(false === $request->attributes->get('_wdt'));
    }

    public function testCidrRangeIsAuthorized(): void
    {
        $subscriber = new ProfilerAccessSubscriber(['192.168.0.0/16'], [], false, $this->logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '192.168.45.100');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelRequest($event);

        self::assertFalse($request->attributes->has('_profiler'));
    }

    public function testLocalhostIsAuthorized(): void
    {
        $subscriber = new ProfilerAccessSubscriber(['127.0.0.1'], [], false, $this->logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelRequest($event);

        self::assertFalse($request->attributes->has('_profiler'));
    }

    public function testSubRequestIsIgnored(): void
    {
        $subscriber = new ProfilerAccessSubscriber([], [], false, $this->logger);
        $request = Request::create('/');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, 2); // SUB_REQUEST = 2

        $subscriber->onKernelRequest($event);

        self::assertFalse($request->attributes->has('_profiler'));
    }

    public function testUnknownClientIpIsBlocked(): void
    {
        $subscriber = new ProfilerAccessSubscriber(['127.0.0.1'], [], false, $this->logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '192.168.100.200');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelRequest($event);

        self::assertSame(false, $request->attributes->get('_profiler'));
        self::assertSame(false, $request->attributes->get('_wdt'));
    }

    public function testMultipleAllowedIps(): void
    {
        $subscriber = new ProfilerAccessSubscriber(
            ['192.168.1.1', '192.168.1.2', '10.0.0.1'],
            [],
            false,
            $this->logger
        );

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);

        // Test first IP
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '192.168.1.1');
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelRequest($event);
        self::assertFalse($request->attributes->has('_profiler'));

        // Test second IP
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '192.168.1.2');
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelRequest($event);
        self::assertFalse($request->attributes->has('_profiler'));

        // Test third IP
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');
        $event = new RequestEvent($kernel, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelRequest($event);
        self::assertFalse($request->attributes->has('_profiler'));
    }
}
