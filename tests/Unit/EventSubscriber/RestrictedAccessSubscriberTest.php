<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\Tests\Unit\EventSubscriber;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\KernelEvents;
use Zhortein\DevSecurityBundle\Attribute\RestrictedToDevWhitelist;
use Zhortein\DevSecurityBundle\EventSubscriber\RestrictedAccessSubscriber;

final class RestrictedAccessSubscriberTest extends TestCase
{
    private LoggerInterface $logger;

    protected function setUp(): void
    {
        $this->logger = new NullLogger();
    }

    public function testSubscriberIsRegisteredForKernelControllerEvent(): void
    {
        $subscriber = new RestrictedAccessSubscriber([], [], false, $this->logger);
        $subscribedEvents = $subscriber::getSubscribedEvents();

        self::assertArrayHasKey(KernelEvents::CONTROLLER, $subscribedEvents);
        self::assertSame('onKernelController', $subscribedEvents[KernelEvents::CONTROLLER]);
    }

    public function testControllerWithoutAttributeIsAllowed(): void
    {
        $this->expectNotToPerformAssertions();

        $subscriber = new RestrictedAccessSubscriber(['127.0.0.1'], [], false, $this->logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $controller = new class {};
        $event = new ControllerEvent($kernel, fn () => null, $request, 1); // MAIN_REQUEST = 1

        // Should not throw
        $subscriber->onKernelController($event);
    }

    public function testAllowedIpCanAccessRestrictedRoute(): void
    {
        $this->expectNotToPerformAssertions();

        $subscriber = new RestrictedAccessSubscriber(['127.0.0.1'], [], false, $this->logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $controller = new RestrictedControllerStub();
        $event = new ControllerEvent($kernel, $controller, $request, 1); // MAIN_REQUEST = 1

        // Should not throw
        $subscriber->onKernelController($event);
    }

    public function testDisallowedIpIsBlockedFromRestrictedRoute(): void
    {
        $subscriber = new RestrictedAccessSubscriber(['127.0.0.1'], [], false, $this->logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '192.168.1.100');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $controller = new RestrictedControllerStub();
        $event = new ControllerEvent($kernel, $controller, $request, 1); // MAIN_REQUEST = 1

        $this->expectException(AccessDeniedHttpException::class);
        $subscriber->onKernelController($event);
    }

    public function testCidrRangeAllowsAccess(): void
    {
        $this->expectNotToPerformAssertions();

        $subscriber = new RestrictedAccessSubscriber(['10.0.0.0/8'], [], false, $this->logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.100.50.5');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $controller = new RestrictedControllerStub();
        $event = new ControllerEvent($kernel, $controller, $request, 1); // MAIN_REQUEST = 1

        $subscriber->onKernelController($event);
    }

    public function testArrayControllerNotationIsHandled(): void
    {
        $subscriber = new RestrictedAccessSubscriber(['127.0.0.1'], [], false, $this->logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '192.168.1.100');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $controller = [new RestrictedControllerStub(), '__invoke'];
        $event = new ControllerEvent($kernel, $controller, $request, 1); // MAIN_REQUEST = 1

        $this->expectException(AccessDeniedHttpException::class);
        $subscriber->onKernelController($event);
    }

    public function testCallableWithoutObjectIsIgnored(): void
    {
        $this->expectNotToPerformAssertions();

        $subscriber = new RestrictedAccessSubscriber(['127.0.0.1'], [], false, $this->logger);
        $request = Request::create('/');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new ControllerEvent($kernel, 'strlen', $request, 1); // MAIN_REQUEST = 1

        // Should not throw
        $subscriber->onKernelController($event);
    }

    public function testAccessDeniedMessageIsAccurate(): void
    {
        $subscriber = new RestrictedAccessSubscriber(['127.0.0.1'], [], false, $this->logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '192.168.1.100');

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $controller = new RestrictedControllerStub();
        $event = new ControllerEvent($kernel, $controller, $request, 1); // MAIN_REQUEST = 1

        try {
            $subscriber->onKernelController($event);
            self::fail('AccessDeniedHttpException should be thrown');
        } catch (AccessDeniedHttpException $e) {
            self::assertStringContainsString('restricted to the developer whitelist', $e->getMessage());
        }
    }
}

#[RestrictedToDevWhitelist]
final class RestrictedControllerStub
{
    #[RestrictedToDevWhitelist]
    public function __invoke(): void
    {
    }
}
