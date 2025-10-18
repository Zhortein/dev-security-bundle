<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\Tests\Unit\EventSubscriber;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Zhortein\DevSecurityBundle\Attribute\RestrictedToDevWhitelist;
use Zhortein\DevSecurityBundle\EventSubscriber\RestrictedAccessSubscriber;

#[RestrictedToDevWhitelist]
final class RestrictedController
{
    public function __invoke(): void
    {
    }
}

final class RestrictedAccessSubscriberLoggingTest extends TestCase
{
    public function testDeniedAccessIsLoggedAtWarningLevel(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        // Expect warning() to be called once with the denied IP
        $logger->expects(self::once())
            ->method('warning')
            ->with(self::stringContains('Restricted route access denied for 10.0.0.5'));

        $subscriber = new RestrictedAccessSubscriber(['192.168.1.1'], [], true, $logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.5');

        $controller = new RestrictedController();
        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new ControllerEvent($kernel, $controller, $request, 1); // MAIN_REQUEST = 1

        self::expectException(AccessDeniedHttpException::class);
        $subscriber->onKernelController($event);
    }

    public function testDeniedAccessIsNotLoggedWhenDisabled(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        // Expect no logging when disabled
        $logger->expects(self::never())
            ->method('warning');

        $subscriber = new RestrictedAccessSubscriber(['192.168.1.1'], [], false, $logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.5');

        $controller = new RestrictedController();
        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new ControllerEvent($kernel, $controller, $request, 1); // MAIN_REQUEST = 1

        self::expectException(AccessDeniedHttpException::class);
        $subscriber->onKernelController($event);
    }

    public function testAllowedAccessIsNotLogged(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        // Expect no logging for allowed access
        $logger->expects(self::never())
            ->method('warning');

        $subscriber = new RestrictedAccessSubscriber(['192.168.1.1'], [], true, $logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '192.168.1.1');

        $controller = new RestrictedController();
        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new ControllerEvent($kernel, $controller, $request, 1); // MAIN_REQUEST = 1

        // Should not throw
        $subscriber->onKernelController($event);
    }

    public function testLogMessageIncludesReverseHostname(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        // Expect reverse hostname in log message
        $logger->expects(self::once())
            ->method('warning')
            ->with(self::matchesRegularExpression('/Restricted route access denied for .* \(reverse: .*\)/'));

        $subscriber = new RestrictedAccessSubscriber(['192.168.1.1'], [], true, $logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.5');

        $controller = new RestrictedController();
        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new ControllerEvent($kernel, $controller, $request, 1); // MAIN_REQUEST = 1

        self::expectException(AccessDeniedHttpException::class);
        $subscriber->onKernelController($event);
    }

    public function testLogMessageContainsReverseHostname(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        // Expect reverse hostname information to be included (whether it resolves or not)
        $logger->expects(self::once())
            ->method('warning')
            ->with(self::matchesRegularExpression('/Restricted route access denied for .* \(reverse: .*\)/'));

        $subscriber = new RestrictedAccessSubscriber(['192.168.1.1'], [], true, $logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.5');

        $controller = new RestrictedController();
        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new ControllerEvent($kernel, $controller, $request, 1); // MAIN_REQUEST = 1

        self::expectException(AccessDeniedHttpException::class);
        $subscriber->onKernelController($event);
    }

    public function testUnrestrictedControllerIsNotLogged(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        // Unattributed controllers should not be logged even from blocked IPs
        $logger->expects(self::never())
            ->method('warning');

        $subscriber = new RestrictedAccessSubscriber(['192.168.1.1'], [], true, $logger);
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.5');

        // Create an unrestricted controller (no attribute)
        $controller = new class {
            public function __invoke(): void
            {
            }
        };

        $kernel = $this->createMock(\Symfony\Component\HttpKernel\HttpKernelInterface::class);
        $event = new ControllerEvent($kernel, $controller, $request, 1); // MAIN_REQUEST = 1

        // Should not throw or log
        $subscriber->onKernelController($event);
    }
}
