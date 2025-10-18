<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\EventSubscriber;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\KernelEvents;
use Zhortein\DevSecurityBundle\Attribute\RestrictedToDevWhitelist;

/**
 * Restricts access to routes marked with RestrictedToDevWhitelist attribute.
 *
 * This subscriber checks if a controller or action is marked with the RestrictedToDevWhitelist
 * attribute and enforces IP/hostname whitelist restrictions.
 */
final readonly class RestrictedAccessSubscriber implements EventSubscriberInterface
{
    /**
     * @param array<string> $allowedIps          List of allowed IPs or CIDR ranges
     * @param array<string> $allowedHostPatterns List of allowed hostname patterns
     */
    public function __construct(
        private array $allowedIps,
        private array $allowedHostPatterns,
        private bool $logBlockedAttempts,
        private LoggerInterface $logger,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::CONTROLLER => 'onKernelController',
        ];
    }

    public function onKernelController(ControllerEvent $event): void
    {
        $controller = $event->getController();
        if (is_array($controller)) {
            $controller = $controller[0];
        }

        if (!is_object($controller)) {
            return;
        }

        $reflection = new \ReflectionClass($controller);
        $classAttributes = $reflection->getAttributes(RestrictedToDevWhitelist::class);
        $methodAttributes = [];

        // Get method attributes if controller is callable
        if (method_exists($controller, '__invoke')) {
            $method = $reflection->getMethod('__invoke');
            $methodAttributes = $method->getAttributes(RestrictedToDevWhitelist::class);
        }

        $attributes = array_merge($classAttributes, $methodAttributes);

        if (empty($attributes)) {
            return;
        }

        $request = $event->getRequest();
        $clientIp = $request->getClientIp() ?? 'unknown';

        // Check IP and reverse DNS
        foreach ($this->allowedIps as $allowed) {
            if (IpUtils::checkIp($clientIp, $allowed)) {
                return;
            }
        }

        $reverse = @gethostbyaddr($clientIp) ?: null;
        if ($reverse) {
            foreach ($this->allowedHostPatterns as $pattern) {
                if (fnmatch($pattern, $reverse)) {
                    return;
                }
            }
        }

        // Access denied
        if ($this->logBlockedAttempts) {
            $this->logger->warning(sprintf(
                'Restricted route access denied for %s (reverse: %s)',
                $clientIp,
                $reverse ?: 'unknown'
            ));
        }

        throw new AccessDeniedHttpException('Access denied: this route is restricted to the developer whitelist.');
    }
}
