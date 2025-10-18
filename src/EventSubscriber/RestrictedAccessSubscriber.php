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

final class RestrictedAccessSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly array $allowedIps,
        private readonly array $allowedHostPatterns,
        private readonly bool $logBlockedAttempts,
        private readonly LoggerInterface $logger
    ) {}

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

        $reflection = new \ReflectionClass($controller);
        $attributes = array_merge(
            $reflection->getAttributes(RestrictedToDevWhitelist::class),
            $event->getControllerAttributes(RestrictedToDevWhitelist::class)
        );

        if (empty($attributes)) {
            return;
        }

        $request = $event->getRequest();
        $clientIp = $request->getClientIp() ?? 'unknown';

        // Vérification IP et reverse
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

        // Refus
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
