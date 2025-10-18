<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\EventSubscriber;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Restricts access to Symfony Profiler and Web Debug Toolbar based on whitelist configuration.
 *
 * This subscriber disables the profiler and Web Debug Toolbar for requests from
 * unauthorized IPs or hostnames, protecting sensitive debugging information.
 */
final readonly class ProfilerAccessSubscriber implements EventSubscriberInterface
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
            KernelEvents::REQUEST => 'onKernelRequest',
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $clientIp = $request->getClientIp() ?? 'unknown';

        // Direct IP/CIDR authorization
        foreach ($this->allowedIps as $allowed) {
            if (IpUtils::checkIp($clientIp, $allowed)) {
                return;
            }
        }

        // Reverse DNS check
        $reverse = @gethostbyaddr($clientIp) ?: null;
        if ($reverse) {
            foreach ($this->allowedHostPatterns as $pattern) {
                if (fnmatch($pattern, $reverse)) {
                    return;
                }
            }
        }

        // Blocked: disable profiler and web debug toolbar
        $request->attributes->set('_profiler', false);
        $request->attributes->set('_wdt', false);

        if ($this->logBlockedAttempts) {
            $this->logger->info(sprintf(
                'Profiler disabled for unauthorized IP %s (reverse: %s)',
                $clientIp,
                $reverse ?: 'unknown'
            ));
        }
    }
}
