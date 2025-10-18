<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\EventSubscriber;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

final class ProfilerAccessSubscriber implements EventSubscriberInterface
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

        // Autorisation directe (IP/CIDR)
        foreach ($this->allowedIps as $allowed) {
            if (IpUtils::checkIp($clientIp, $allowed)) {
                return;
            }
        }

        // Reverse DNS autorisé ?
        $reverse = @gethostbyaddr($clientIp) ?: null;
        if ($reverse) {
            foreach ($this->allowedHostPatterns as $pattern) {
                if (fnmatch($pattern, $reverse)) {
                    return;
                }
            }
        }

        // Bloqué : désactive profiler et toolbar
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
