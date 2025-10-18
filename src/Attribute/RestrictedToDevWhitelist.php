<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\Attribute;

/**
 * Attribute to restrict a controller or action
 * to the developer whitelist defined in bundle config.
 *
 * Example:
 * #[RestrictedToDevWhitelist]
 * public function debugInfo(): Response { ... }
 */
#[\Attribute(\Attribute::TARGET_METHOD | \Attribute::TARGET_CLASS)]
final class RestrictedToDevWhitelist
{
}
