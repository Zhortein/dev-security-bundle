<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

/**
 * Loads and manages bundle configuration.
 */
class ZhorteinDevSecurityBundleExtension extends Extension
{
    /**
     * @param array<string, mixed> $configs
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        // If the bundle isn't activated, stop here
        if (!($config['enabled'] ?? true)) {
            return;
        }

        // Inject global parameters
        $container->setParameter('zhortein_dev_security.allowed_ips', $config['allowed_ips']);
        $container->setParameter('zhortein_dev_security.allowed_hosts', $config['allowed_hosts']);
        $container->setParameter('zhortein_dev_security.log_blocked_attempts', $config['log_blocked_attempts']);

        // Load services configuration
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../../config'));
        $loader->load('services.yaml');
    }

    public function getAlias(): string
    {
        // Allow short name usage in yaml config files (e.g. zhortein_dev_security: { ... })
        return 'zhortein_dev_security';
    }
}
