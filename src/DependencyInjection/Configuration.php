<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Configuration structure for ZhorteinDevSecurityBundle.
 *
 * This defines the options available under `zhortein_dev_security` in YAML configs.
 */
class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('zhortein_dev_security');
        $rootNode = $treeBuilder->getRootNode();

        $rootNode
            ->children()
            ->booleanNode('enabled')
            ->defaultTrue()
            ->info('Enable or disable the Dev Security protection globally.')
            ->end()

            ->arrayNode('allowed_ips')
            ->info('List of IPs or CIDR ranges allowed to access Symfony debug tools.')
            ->example(['127.0.0.1', '::1', '192.168.1.0/24'])
            ->scalarPrototype()->end()
            ->defaultValue(['127.0.0.1', '::1', 'localhost'])
            ->end()

            ->arrayNode('allowed_hosts')
            ->info('List of reverse DNS patterns allowed to access Symfony debug tools (supports wildcards).')
            ->example(['*.mycompany.com', 'mybox.myinternetprovider.com'])
            ->scalarPrototype()->end()
            ->defaultValue([])
            ->end()

            ->booleanNode('log_blocked_attempts')
            ->defaultTrue()
            ->info('If true, each blocked IP will be logged for auditing purposes.')
            ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
