<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\Tests;

use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel as BaseKernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Zhortein\DevSecurityBundle\ZhorteinDevSecurityBundle;

/**
 * Test kernel for integration tests.
 */
class Kernel extends BaseKernel
{
    use MicroKernelTrait;

    public function registerBundles(): iterable
    {
        return [
            new FrameworkBundle(),
            new ZhorteinDevSecurityBundle(),
        ];
    }

    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $loader->load(__DIR__.'/config/test.yaml');
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        // No routes needed for testing
    }

    public function getProjectDir(): string
    {
        return \dirname(__DIR__);
    }
}
