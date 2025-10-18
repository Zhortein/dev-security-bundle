<?php

declare(strict_types=1);

namespace Zhortein\DevSecurityBundle\Tests\Unit\Attribute;

use PHPUnit\Framework\TestCase;
use Zhortein\DevSecurityBundle\Attribute\RestrictedToDevWhitelist;

final class RestrictedToDevWhitelistTest extends TestCase
{
    public function testAttributeCanBeInstantiated(): void
    {
        $attribute = new RestrictedToDevWhitelist();

        self::assertInstanceOf(RestrictedToDevWhitelist::class, $attribute);
    }

    public function testAttributeIsMarkedAsTarget(): void
    {
        $reflection = new \ReflectionClass(RestrictedToDevWhitelist::class);

        self::assertTrue($reflection->isUserDefined());
    }

    public function testAttributeCanBeAppliedToClass(): void
    {
        $reflection = new \ReflectionClass(RestrictedToDevWhitelistStub::class);
        $attributes = $reflection->getAttributes(RestrictedToDevWhitelist::class);

        self::assertCount(1, $attributes);
    }

    public function testAttributeCanBeAppliedToMethod(): void
    {
        $reflection = new \ReflectionClass(RestrictedToDevWhitelistStub::class);
        $method = $reflection->getMethod('__invoke');
        $attributes = $method->getAttributes(RestrictedToDevWhitelist::class);

        self::assertCount(1, $attributes);
    }
}

#[RestrictedToDevWhitelist]
final class RestrictedToDevWhitelistStub
{
    #[RestrictedToDevWhitelist]
    public function __invoke(): void
    {
    }
}
