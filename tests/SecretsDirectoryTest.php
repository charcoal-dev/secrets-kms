<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Tests;

use Charcoal\Security\Secrets\Filesystem\SecretsDirectory;
use Charcoal\Security\Secrets\Tests\Fixtures\TestSecretsEnum;
use Charcoal\Security\Secrets\Types\SecretKey32;
use PHPUnit\Framework\TestCase;

/**
 * Class SecretsDirectoryTest
 * @package Charcoal\Security\Secrets\Tests
 */
final class SecretsDirectoryTest extends TestCase
{
    public function testExampleSecret(): void
    {
        $lfsDirectory = new SecretsDirectory(TestSecretsEnum::Example);
        $this->assertFalse($lfsDirectory->has("does_not_exist", 0));
        $this->assertFalse($lfsDirectory->has("some_secret", 0));
        $this->assertTrue($lfsDirectory->has("some_secret", 1));
    }

    public function testExampleSecretRead(): void
    {
        $exampleSecrets = new SecretsDirectory(TestSecretsEnum::Example);
        $someSecretKey = $exampleSecrets->load("some_secret", 1);
        $this->assertEquals("some_secret:00001", $someSecretKey->ref());
        $this->assertInstanceOf(SecretKey32::class, $someSecretKey);
        $someSecretKey->useSecretEntropy(function ($entropy) {
            $this->assertEquals("1234567890abcdefghijklmnopqrstuv", $entropy);
        });
    }

    public function testChildNamespace(): void
    {
        $exampleSecrets = new SecretsDirectory(TestSecretsEnum::Example);
        $child2 = $exampleSecrets->namespace("child1/child2");
        $this->assertFalse($child2->has("deep_secret", -786));
        $this->assertFalse($child2->has("deep_secret", 0));
        $this->assertFalse($child2->has("deep_secret", 785));

        $this->assertTrue($child2->has("deep_secret", 786));
        $deepSecret786 = $child2->load("deep_secret", 786);
        $this->assertEquals("deep_secret:00786", $deepSecret786->ref());
        $deepSecret786->useSecretEntropy(function ($entropy) {
            $this->assertEquals("abcdefghijklmnopqrstuvwxyz012345", $entropy);
        });
    }
}