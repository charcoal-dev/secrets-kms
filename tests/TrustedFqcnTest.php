<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Tests;

use Charcoal\Security\Secrets\Config\TrustedFqcn;
use Charcoal\Security\Secrets\SecretsNamespace;
use Charcoal\Security\Secrets\Tests\Fixtures\SecretConsumer;
use PHPUnit\Framework\TestCase;

/**
 * This class contains test cases for the TrustedFqcn class, which is used
 * to validate and manage Fully Qualified Class Names (FQCNs) for utility
 * classes and namespace contracts.
 */
class TrustedFqcnTest extends TestCase
{
    public function testConstructorWithValidFqcn(): void
    {
        $utilityClasses = [SecretConsumer::class, "DateTime"];
        $namespaceContracts = [SecretsNamespace::class];

        $trustedFqcn = new TrustedFqcn($utilityClasses, $namespaceContracts);
        /** @noinspection PhpConditionAlreadyCheckedInspection */
        $this->assertInstanceOf(TrustedFqcn::class, $trustedFqcn);
    }

    public function testConstructorWithEmptyArrays(): void
    {
        $trustedFqcn = new TrustedFqcn([], []);
        /** @noinspection PhpConditionAlreadyCheckedInspection */
        $this->assertInstanceOf(TrustedFqcn::class, $trustedFqcn);
    }

    public function testConstructorThrowsExceptionForNonStringFqcn(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage("Invalid trusted FQCN");

        new TrustedFqcn([123], []);
    }

    public function testConstructorThrowsExceptionForEmptyStringFqcn(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage("Invalid trusted FQCN");

        new TrustedFqcn([""], []);
    }

    public function testConstructorThrowsExceptionForNonExistentClass(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage("Invalid trusted FQCN");

        new TrustedFqcn(["NonExistentClass"], []);
    }

    public function testCanUtilizeSecretsWithRegisteredClass(): void
    {
        $trustedFqcn = new TrustedFqcn([SecretConsumer::class, "DateTime"], [SecretsNamespace::class]);

        $this->assertTrue($trustedFqcn->canUtilizeSecrets(SecretConsumer::class));
        $this->assertTrue($trustedFqcn->canUtilizeSecrets("DateTime"));
    }

    public function testCanUtilizeSecretsWithUnregisteredClass(): void
    {
        $trustedFqcn = new TrustedFqcn([SecretConsumer::class], [SecretsNamespace::class]);

        $this->assertFalse($trustedFqcn->canUtilizeSecrets("DateTime"));
        $this->assertFalse($trustedFqcn->canUtilizeSecrets("stdClass"));
    }

    public function testCanUtilizeSecretsWithObjectInstance(): void
    {
        $trustedFqcn = new TrustedFqcn([SecretConsumer::class, "DateTime"], [SecretsNamespace::class]);

        $secretConsumerObj = new SecretConsumer();
        $dateTimeObj = new \DateTime();
        $stdClassObj = new \stdClass();

        $this->assertTrue($trustedFqcn->canUtilizeSecrets($secretConsumerObj));
        $this->assertTrue($trustedFqcn->canUtilizeSecrets($dateTimeObj));
        $this->assertFalse($trustedFqcn->canUtilizeSecrets($stdClassObj));
    }

    public function testIsValidNamespaceWithSecretsNamespace(): void
    {
        $trustedFqcn = new TrustedFqcn([SecretConsumer::class], [SecretsNamespace::class]);

        $this->assertTrue($trustedFqcn->isValidNamespace(SecretsNamespace::class));
    }

    public function testIsValidNamespaceWithUnregisteredClass(): void
    {
        $trustedFqcn = new TrustedFqcn([SecretConsumer::class], [SecretsNamespace::class]);

        $this->assertFalse($trustedFqcn->isValidNamespace(SecretConsumer::class));
        $this->assertFalse($trustedFqcn->isValidNamespace("stdClass"));
        $this->assertFalse($trustedFqcn->isValidNamespace("ArrayObject"));
    }

    public function testIsValidNamespaceWithEmptyNamespaceContracts(): void
    {
        $trustedFqcn = new TrustedFqcn([SecretConsumer::class], []);

        $this->assertFalse($trustedFqcn->isValidNamespace(SecretsNamespace::class));
    }

    public function testCrossMethodChecking(): void
    {
        $trustedFqcn = new TrustedFqcn([SecretConsumer::class], [SecretsNamespace::class]);

        // Utility class should not be valid namespace
        $this->assertFalse($trustedFqcn->isValidNamespace(SecretConsumer::class));

        // Namespace class should not be able to use secrets
        $this->assertFalse($trustedFqcn->canUtilizeSecrets(SecretsNamespace::class));
    }

    public function testInspectWithEmptyArrays(): void
    {
        $trustedFqcn = new TrustedFqcn([], []);

        $result = $trustedFqcn->inspect();

        $this->assertIsArray($result);
        $this->assertArrayHasKey("secretsUtilityClasses", $result);
        $this->assertArrayHasKey("secretsNamespaceContracts", $result);
        $this->assertEquals("", $result["secretsUtilityClasses"]);
        $this->assertEquals("", $result["secretsNamespaceContracts"]);
    }

    public function testInspectWithRegisteredClasses(): void
    {
        $trustedFqcn = new TrustedFqcn([SecretConsumer::class], [SecretsNamespace::class]);

        $result = $trustedFqcn->inspect();

        $this->assertEquals(SecretConsumer::class, $result["secretsUtilityClasses"]);
        $this->assertEquals(SecretsNamespace::class, $result["secretsNamespaceContracts"]);
    }

    public function testInspectWithMultipleUtilityClasses(): void
    {
        $trustedFqcn = new TrustedFqcn(
            [SecretConsumer::class, "DateTime", "Exception"],
            [SecretsNamespace::class]
        );

        $result = $trustedFqcn->inspect();

        $expectedUtility = SecretConsumer::class . ", DateTime, Exception";
        $this->assertEquals($expectedUtility, $result["secretsUtilityClasses"]);
        $this->assertEquals(SecretsNamespace::class, $result["secretsNamespaceContracts"]);
    }

    public function testDuplicateFqcnInConstructor(): void
    {
        $trustedFqcn = new TrustedFqcn(
            [SecretConsumer::class, SecretConsumer::class, "DateTime"],
            [SecretsNamespace::class]
        );

        // Should still work, duplicates should be handled
        $this->assertTrue($trustedFqcn->canUtilizeSecrets(SecretConsumer::class));
        $this->assertTrue($trustedFqcn->canUtilizeSecrets("DateTime"));
        $this->assertTrue($trustedFqcn->isValidNamespace(SecretsNamespace::class));
    }

    public function testCaseSensitivity(): void
    {
        $trustedFqcn = new TrustedFqcn([SecretConsumer::class], [SecretsNamespace::class]);

        $this->assertTrue($trustedFqcn->canUtilizeSecrets(SecretConsumer::class));
        $this->assertTrue($trustedFqcn->isValidNamespace(SecretsNamespace::class));

        // Test with a lowercase version of the class names - should be false
        $lowercaseUtility = strtolower(SecretConsumer::class);
        $lowercaseNamespace = strtolower(SecretsNamespace::class);

        $this->assertFalse($trustedFqcn->canUtilizeSecrets($lowercaseUtility));
        $this->assertFalse($trustedFqcn->isValidNamespace($lowercaseNamespace));
    }
}