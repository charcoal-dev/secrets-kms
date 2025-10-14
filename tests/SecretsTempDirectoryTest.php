<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Tests;

use Charcoal\Security\Secrets\Filesystem\SecretsDirectory;
use Charcoal\Security\Secrets\SecretsKms;
use Charcoal\Security\Secrets\Support\PrngEntropy32;
use Charcoal\Security\Secrets\Tests\Fixtures\TestSecretsEnum;
use Charcoal\Security\Secrets\Types\SecretKey32;
use PHPUnit\Framework\TestCase;

/**
 * Class SecretsTempDirectoryTest
 * Tests write, read, and delete operations in the temp directory
 * @package Charcoal\Security\Secrets\Tests
 */
final class SecretsTempDirectoryTest extends TestCase
{
    private SecretsDirectory $tempDirectory;
    private bool $originalAllowWrites;
    private bool $originalAllowDeletes;

    protected function setUp(): void
    {
        parent::setUp();

        // Save original flag states
        $this->originalAllowWrites = SecretsKms::$lfsAllowWrites;
        $this->originalAllowDeletes = SecretsKms::$lfsAllowDeletes;

        // Enable writes and deletes for testing
        SecretsKms::$lfsAllowWrites = true;
        SecretsKms::$lfsAllowDeletes = true;

        // Ensure temp directory exists
        $tempPath = __DIR__ . DIRECTORY_SEPARATOR . "Fixtures" . DIRECTORY_SEPARATOR . "Secrets" . DIRECTORY_SEPARATOR . "temp";
        if (!is_dir($tempPath)) {
            mkdir($tempPath, 0700, true);
        }

        $this->tempDirectory = new SecretsDirectory(TestSecretsEnum::Temp);
    }

    protected function tearDown(): void
    {
        // Restore original flag states
        SecretsKms::$lfsAllowWrites = $this->originalAllowWrites;
        SecretsKms::$lfsAllowDeletes = $this->originalAllowDeletes;

        parent::tearDown();
    }

    public function testStoreAndLoadSecret(): void
    {
        $secretId = "test_secret";
        $version = 1;

        // Store a new secret
        $this->tempDirectory->store(null, $secretId, $version, new PrngEntropy32());

        // Verify it exists
        $this->assertTrue($this->tempDirectory->has($secretId, $version));

        // Load and verify
        $loadedSecret = $this->tempDirectory->load($secretId, $version);
        $this->assertInstanceOf(SecretKey32::class, $loadedSecret);
        $this->assertEquals("test_secret:00001", $loadedSecret->ref());
        $this->assertEquals($secretId, $loadedSecret->id());
        $this->assertEquals($version, $loadedSecret->version());
        $this->assertEquals(32, $loadedSecret->length());

        // Verify entropy is 32 bytes
        $loadedSecret->useSecretEntropy(function (string $entropy) {
            $this->assertEquals(32, strlen($entropy));
        });

        // Clean up
        $this->tempDirectory->delete($secretId, $version, null);
        $this->assertFalse($this->tempDirectory->has($secretId, $version));
    }

    public function testStoreMultipleVersions(): void
    {
        $secretId = "versioned_secret";

        // Store multiple versions
        for ($version = 1; $version <= 3; $version++) {
            $this->tempDirectory->store(null, $secretId, $version, new PrngEntropy32());
        }

        // Verify-all versions exist
        $this->assertTrue($this->tempDirectory->has($secretId, 1));
        $this->assertTrue($this->tempDirectory->has($secretId, 2));
        $this->assertTrue($this->tempDirectory->has($secretId, 3));
        $this->assertFalse($this->tempDirectory->has($secretId, 4));

        // Load each version
        $secret1 = $this->tempDirectory->load($secretId, 1);
        $secret2 = $this->tempDirectory->load($secretId, 2);
        $secret3 = $this->tempDirectory->load($secretId, 3);

        $this->assertEquals("versioned_secret:00001", $secret1->ref());
        $this->assertEquals("versioned_secret:00002", $secret2->ref());
        $this->assertEquals("versioned_secret:00003", $secret3->ref());

        // Verify each version has different entropy
        $entropy1 = null;
        $entropy2 = null;
        $entropy3 = null;

        $secret1->useSecretEntropy(function (string $e) use (&$entropy1) {
            $entropy1 = $e;
        });

        $secret2->useSecretEntropy(function (string $e) use (&$entropy2) {
            $entropy2 = $e;
        });

        $secret3->useSecretEntropy(function (string $e) use (&$entropy3) {
            $entropy3 = $e;
        });

        $this->assertNotEquals($entropy1, $entropy2);
        $this->assertNotEquals($entropy2, $entropy3);
        $this->assertNotEquals($entropy1, $entropy3);

        // Clean up all versions
        $this->tempDirectory->delete($secretId, 1, null);
        $this->tempDirectory->delete($secretId, 2, null);
        $this->tempDirectory->delete($secretId, 3, null);

        $this->assertFalse($this->tempDirectory->has($secretId, 1));
        $this->assertFalse($this->tempDirectory->has($secretId, 2));
        $this->assertFalse($this->tempDirectory->has($secretId, 3));
    }

    public function testStoreInNamespace(): void
    {
        $secretId = "namespaced_secret";
        $version = 1;

        // Create namespace
        $namespace = $this->tempDirectory->namespace("level1");

        // Store secret in namespace
        $this->tempDirectory->store($namespace, $secretId, $version, new PrngEntropy32());

        // Verify it exists in namespace
        $this->assertTrue($this->tempDirectory->has($secretId, $version, $namespace));
        $this->assertFalse($this->tempDirectory->has($secretId, $version, null));

        // Load from namespace
        $loadedSecret = $this->tempDirectory->load($secretId, $version, $namespace);
        $this->assertEquals("namespaced_secret:00001", $loadedSecret->ref());

        // Clean up
        $this->tempDirectory->delete($secretId, $version, $namespace);
        $this->assertFalse($this->tempDirectory->has($secretId, $version, $namespace));
    }

    public function testStoreInDeepNamespace(): void
    {
        $secretId = "deep_secret";
        $version = 100;

        // Create deep namespace
        $deepNamespace = $this->tempDirectory->namespace("level1/level2/level3");

        // Store secret in deep namespace
        $this->tempDirectory->store($deepNamespace, $secretId, $version, new PrngEntropy32());

        // Verify it exists
        $this->assertTrue($this->tempDirectory->has($secretId, $version, $deepNamespace));

        // Load and verify
        $loadedSecret = $this->tempDirectory->load($secretId, $version, $deepNamespace);
        $this->assertEquals("deep_secret:00100", $loadedSecret->ref());
        $this->assertEquals(100, $loadedSecret->version());

        // Clean up
        $this->tempDirectory->delete($secretId, $version, $deepNamespace);
        $this->assertFalse($this->tempDirectory->has($secretId, $version, $deepNamespace));
    }

    public function testDeleteNonExistentSecret(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->tempDirectory->delete("does_not_exist", 999, null);
    }

    public function testLoadNonExistentSecret(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->tempDirectory->load("does_not_exist", 999);
    }

    public function testStoreWithWritesDisabled(): void
    {
        SecretsKms::$lfsAllowWrites = false;

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Secrets writing are disabled from SecretsKms");

        $this->tempDirectory->store(null, "test", 1, new PrngEntropy32());
    }

    public function testDeleteWithDeletesDisabled(): void
    {
        // First, store a secret
        $secretId = "secret_to_delete";
        $version = 1;

        // Clean up if exists from previous run
        if ($this->tempDirectory->has($secretId, $version)) {
            $this->tempDirectory->delete($secretId, $version, null);
        }

        $this->tempDirectory->store(null, $secretId, $version, new PrngEntropy32());

        // Disable deletes
        SecretsKms::$lfsAllowDeletes = false;

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Secrets deletes are disabled from SecretsKms");

        try {
            $this->tempDirectory->delete($secretId, $version, null);
        } finally {
            // Clean up (re-enable deletes first)
            SecretsKms::$lfsAllowDeletes = true;
            $this->tempDirectory->delete($secretId, $version, null);
        }
    }

    public function testStoreOverwriteProhibited(): void
    {
        $secretId = "no_overwrite";
        $version = 1;

        // Store initial secret
        $this->tempDirectory->store(null, $secretId, $version, new PrngEntropy32());

        // Try to overwrite - should fail
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Overwrites prohibited");

        try {
            $this->tempDirectory->store(null, $secretId, $version, new PrngEntropy32());
        } finally {
            // Clean up
            $this->tempDirectory->delete($secretId, $version, null);
        }
    }

    public function testHighVersionNumber(): void
    {
        $secretId = "high_version";
        $version = 65534;

        // Store with high version number
        $this->tempDirectory->store(null, $secretId, $version, new PrngEntropy32());

        // Verify
        $this->assertTrue($this->tempDirectory->has($secretId, $version));
        $loadedSecret = $this->tempDirectory->load($secretId, $version);
        $this->assertEquals("high_version:65534", $loadedSecret->ref());

        // Clean up
        $this->tempDirectory->delete($secretId, $version, null);
    }

    public function testSecretIdFormats(): void
    {
        $validIds = [
            "secret123",
            "secret-name",
            "secret_name",
            "My-Secret_123",
            "test0",
            "ValidName99",
        ];

        // Clean up all potential leftover files first
        foreach ($validIds as $index => $secretId) {
            $version = $index + 1;
            try {
                $this->tempDirectory->delete($secretId, $version, null);
                clearstatcache(true);
            } catch (\Throwable) {
            }
        }

        foreach ($validIds as $index => $secretId) {
            $version = $index + 1;

            $this->tempDirectory->store(null, $secretId, $version, new PrngEntropy32());
            $this->assertTrue($this->tempDirectory->has($secretId, $version));
            $this->tempDirectory->delete($secretId, $version, null);
            clearstatcache(true);
        }

        $this->assertTrue(true); // All valid IDs passed
    }

    public function testMetaId(): void
    {
        $this->assertEquals("Temp", $this->tempDirectory->metaId());
    }

    public function testNamespaceReusability(): void
    {
        // Create same namespace multiple times
        $ns1 = $this->tempDirectory->namespace("reusable");
        $ns2 = $this->tempDirectory->namespace("reusable");

        // Store in first namespace instance
        $this->tempDirectory->store($ns1, "test1", 1, new PrngEntropy32());

        // Should be accessible from second namespace instance
        $this->assertTrue($this->tempDirectory->has("test1", 1, $ns2));

        // Load from second instance
        $secret = $this->tempDirectory->load("test1", 1, $ns2);
        $this->assertEquals("test1:00001", $secret->ref());

        // Clean up
        $this->tempDirectory->delete("test1", 1, $ns1);
    }
}