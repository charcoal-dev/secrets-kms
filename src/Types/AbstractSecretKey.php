<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Types;

use Charcoal\Base\Support\ErrorHelper;
use Charcoal\Contracts\Buffers\ByteArrayInterface;
use Charcoal\Contracts\Buffers\Sensitive\SensitiveKeyBufferInterface;
use Charcoal\Contracts\Security\Secrets\SecretKeyInterface;
use Charcoal\Contracts\Security\Secrets\SecretStorageInterface;
use Charcoal\Contracts\Security\Secrets\SecretsUtilityInterface;
use Charcoal\Security\Secrets\SecretsKms;
use Charcoal\Security\Secrets\Traits\SensitiveBufferTrait;

/**
 * An abstraction of secret key buffer
 */
abstract readonly class AbstractSecretKey implements ByteArrayInterface,
    SensitiveKeyBufferInterface,
    SecretKeyInterface
{
    use SensitiveBufferTrait;

    protected const int FixedLengthBytes = 0;

    final public function __construct(
        private SecretStorageInterface $storage,
        private string                 $ref,
        private int                    $version,
        #[\SensitiveParameter]
        private false|string           $entropy
    )
    {
        if (!static::FixedLengthBytes || !in_array(static::FixedLengthBytes, SecretsKms::SECRET_KEY_BUFFERS, true)) {
            throw new \LogicException("Invalid secret byte length");
        }

        if (!$this->entropy) {
            throw new \RuntimeException("Failed to read entropy bytes",
                previous: ErrorHelper::lastErrorToRuntimeException());
        }

        // Validate Entropy
        if (strlen($this->entropy) !== static::FixedLengthBytes) {
            throw new \LengthException(sprintf("Entropy must be %d bytes", static::FixedLengthBytes));
        }

        if (!SecretsKms::SECRET_ENTROPY_NULL_PADDING) {
            if (str_starts_with($this->entropy, "\0") || str_ends_with($this->entropy, "\0")) {
                throw new \InvalidArgumentException("Entropy must not be null padded");
            }
        }
    }

    final public function length(): int
    {
        return static::FixedLengthBytes;
    }

    final public function ref(): string
    {
        return sprintf("%s:%05d", $this->ref, $this->version);
    }

    final public function id(): string
    {
        return $this->ref;
    }

    final public function version(): int
    {
        return $this->version;
    }

    final public function requestSecret(
        SecretsUtilityInterface $class,
        \Closure                $callback
    ): mixed
    {
        // Validate FQCN of secret requester/utilizer
        if (!$this->storage->trustedFqcn()->canUtilizeSecrets($class)) {
            throw new \DomainException("Cannot utilize secrets from class: " . $class::class);
        }

        return $class->handleSecretEntropy($callback($this->entropy));
    }
}