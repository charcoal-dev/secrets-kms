<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Traits;

use Charcoal\Contracts\Buffers\ByteArrayInterface;
use Charcoal\Contracts\Encoding\EncodingSchemeInterface;

/**
 *  A trait that disabled all methods of the sensitive buffer.
 */
trait SensitiveBufferTrait
{
    public static function decode(EncodingSchemeInterface $scheme, string $data): never
    {
        throw new \DomainException("Static constructor not available for secret key");
    }

    public function bytes(): never
    {
        throw new \DomainException("Sensitive buffer cannot be read or serialized");
    }

    public function encode(): never
    {
        throw new \DomainException("Sensitive buffer cannot be read or serialized");
    }

    public function __toString(): never
    {
        throw new \DomainException("Sensitive buffer cannot be read or serialized");
    }

    public static function __set_state(array $in): never
    {
        throw new \DomainException("Sensitive buffer cannot be read or serialized");
    }

    public function __sleep(): never
    {
        throw new \DomainException("Sensitive buffer cannot be read or serialized");
    }

    public function __wakeup(): never
    {
        throw new \DomainException("Sensitive buffer cannot be read or serialized");
    }

    public function serialize(): never
    {
        throw new \DomainException("Sensitive buffer cannot be read or serialized");
    }

    public function unserialize(string $data): never
    {
        throw new \DomainException("Sensitive buffer cannot be read or serialized");
    }

    public function __serialize(): never
    {
        throw new \DomainException("Sensitive buffer cannot be read or serialized");
    }

    public function __unserialize(array $data): never
    {
        throw new \DomainException("Sensitive buffer cannot be read or serialized");
    }

    public function __clone(): never
    {
        throw new \DomainException("Sensitive buffer cannot be read or serialized");
    }

    public function __debugInfo(): never
    {
        throw new \DomainException("Sensitive buffer cannot be read or serialized");
    }

    public function equals(ByteArrayInterface|string $b): never
    {
        throw new \DomainException("Sensitive buffer cannot be read or serialized");
    }
}