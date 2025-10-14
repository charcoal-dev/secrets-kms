<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Enums;

use Charcoal\Contracts\Security\Secrets\SecretKeyInterface;
use Charcoal\Security\Secrets\Types\SecretKey16;
use Charcoal\Security\Secrets\Types\SecretKey20;
use Charcoal\Security\Secrets\Types\SecretKey24;
use Charcoal\Security\Secrets\Types\SecretKey32;
use Charcoal\Security\Secrets\Types\SecretKey40;
use Charcoal\Security\Secrets\Types\SecretKey64;

/**
 * Key Types
 */
enum KeySize: int
{
    case Bytes16 = 16;
    case Bytes20 = 20;
    case Bytes24 = 24;
    case Bytes32 = 32;
    case Bytes40 = 40;
    case Bytes64 = 64;

    /**
     * Returns the type of the secret key.
     * @return class-string<SecretKeyInterface>
     */
    public function getTypeFqcn(): string
    {
        return match ($this) {
            self::Bytes16 => SecretKey16::class,
            self::Bytes20 => SecretKey20::class,
            self::Bytes24 => SecretKey24::class,
            self::Bytes32 => SecretKey32::class,
            self::Bytes40 => SecretKey40::class,
            self::Bytes64 => SecretKey64::class,
            default => throw new \RuntimeException("No secret buffer available for: " . $this->name),
        };
    }
}