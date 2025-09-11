<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Support;

use Charcoal\Contracts\Security\Secrets\SecretGeneratorInterface;

/**
 * PRNG (pseudo-random number generator) that uses random_bytes()
 */
final readonly class PrngEntropy32 implements SecretGeneratorInterface
{
    public static function size(): int
    {
        return 32;
    }

    /**
     * @return string
     * @throws \Random\RandomException
     */
    public static function generate(): string
    {
        return random_bytes(32);
    }
}

