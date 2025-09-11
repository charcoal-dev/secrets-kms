<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Types;

/**
 * @api 32 bytes secret key
 */
final readonly class SecretKey32 extends AbstractSecretKey
{
    protected const int FixedLengthBytes = 32;
}