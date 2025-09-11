<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Types;

/**
 * @api 20 bytes secret key
 */
final readonly class SecretKey20 extends AbstractKeyBuffer
{
    protected const int FixedLengthBytes = 20;
}