<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Tests\Fixtures;

use Charcoal\Contracts\Security\Secrets\SecretsUtilityInterface;

/**
 * A class that implements SecretsUtilityInterface
 */
class SecretConsumer implements SecretsUtilityInterface
{
    public function readSecret(string $entropy): string
    {
        return base64_encode($entropy);
    }
}