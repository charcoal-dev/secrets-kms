<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Tests\Fixtures;

use Charcoal\Security\Secrets\Contracts\SecretsProviderEnumInterface;
use Charcoal\Security\Secrets\Enums\KeySize;

enum TestSecretsEnum: string implements SecretsProviderEnumInterface
{
    case Example = "example_secrets";

    public function getId(): string
    {
        return $this->name;
    }

    public function resolvePath(): string
    {
        return __DIR__
            . DIRECTORY_SEPARATOR . "Secrets"
            . DIRECTORY_SEPARATOR . $this->value;
    }

    public function getKeySize(): KeySize
    {
        return KeySize::Bytes32;
    }
}