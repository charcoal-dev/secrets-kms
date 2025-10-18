<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Contracts;

use Charcoal\Security\Secrets\Enums\KeySize;

/**
 * Interface SecretsProviderInterface
 * @package Charcoal\Security\Secrets\Contracts
 */
interface SecretsProviderInterface
{
    public function getId(): string;

    public function resolvePath(): string;

    public function getKeySize(): KeySize;
}