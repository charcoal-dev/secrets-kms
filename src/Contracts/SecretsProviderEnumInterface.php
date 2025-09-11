<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Contracts;

use Charcoal\Security\Secrets\Enums\KeySize;

/**
 * Interface SecretsProviderEnumInterface
 * Defines a contract for enums that provide secrets and their path resolution.
 */
interface SecretsProviderEnumInterface extends \UnitEnum
{
    public function getId(): string;

    public function resolvePath(): string;

    public function getKeySize(): KeySize;
}