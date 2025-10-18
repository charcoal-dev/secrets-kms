<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Contracts;

/**
 * Interface SecretsProviderEnumInterface
 * Defines a contract for enums that provide secrets and their path resolution.
 */
interface SecretsProviderEnumInterface extends SecretsProviderInterface, \UnitEnum
{
}