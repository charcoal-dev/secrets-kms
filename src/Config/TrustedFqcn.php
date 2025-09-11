<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Config;

use Charcoal\Contracts\Security\Secrets\TrustedFqcnInterface;

/**
 * Passed to constructor of SecretsStorageProvider.
 */
final readonly class TrustedFqcn implements TrustedFqcnInterface
{
    private array $secretsUtilityClasses;
    private array $secretsNamespaceContracts;

    public function __construct(
        array $secretsUtilityClasses,
        array $secretsNamespaceContracts,
    )
    {
        foreach ([...$secretsNamespaceContracts, ...$secretsUtilityClasses] as $fqcn) {
            if (!is_string($fqcn) || !$fqcn || !class_exists($fqcn)) {
                throw new \LogicException("Invalid trusted FQCN");
            }
        }

        $this->secretsUtilityClasses = array_fill_keys(array_values($secretsUtilityClasses), true);
        $this->secretsNamespaceContracts = array_fill_keys(array_values($secretsNamespaceContracts), true);
    }

    /**
     * Checks if a given object or classname (fqcn) can use secrets.
     */
    public function canUtilizeSecrets(object|string $class): bool
    {
        $fqcn = is_string($class) ? $class : $class::class;
        return $this->secretsUtilityClasses[$fqcn] ?? false;
    }

    /**
     * Checks if a given object or classname (fqcn) is an accepted SecretsNamespaceInterface.
     */
    public function isValidNamespace(object|string $class): bool
    {
        $fqcn = is_string($class) ? $class : $class::class;
        return $this->secretsNamespaceContracts[$fqcn] ?? false;
    }

    /**
     * Inspect trusted concrete FQCNs.
     * @api
     */
    public function inspect(): array
    {
        return [
            "secretsUtilityClasses" => implode(", ", array_keys($this->secretsUtilityClasses)),
            "secretsNamespaceContracts" => implode(", ", array_keys($this->secretsNamespaceContracts)),
        ];
    }
}