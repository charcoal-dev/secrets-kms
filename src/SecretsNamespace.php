<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets;

use Charcoal\Contracts\Security\Secrets\SecretGeneratorInterface;
use Charcoal\Contracts\Security\Secrets\SecretKeyInterface;
use Charcoal\Contracts\Security\Secrets\SecretNamespaceInterface;
use Charcoal\Contracts\Security\Secrets\SecretStorageInterface;

/**
 * A namespace for managing secrets.
 */
final readonly class SecretsNamespace implements SecretNamespaceInterface
{
    public function __construct(
        private SecretStorageInterface $storage,
        private string                 $refId,
    )
    {
        if (!$this->refId || !preg_match(SecretsKms::NAMESPACE_REGEXP, $this->refId) || strlen($this->refId) > 163) {
            throw new \InvalidArgumentException("Invalid namespace path");
        }
    }

    /**
     * Loads a secret from the namespace.
     */
    public function load(string $id, int $version): SecretKeyInterface
    {
        return $this->storage->load($id, $version, $this);
    }

    /**
     * Stores a secret in the namespace.
     */
    public function store(string $id, int $version, SecretGeneratorInterface $generator): void
    {
        $this->storage->store($this, $id, $version, $generator);
    }

    /**
     * Deletes a secret from the namespace.
     */
    public function delete(string $id, int $version): void
    {
        $this->storage->delete($id, $version, $this);
    }

    /**
     * Checks if the secret exists in the namespace.
     */
    public function has(string $id, int $version): bool
    {
        return $this->storage->has($id, $version, $this);
    }

    /**
     * @return string
     */
    public function refId(): string
    {
        return $this->refId;
    }
}