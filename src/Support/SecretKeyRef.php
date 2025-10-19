<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Support;

use Charcoal\Security\Secrets\SecretsKms;

/**
 * Value object for secret key reference
 * @api
 */
final readonly class SecretKeyRef
{
    /**
     * Decode full reference back to id and version (return SecretKeyRef value object)
     * @api
     */
    public static function decode(string $refId): SecretKeyRef
    {
        if (!$refId || !str_contains($refId, ":")) {
            throw new \InvalidArgumentException("Invalid secret key reference");
        }

        $refId = explode(":", $refId, 2);
        return new SecretKeyRef($refId[0], intval(ltrim($refId[1], "0")), null, true);
    }

    /**
     * @param string $ref
     * @param int $version
     * @return string
     */
    public static function encode(string $ref, int $version): string
    {
        return sprintf("%s:%05d", $ref, $version);
    }

    /**
     * @param string $ref
     * @param int $version
     * @param string|null $namespace
     * @param bool $validate
     */
    public function __construct(
        public string  $ref,
        public int     $version,
        public ?string $namespace = null,
        bool           $validate
    )
    {
        if ($validate) {
            if (!$this->ref || !preg_match(SecretsKms::REF_REGEXP, $this->ref)) {
                throw new \InvalidArgumentException("Invalid secret reference format");
            }

            if ($this->version < 0 || $this->version > 65535) {
                throw new \InvalidArgumentException("Invalid secret version");
            }

            if ($this->namespace) {
                $this->validateNamespace($this->namespace);
            }
        }
    }

    /**
     * Returns the new instance of SecretKeyRef with namespace altered
     * @api
     */
    public function withNamespace(string $namespace): self
    {
        $this->validateNamespace($namespace);
        return new self($this->ref, $this->version, $namespace, false);
    }

    /**
     * @param string $namespace
     * @return void
     */
    private function validateNamespace(string $namespace): void
    {
        if (!$namespace || !preg_match(SecretsKms::NAMESPACE_REGEXP, $namespace)) {
            throw new \InvalidArgumentException("Invalid namespace path");
        }
    }
}