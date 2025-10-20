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
        return new SecretKeyRef(true, $refId[0], intval(ltrim($refId[1], "0")), null);
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
     * @param bool $validate
     * @param string $ref
     * @param int $version
     * @param string|null $namespace
     * @param string|null $remixMessage
     * @param int|null $remixIterations
     */
    public function __construct(
        bool           $validate,
        public string  $ref,
        public int     $version,
        public ?string $namespace = null,
        public ?string $remixMessage = null,
        public ?int    $remixIterations = null,
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

            if ($this->remixMessage || $this->remixIterations) {
                $this->validateRemixing($this->remixMessage, $this->remixIterations);
            }
        }
    }

    /**
     * Encodes the SecretKeyRef value to string; that could be used to uniquely identify the secret while indexing
     * @return string
     */
    public function toString(): string
    {
        $encoded = self::encode($this->ref, $this->version);
        if ($this->namespace) {
            $encoded = $this->namespace . "@" . $encoded;
        }

        if ($this->remixMessage) {
            $encoded .= "[*]:" . $this->remixMessage . ":" . $this->remixIterations;
        }

        return $encoded;
    }

    /**
     * Returns the new instance of SecretKeyRef with namespace altered
     * @api
     */
    public function withNamespace(string $namespace): self
    {
        $this->validateNamespace($namespace);
        return new self(false, $this->ref, $this->version, $namespace, $this->remixMessage, $this->remixIterations);
    }

    /**
     * Returns the new instance of SecretKeyRef with remixing parameters altered
     * @api
     */
    public function withRemixing(string $message, int $iterations): self
    {
        $this->validateRemixing($message, $iterations);
        return new self(false, $this->ref, $this->version, $this->namespace, $message, $iterations);
    }

    /**
     * @param string|null $message
     * @param int|null $iterations
     * @return void
     */
    private function validateRemixing(?string $message, ?int $iterations): void
    {
        if (!$message || !$iterations) {
            throw new \InvalidArgumentException("Remix message and iterations must both be set or both be null");
        }

        if (!preg_match(SecretsKms::REF_REGEXP, $message)) {
            throw new \InvalidArgumentException("Invalid remix message format");
        }

        if ($iterations < 1) {
            throw new \InvalidArgumentException("Invalid remix iterations");
        }
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