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
 */
final readonly class SecretKeyRef
{
    public function __construct(
        public string $ref,
        public int    $version,
        bool          $validate
    )
    {
        if ($validate) {
            if (!$this->ref || !preg_match(SecretsKms::REF_REGEXP, $this->ref)) {
                throw new \InvalidArgumentException("Invalid secret reference format");
            }

            if ($this->version < 0 || $this->version > 65535) {
                throw new \InvalidArgumentException("Invalid secret version");
            }
        }
    }
}