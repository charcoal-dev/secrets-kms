<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Filesystem;

/**
 * This class is immutable and encapsulates details about a specific path,
 * such as its location and whether it is writable.
 */
final readonly class PathBinding
{
    public function __construct(
        public string  $namespace,
        public ?string $directoryPath,
        public bool    $isWritable,
    )
    {
    }
}