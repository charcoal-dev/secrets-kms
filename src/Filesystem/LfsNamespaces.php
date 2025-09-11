<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Filesystem;

/**
 * Namespaces to paths mapping, and attribute holder
 */
final class LfsNamespaces implements \IteratorAggregate, \Countable
{
    /** @var array<string,PathBinding> */
    private array $paths = [];

    public function __construct()
    {
    }

    public function set(PathBinding $binding): void
    {
        $this->paths[strtolower($binding->namespace)] = $binding;
    }

    public function get(string $namespace): ?PathBinding
    {
        if (!$namespace) {
            return null;
        }

        return $this->paths[strtolower($namespace)] ?? null;
    }

    public function count(): int
    {
        return count($this->paths);
    }

    public function getIterator(): \Traversable
    {
        return new \ArrayIterator($this->paths);
    }
}