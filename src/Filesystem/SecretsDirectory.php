<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets\Filesystem;

use Charcoal\Base\Support\ErrorHelper;
use Charcoal\Contracts\Security\Secrets\SecretGeneratorInterface;
use Charcoal\Contracts\Security\Secrets\SecretKeyInterface;
use Charcoal\Contracts\Security\Secrets\SecretNamespaceInterface;
use Charcoal\Contracts\Security\Secrets\SecretStorageInterface;
use Charcoal\Filesystem\Enums\Assert;
use Charcoal\Filesystem\Exceptions\FilesystemException;
use Charcoal\Filesystem\Node\DirectoryNode;
use Charcoal\Filesystem\Path\DirectoryPath;
use Charcoal\Security\Secrets\Config\TrustedFqcn;
use Charcoal\Security\Secrets\Contracts\SecretsProviderEnumInterface;
use Charcoal\Security\Secrets\SecretsKms;
use Charcoal\Security\Secrets\SecretsNamespace;

/**
 * Represents a directory for managing secrets and provides methods
 * to retrieve, store, delete, and check the existence of secrets.
 * Implements the SecretStorageInterface for standard operations.
 */
final readonly class SecretsDirectory implements SecretStorageInterface
{
    private DirectoryNode $directory;
    private LfsNamespaces $namespaces;
    private int $keySize;
    private string $keyBufferFqcn;

    /**
     * SecretsDirectory constructor.
     */
    public function __construct(
        private SecretsProviderEnumInterface $enum,
        private TrustedFqcn                  $trustedFqcn
    )
    {
        try {
            $this->directory = new DirectoryNode(new DirectoryPath($enum->resolvePath()));
            match (DIRECTORY_SEPARATOR) {
                "\\" => $this->directory->path->assert(Assert::Readable),
                default => $this->directory->path->assert(Assert::Readable, Assert::Executable),
            };
        } catch (FilesystemException $e) {
            throw new \RuntimeException("Failed to load secrets root directory: " . $e::class, previous: $e);
        }

        $this->namespaces = new LfsNamespaces();
        $this->keySize = $this->enum->getKeySize()->value;
        $this->keyBufferFqcn = $this->enum->getKeySize()->getTypeFqcn();
    }

    /**
     * Returns the unique identifier for the SecretsProviderEnumInterface.
     */
    public function metaId(): string
    {
        return $this->enum->getId();
    }

    /**
     * Returns a new SecretsNamespace instance each time.
     * Underlying path resolution is cached via LfsNamespaces, so repeated calls
     * for the same $path do not revalidate against the filesystem.
     */
    public function namespace(string $path): SecretsNamespace
    {
        $nsInstance = new SecretsNamespace($this, $path);
        $existingAttr = $this->namespaces->get($path);
        if ($existingAttr) {
            return $nsInstance;
        }

        $dirPath = DIRECTORY_SEPARATOR === "\\" && str_contains($path, "/")
            ? str_replace("/", DIRECTORY_SEPARATOR, $path)
            : null;

        try {
            $asserts = [Assert::Exists, Assert::IsDirectory, Assert::Readable];
            if (DIRECTORY_SEPARATOR === "/") {
                $asserts[] = Assert::Executable;
            }

            $childPath = $this->directory->childPathInfo($dirPath ?? $path, true);
            $childPath->assert(...$asserts);
        } catch (FilesystemException $e) {
            throw new \RuntimeException("Secrets namespace directory resolution failed: " . $e::class, previous: $e);
        }

        $this->namespaces->set(new PathBinding($path, $dirPath, $childPath->writable));
        return $nsInstance;
    }

    /**
     * Loads a secret from the filesystem.
     */
    public function load(string $id, int $version, ?SecretNamespaceInterface $namespace): SecretKeyInterface
    {
        $filepath = $this->resolveFilepath($id, $version, $namespace);
        return $this->generateSecretBuffer($id, $version, @file_get_contents($filepath, false, null, 0, $this->keySize));
    }

    /**
     * Checks if the secret exists in the filesystem
     */
    public function has(string $id, int $version, ?SecretNamespaceInterface $namespace): bool
    {
        try {
            $this->resolveFilepath($id, $version, $namespace);
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Deletes a secret from the filesystem.
     */
    public function delete(string $id, int $version, ?SecretNamespaceInterface $namespace): void
    {
        if (!SecretsKms::$lfsAllowDeletes) {
            throw new \RuntimeException("Secrets deletes are disabled from SecretsKms");
        }

        $filepath = $this->resolveFilepath($id, $version, $namespace);
        error_clear_last();
        if (!@unlink($filepath)) {
            throw new \RuntimeException(
                "Failed to delete secret file",
                previous: ErrorHelper::lastErrorToRuntimeException()
            );
        }
    }

    /**
     * Stores a secret in the filesystem.
     */
    public function store(
        ?SecretNamespaceInterface $namespace,
        string                    $id,
        int                       $version,
        SecretGeneratorInterface  $generator
    ): void
    {
        if (!SecretsKms::$lfsAllowWrites) {
            throw new \RuntimeException("Secrets writing are disabled from SecretsKms");
        }

        if ($generator::size() !== $this->keySize) {
            throw new \InvalidArgumentException("Generator size does not match key size");
        }

        $filename = $this->normalizeFilename($id, $version);
        $filepath = $this->normalizePath($namespace)
            . DIRECTORY_SEPARATOR
            . $filename;

        error_clear_last();
        if (@file_exists($filepath)) {
            throw new \RuntimeException("Overwrites prohibited; Secret file already exists: " . $filepath,
                previous: ErrorHelper::lastErrorToRuntimeException());
        }

        $parent = dirname($filepath);
        $om = umask(SecretsKms::LFS_DEFAULT_UMASK);
        try {
            error_clear_last();
            if (!@file_exists($parent) || !@is_dir($parent) || !@is_writable($parent)) {
                $failure = ErrorHelper::lastErrorToRuntimeException();
                if ($failure) {
                    throw $failure;
                }

                if (!@mkdir($parent, SecretsKms::LFS_DEFAULT_DIR_PERM, true)) {
                    throw new \RuntimeException("Failed to create secrets directory: " . $parent,
                        previous: ErrorHelper::lastErrorToRuntimeException());
                }
            }

            $writeSecret = @file_put_contents($filepath,
                $this->pipeValidateGenerator($generator::generate()), LOCK_EX);
            if ($writeSecret === false) {
                throw new \RuntimeException("Failed to write secret to file: " . $filepath,
                    previous: ErrorHelper::lastErrorToRuntimeException());
            }

            @chmod($filepath, SecretsKms::LFS_DEFAULT_FILE_PERM);
        } finally {
            umask($om);
        }
    }

    /**
     * Validates the entropy generated by the generator.
     */
    private function pipeValidateGenerator(string $entropy): string
    {
        if (strlen($entropy) !== $this->keySize) {
            throw new \InvalidArgumentException(sprintf(
                "Generator entropy size mismatch: expected %d, got %d",
                $this->keySize,
                strlen($entropy)
            ));
        }

        if (!SecretsKms::SECRET_ENTROPY_NULL_PADDING) {
            if (str_starts_with($entropy, "\0") || str_ends_with($entropy, "\0")) {
                throw new \InvalidArgumentException("Entropy must not be null padded");
            }
        }

        return $entropy;
    }

    /**
     * Generates a new secret key buffer.
     */
    private function generateSecretBuffer(string $ref, int $version, false|string $entropy): SecretKeyInterface
    {
        return new $this->keyBufferFqcn($this, $ref, $version, $entropy);
    }

    /**
     * Returns the TrustedFqcnInterface instance.
     * This is used to validate namespace and secret utilizer concrete classes.
     */
    public function trustedFqcn(): TrustedFqcn
    {
        return $this->trustedFqcn;
    }

    /**
     * @param string $id
     * @param int $version
     * @return string
     */
    private function normalizeFilename(string $id, int $version): string
    {
        $vSuffix = "_v" . str_pad((string)$version, SecretsKms::LFS_VERSION_PADDING, "0", STR_PAD_LEFT);
        return strtolower($id . $vSuffix) .
            (SecretsKms::$lfsUseFileExtensions ? SecretsKms::LFS_SECRETS_EXTENSION : "");
    }

    /**
     * Ensure the namespace is registered and has a valid path binding.
     */
    private function ensureChildNamespace(SecretNamespaceInterface $namespace): PathBinding
    {
        $registered = $this->namespaces->get($namespace->refId());
        if (!$registered) {
            throw new \RuntimeException(sprintf("Secrets store[%s]: Namespace not registered or orphaned: %s",
                $this->metaId(), $namespace->refId()));
        }

        return $registered;
    }

    /**
     * Internal helper to resolve the path to the namespace directory.
     */
    private function normalizePath(?SecretNamespaceInterface $namespace): string
    {
        if ($namespace && !$this->trustedFqcn->isValidNamespace($namespace::class)) {
            throw new \DomainException("Unregistered namespace class: " . $namespace::class);
        }

        if (!$namespace) {
            return $this->directory->path->absolute;
        }

        // Find relevant child
        $registered = $this->ensureChildNamespace($namespace);
        return $this->directory->path->absolute
            . DIRECTORY_SEPARATOR
            . ($registered->directoryPath ?? $registered->namespace);
    }

    /**
     * Internal helper to resolve the path to the secret file.
     */
    private function resolveFilepath(string $id, int $version, ?SecretNamespaceInterface $namespace): string
    {
        if (!preg_match(SecretsKms::REF_REGEXP, $id) || $version >= 65535) {
            throw new \InvalidArgumentException("Invalid secret reference format");
        }

        $filepath = $this->normalizePath($namespace)
            . DIRECTORY_SEPARATOR
            . $this->normalizeFilename($id, $version);

        error_clear_last();
        if (!@file_exists($filepath) || !@is_file($filepath) || !@is_readable($filepath)) {
            throw new \RuntimeException("Secret file not found or not readable",
                previous: ErrorHelper::lastErrorToRuntimeException());
        }

        return $filepath;
    }
}
