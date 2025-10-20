<?php
/**
 * Part of the "charcoal-dev/secrets-kms" package.
 * @link https://github.com/charcoal-dev/secrets-kms
 */

declare(strict_types=1);

namespace Charcoal\Security\Secrets;

/**
 * Constants and behavior control trigger for Secrets KMS.
 */
final class SecretsKms
{
    /** @internal Supported secret key lengths */
    public const array SECRET_KEY_BUFFERS = [16, 20, 24, 32, 40, 64];

    /** language=RegExp pattern for secret reference */
    public const string REF_REGEXP = "/\A[A-Za-z0-9][A-Za-z0-9\-_]{1,39}\z/";
    /** language=RegExp pattern for namespace */
    public const string NAMESPACE_REGEXP = "/\A[A-Za-z0-9][A-Za-z0-9\-_]{1,39}(\/[A-Za-z0-9][A-Za-z0-9\-_]{1,39}){0,3}\z/";

    /**
     * Local File System (LFS) behaviour toggles
     */
    public static bool $lfsUseFileExtensions = false;
    public static bool $lfsAllowDeletes = false;
    public static bool $lfsAllowWrites = false;

    /**
     * Null Padding Handling
     */
    public static bool $nullPaddingReplace = true;
    /** Invalidates the secret that has NULL bytes on either end */
    public const bool SECRET_ENTROPY_NULL_PADDING = false;
    /** @var string Bytes to replace NULL bytes padding (if enabled) */
    public const string SECRET_ENTROPY_NULL_PADDING_REPLACEMENT = "\1";

    /**
     * Local File System (LFS) constants.
     */
    public const string LFS_SECRETS_EXTENSION = ".key";
    public const int LFS_VERSION_PADDING = 5;
    public const int LFS_DEFAULT_UMASK = 0o077;
    public const int LFS_DEFAULT_DIR_PERM = 0o700;
    public const int LFS_DEFAULT_FILE_PERM = 0o600;
}