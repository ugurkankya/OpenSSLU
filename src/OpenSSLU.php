<?php

namespace OpenSSLU;

class OpenSSLU
{
    /**
     * Default Encryption Method
     */
    protected const DEFAULT_ENCRYPTION_METHOD = 'AES-256-CBC-HMAC-SHA256';

    /**
     * Default Encryption Key
     */
    protected const DEFAULT_ENCRYPTION_KEY = 'DEFAULT_TEST';

    /**
     * Default Encryption Option
     */
    protected const DEFAULT_OPTION = 0;

    /**
     * Build the __construct()
     *
     * @throws \Exception
     */
    public function __construct()
    {
        if (PHP_VERSION_ID < 70100) {
            throw new \Exception('OpenSSLU needs at least PHP 7.1 or higher.');
        }
    }

    /**
     * Encrypt the data and return it back.
     *
     * @param $data
     * @param string $encryptionMethod
     * @param string $encryptionKey
     * @param int $options
     * @return array
     * @throws EncryptFailedException
     * @throws IvKeyException
     */
    public function encrypt($data,
                            $encryptionMethod = self::DEFAULT_ENCRYPTION_METHOD,
                            $encryptionKey = self::DEFAULT_ENCRYPTION_KEY,
                            $options = self::DEFAULT_OPTION
    )
    {
        if ($data === null) {
            throw new \InvalidArgumentException('OpenSSLU needs a data to encrypt.');
        }

        if ($encryptionMethod === null) {
            throw new \InvalidArgumentException('OpenSSLU needs a encryption method.');
        }

        if ($encryptionKey === null) {
            throw new \InvalidArgumentException('OpenSSLU needs a encryption key.');
        }

        if (in_array($encryptionMethod, $this->getEncryptionMethods()) === false) {
            throw new \InvalidArgumentException('OpenSSLU needs a valid encryption method.');
        }

        if ($options === null) {
            throw new \InvalidArgumentException('OpenSSLU needs some options.');
        }

        try {
            $encryptedData = openssl_encrypt($data,
                $encryptionMethod,
                $encryptionKey,
                $options,
                $iv = $this->getEncryptionMethodBasedIvKey($encryptionMethod)
            );

            if ($encryptedData === false) {
                throw new EncryptFailedException('Failed to encrypt the data.');
            }

            return [
                'encryptedData' => $encryptedData,
                'ivKey'         => base64_encode($iv)
            ];

        } catch (IvKeyException $e) {
            throw $e;
        }
    }


    /**
     * Decrypt the data and return it back.
     *
     * @param $data
     * @param $iv
     * @param string $encryptionMethod
     * @param string $encryptionKey
     * @param int $options
     * @return array
     * @throws DecryptFailedException
     * @throws IvKeyException
     */
    public function decrypt($data,
                            $iv,
                            $encryptionMethod = self::DEFAULT_ENCRYPTION_METHOD,
                            $encryptionKey = self::DEFAULT_ENCRYPTION_KEY,
                            $options = self::DEFAULT_OPTION
    )
    {
        if ($data === null) {
            throw new \InvalidArgumentException('OpenSSLU needs a data to decrypt.');
        }

        if ($iv === null) {
            throw new \InvalidArgumentException('OpenSSLU needs a iv to decrypt.');
        }

        if ($encryptionMethod === null) {
            throw new \InvalidArgumentException('OpenSSLU needs a encryption method.');
        }

        if ($encryptionKey === null) {
            throw new \InvalidArgumentException('OpenSSLU needs a encryption key.');
        }

        if (in_array($encryptionMethod, $this->getEncryptionMethods()) === false) {
            throw new \InvalidArgumentException('OpenSSLU needs a valid encryption method.');
        }

        if ($options === null) {
            throw new \InvalidArgumentException('OpenSSLU needs some options.');
        }

        try {
            $decryptedData = openssl_decrypt($data,
                $encryptionMethod,
                $encryptionKey,
                $options,
                $decryptedIv = base64_decode($iv)
            );

            if ($decryptedData === false) {
                throw new DecryptFailedException('OpenSSLU failed to decrypt the data.');
            }

            return [
              'decryptedData' => $decryptedData,
              'ivKey' => $decryptedIv
            ];

        } catch (IvKeyException $e) {
            throw $e;
        }
    }

    /**
     * Get the encryption method based iv key and return it.
     *
     * @param string $encryptionMethod
     * @return string
     * @throws IvKeyException
     */
    public function getEncryptionMethodBasedIvKey($encryptionMethod = self::DEFAULT_ENCRYPTION_METHOD)
    {
        if (!$ivKey = openssl_random_pseudo_bytes(openssl_cipher_iv_length($encryptionMethod))) {
            throw new IvKeyException('OpenSSLU was unable to generate an iv key for the specified encryption method.');
        }

        return $ivKey;
    }

    /**
     * Get all available cipher methods.
     *
     * @return array|null
     */
    protected function getEncryptionMethods(): ?array
    {
        return openssl_get_cipher_methods();
    }
}
