<?php

use OpenSSLU\OpenSSLU;
use PHPUnit\Framework\TestCase;

class OpenSSLUTest extends TestCase
{
    public function encryptionDataProvider()
    {
        return [
            ['testData', 'AES-256-CBC-HMAC-SHA256', 'test-encryption-key'],
            ['anotherTestData', 'AES-128-CBC', 'another-test-encryption-key'],
            ['anotherTestDataWithHMAC', 'AES-128-CBC-HMAC-SHA1', 'another-test-encryption-key-hmac']
        ];
    }

    public function decryptionDataProvider()
    {
        return [
            ['KzU0gD0pjKzB10sZqleCGg==', 'rf1OMsrsgrgXlFjePnzkCQ==', 'AES-256-CBC-HMAC-SHA256', 'test-encryption-key'],
            ['9A70RabQkv95AA4FNv44IA==', 'Z11E/gzUdZ2SWrvHmUpY6Q==', 'AES-128-CBC', 'another-test-encryption-key'],
            ['vDEsgpbEKARx5FJCXsrMd+1AfcSZwjGOdG+Be6Dhns8=', 'AB6IFqaKgTIkALISSMMvqg==', 'AES-128-CBC-HMAC-SHA1', 'another-test-encryption-key-hmac']
        ];
    }

    /**
     * @dataProvider encryptionDataProvider
     */
    public function testShouldEncryptDataAndReturnItBack($data, $encryptionMethod, $encryptionKey)
    {
        $openSSLU = new OpenSSLU();

        $encryptTestData = $openSSLU->encrypt($data, $encryptionMethod, $encryptionKey);

        $this->assertArrayHasKey('encryptedData', $encryptTestData);

        $this->assertArrayHasKey('ivKey', $encryptTestData);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testShouldNotEncryptDataWithInvalidMethod()
    {
        $openSSLU = new OpenSSLU();

        $openSSLU->encrypt('someData', 'notKnownMethod');
    }

    /**
     * @dataProvider decryptionDataProvider
     */
    public function testShouldDecryptDataAndReturnItBack($data, $iv, $encryptionMethod, $encryptionKey)
    {
        $openSSLU = new OpenSSLU();

        $decryptTestData = $openSSLU->decrypt($data, $iv, $encryptionMethod, $encryptionKey);

        $this->assertArrayHasKey('decryptedData', $decryptTestData);

        $this->assertArrayHasKey('ivKey', $decryptTestData);
    }

    /**
     * @expectedException \OpenSSLU\DecryptFailedException
     */
    public function testShouldNotDecryptDataWithWrongIv()
    {
        $openSSLU = new OpenSSLU();

        $openSSLU->decrypt('hello', '55etPDekLvXQVX7I+lOqkA==');
    }
}
