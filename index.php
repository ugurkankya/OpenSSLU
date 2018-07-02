<?php
require('vendor/autoload.php');

use OpenSSLU\OpenSSLU;

$openSSLU = new OpenSSLU();

$encryptedData = $openSSLU->encrypt('originalText');

$decryptedData = $openSSLU->decrypt('4pQR3JlarDEh3+k8maWGag==', 'blG5o2BIMCW8CJDTT/Vrvg==');