<?php
function encrypt_decrypt($string, $action = 'encrypt')
{
    $encrypt_method = "AES-256-CBC";
    $secret_key = 'Sdgsjkd6dsadsa3245assa'; // user define private key
    $secret_key = 'Sdgsjkd6dsadsa3245assa'; // user define private key
    $secret_iv = 'MKOIFGTIHG89234HJHJ'; // user define secret key
    $key = hash('sha256', $secret_key);
    $iv = substr(hash('sha256', $secret_iv), 0, 16); // sha256 is hash_hmac_algo
    if ($action == 'encrypt') {
        $output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
        $output = base64_encode($output);
    } else if ($action == 'decrypt') {
        $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
    }
    return $output;
}

echo encrypt_decrypt('123','encrypt');

// NUNFQWI5dE5uMVczUnlYN0h3WUlYZz09

//echo encrypt_decrypt('NUNFQWI5dE5uMVczUnlYN0h3WUlYZz09','decrypt');
