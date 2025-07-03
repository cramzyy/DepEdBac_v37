<?php
// router.php - Central routing system with URL hashing

// Start session if not already started
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Define the encryption key (change this to a secure random string)
define('URL_ENCRYPTION_KEY', 'YzkZyWVXOmvxfdibNtnozh');

/**
 * URL Encryption/Decryption Functions
 */

// Function to encrypt a URL path
function encryptPath($path) {
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($path, 'AES-256-CBC', URL_ENCRYPTION_KEY, 0, $iv);
    return urlencode(base64_encode($encrypted . '::' . base64_encode($iv)));
}

// Function to decrypt a URL path
function decryptPath($encryptedPath) {
    $decoded = base64_decode(urldecode($encryptedPath));
    list($encrypted_data, $iv_encoded) = explode('::', $decoded, 2);
    $iv = base64_decode($iv_encoded);
    return openssl_decrypt($encrypted_data, 'AES-256-CBC', URL_ENCRYPTION_KEY, 0, $iv);
}

// Function to generate a hashed URL
function generateUrl($path, $params = []) {
    $encrypted = encryptPath($path);
    $url = $encrypted;
    
    if (!empty($params)) {
        $queryString = http_build_query($params);
        $url .= '?' . $queryString;
    }
    
    return $url;
}

/**
 * Routing Logic
 */

// Get the encrypted path from the URL
$encryptedPath = $_GET['path'] ?? '';

// Default to index if no path is provided
if (empty($encryptedPath)) {
    $targetFile = 'index.php';
} else {
    // Check if this is an encrypted path or a direct file access
    if (strpos($encryptedPath, '.') === false && !file_exists($encryptedPath)) {
        // This is likely an encrypted path
        try {
            $decryptedPath = decryptPath($encryptedPath);
            
            // Extract query parameters if they exist in the decrypted path
            $parts = explode('?', $decryptedPath, 2);
            $targetFile = $parts[0];
            
            if (isset($parts[1])) {
                // Parse and add query parameters
                parse_str($parts[1], $queryParams);
                foreach ($queryParams as $key => $value) {
                    $_GET[$key] = $value;
                }
            }
        } catch (Exception $e) {
            // If decryption fails, redirect to index
            header("Location: " . generateUrl('index.php'));
            exit;
        }
    } else {
        // Direct file access (for assets, etc.)
        $targetFile = $encryptedPath;
    }
}

// Check if the target file exists
if (!file_exists($targetFile)) {
    header("HTTP/1.0 404 Not Found");
    echo "404 - File not found";
    exit;
}

// Define a global function to be used in all pages for generating URLs
function url($path, $params = []) {
    return generateUrl($path, $params);
}

// Include the target file
include $targetFile;