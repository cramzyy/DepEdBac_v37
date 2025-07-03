<?php
// url_helper.php - Helper functions for URL handling

// Define the encryption key if not already defined (must match router.php)
if (!defined('URL_ENCRYPTION_KEY')) {
    define('URL_ENCRYPTION_KEY', 'YzkZyWVXOmvxfdibNtnozh');
}

/**
 * Encrypts a URL path
 * 
 * @param string $path The path to encrypt
 * @return string The encrypted path
 */
if (!function_exists('encryptPath')) {
    function encryptPath($path) {
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt($path, 'AES-256-CBC', URL_ENCRYPTION_KEY, 0, $iv);
        return urlencode(base64_encode($encrypted . '::' . base64_encode($iv)));
    }
}

/**
 * Generates a secure URL for navigation
 * 
 * @param string $path The target PHP file (e.g., 'login.php')
 * @param array $params Optional query parameters
 * @return string The encrypted URL
 */
if (!function_exists('url')) {
    function url($path, $params = []) {
        // Check if generateUrl exists (from router.php)
        if (function_exists('generateUrl')) {
            return generateUrl($path, $params);
        } else {
            // Fallback to original implementation
            if (!empty($params)) {
                $path .= '?' . http_build_query($params);
            }
            
            $encrypted = encryptPath($path);
            return $encrypted;
        }
    }
}

/**
 * Redirects to a secure URL
 * 
 * @param string $path The target PHP file
 * @param array $params Optional query parameters
 */
if (!function_exists('redirect')) {
    function redirect($path, $params = []) {
        $url = url($path, $params);
        header("Location: $url");
        exit;
    }
}