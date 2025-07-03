<?php
// Include the database connection and URL helper
require 'config.php';
require_once 'url_helper.php';

// Start the session if it hasn't been started yet
// This is needed for login processing before header.php is included
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Process the login when the form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = trim($_POST['password'] ?? '');
    
    // Query the database for a user with the provided username
    $stmt = $pdo->prepare("SELECT * FROM tblUser WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();
    
    // For development: check plain text password (later replace with hashed password verification)
    if ($user && $password === $user['password']) {
        // Save user details in session for later use
        $_SESSION['userID']   = $user['userID'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['admin']    = $user['admin']; // 1 means admin, 0 means regular user
        
        // Redirect to the landing page after successful login
        redirect('index.php');
    } else {
        $error = "Invalid username or password.";
    }
}

// Set this variable BEFORE including the header to hide user menu
$isLoginPage = true;
// Set this variable to true to display the "Bids and Awards" title
$showTitleRight = true; 

include 'view/login_content.php';
?>
