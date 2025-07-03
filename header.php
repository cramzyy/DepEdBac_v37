<?php
// header.php - Common header for all pages

// Start the session if it hasn't been started yet
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Include URL helper functions
require_once 'url_helper.php';

// Set default values for page-specific variables if not already set
if (!isset($isLoginPage)) {
    $isLoginPage = false;
}
if (!isset($showTitleRight)) {
    $showTitleRight = false;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DepEd BAC Tracking System</title>
    <link rel="stylesheet" href="assets/css/header.css">
</head>
<body>
<div class="header">
    <a href="<?php echo url('index.php'); ?>" class="header-link-wrapper">
        <img src="assets/images/DEPED-LAOAG_SEAL_Glow.png" alt="DepEd Logo" class="header-logo">
        <div class="header-text">
            <div class="title-left">
                SCHOOLS DIVISION OF LAOAG CITY<br>DEPARTMENT OF EDUCATION
            </div>
            <?php if ($showTitleRight): ?>
                <div class="title-right">
                    Bids and Awards <br> Committee Tracking System
                </div>
            <?php endif; ?>
        </div>
    </a>
    
    <?php if (!$isLoginPage): ?>
        <div class="user-menu">
            <span class="user-name"><?php echo htmlspecialchars($_SESSION['username'] ?? 'Guest'); ?></span>
            <div class="dropdown" id="profileDropdown">
                <img src="https://cdn-icons-png.flaticon.com/512/149/149071.png" alt="User Icon" class="user-icon" id="profileIcon">
                <span id="dropdownArrow" class="dropdown-arrow"></span>
                <div class="dropdown-content">
                    <?php if (isset($_SESSION['admin']) && $_SESSION['admin'] == 1): ?>
                        <a href="<?php echo url('create_account.php'); ?>">Create Account</a>
                        <a href="<?php echo url('manage_accounts.php'); ?>">Manage Accounts</a>
                    <?php else: ?>
                        <a href="<?php echo url('edit_account.php'); ?>">Change Password</a>
                    <?php endif; ?>
                    <a href="<?php echo url('logout.php'); ?>" id="logoutBtn">Log out</a>
                </div>
            </div>
        </div>
    <?php endif; ?>
</div>

<?php if (!$isLoginPage): ?>
<script src="assets/js/header.js"></script>
<?php endif; ?>