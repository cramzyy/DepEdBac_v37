<?php
session_start();
require_once 'url_helper.php';

// Clear all session data
session_unset();
session_destroy();

// Redirect to login page using encrypted URL
redirect('login.php');
?>
