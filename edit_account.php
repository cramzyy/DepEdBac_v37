<?php
session_start();
require 'config.php'; // Ensure your PDO connection is set up correctly

// User must be logged in
if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit();
}

$userID = $_SESSION['userID'];
$error = "";
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $oldPassword = trim($_POST['old_password'] ?? '');
    $newPassword = trim($_POST['new_password'] ?? '');
    $confirmNewPassword = trim($_POST['confirm_new_password'] ?? '');

    // Fetch current user info to get the stored password
    $stmtUser = $pdo->prepare("SELECT password FROM tbluser WHERE userID = ?");
    $stmtUser->execute([$userID]);
    $user = $stmtUser->fetch();

    if (!$user) {
        $error = "User not found.";
    } elseif (empty($oldPassword) || empty($newPassword) || empty($confirmNewPassword)) {
        $error = "All password fields are required.";
    } elseif ($oldPassword !== $user['password']) { // DIRECT COMPARISON, ASSUMING PLAIN TEXT PASSWORD IN DB
        $error = "Old password does not match.";
    } elseif ($newPassword !== $confirmNewPassword) {
        $error = "New password and confirm new password do not match.";
    } elseif (empty($newPassword)) { // New password cannot be empty
        $error = "New password cannot be empty.";
    } else {
        try {
            $stmt = $pdo->prepare("UPDATE tbluser SET password = ? WHERE userID = ?");
            $stmt->execute([$newPassword, $userID]); // Update with the new password
            $success = true;
        } catch (PDOException $e) {
            $error = "Error updating password: " . $e->getMessage();
        }
    }
}

// Fetch current user info for display (even if not changing password)
$stmt = $pdo->prepare("SELECT u.*, o.officeID, o.officename FROM tbluser u LEFT JOIN officeid o ON u.officeID = o.officeID WHERE u.userID = ?");
$stmt->execute([$userID]);
$user = $stmt->fetch();
include 'view/edit_account_content.php';
?>
