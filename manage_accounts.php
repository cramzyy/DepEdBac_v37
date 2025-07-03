<?php
// Start the session if it hasn't been started yet
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}
require 'config.php'; // Ensure this file exists and contains PDO connection
require_once 'url_helper.php'; // Include URL helper functions

// Only admin users can access this page.
if (!isset($_SESSION['username']) || $_SESSION['admin'] != 1) {
    redirect('index.php');
    exit();
}

$editSuccess = "";
$deleteSuccess = "";
$error = "";

// Fetch office names and IDs from the database for the dropdown
$officeList = [];
try {
    $stmtOffices = $pdo->query("SELECT officeID, officename FROM officeid ORDER BY officeID");
    while ($office = $stmtOffices->fetch()) {
        $officeList[$office['officeID']] = $office['officeID'] . ' - ' . $office['officename'];
    }
} catch (PDOException $e) {
    $error = "Error fetching office list: " . $e->getMessage();
}

// Process deletion if a 'delete' GET parameter is provided.
if (isset($_GET['delete'])) {
    $deleteID = intval($_GET['delete']);
    try {
        $stmt = $pdo->prepare("DELETE FROM tbluser WHERE userID = ?");
        $stmt->execute([$deleteID]);
        $deleteSuccess = "Account deleted successfully.";
    } catch (PDOException $e) {
        $error = "Error deleting account: " . $e->getMessage();
    }
}

// Process editing if the form is submitted.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['editAccount'])) {
    $editUserID = intval($_POST['editUserID']);
    $firstname  = trim($_POST['firstname']);
    $middlename = trim($_POST['middlename'] ?? "");
    $lastname   = trim($_POST['lastname']);
    $position   = trim($_POST['position'] ?? "");
    $username   = trim($_POST['username']);
    $password   = trim($_POST['password']);    // If empty, do not update password.
    $adminFlag  = isset($_POST['admin']) ? 1 : 0;
    $officeName = trim($_POST['office']); // Now comes from a select dropdown

    if (empty($firstname) || empty($lastname) || empty($username) || empty($officeName)) {
        $error = "Please fill in all required fields for editing.";
    } else {
        try {
            // Extract the office ID from the selected option (format: "1 - OSDS", "2 - ADMIN", etc.)
            // Use regex to get the number before the hyphen, or if no hyphen, try to match by name
            if (preg_match('/^(\d+)\s*-\s*.*/', $officeName, $matches)) {
                $officeID = intval($matches[1]);
            } else {
                // Fallback: if format is just "OSDS", try to find by name
                $stmtOffice = $pdo->prepare("SELECT officeID FROM officeid WHERE officename = ?");
                $stmtOffice->execute([$officeName]);
                $office = $stmtOffice->fetch();
                if ($office) {
                    $officeID = $office['officeID'];
                } else {
                    // Default to office ID 1 if no match found
                    $officeID = 1;
                    $error = "Warning: Office name did not match an existing office. Defaulting to Office ID 1.";
                }
            }

            // Update the account. If password is provided, update it; otherwise leave it unchanged.
            if (!empty($password)) {
                $stmtEdit = $pdo->prepare("UPDATE tbluser SET firstname = ?, middlename = ?, lastname = ?, position = ?, username = ?, password = ?, admin = ?, officeID = ? WHERE userID = ?");
                $stmtEdit->execute([$firstname, $middlename, $lastname, $position, $username, $password, $adminFlag, $officeID, $editUserID]);
            } else {
                $stmtEdit = $pdo->prepare("UPDATE tbluser SET firstname = ?, middlename = ?, lastname = ?, position = ?, username = ?, admin = ?, officeID = ? WHERE userID = ?");
                $stmtEdit->execute([$firstname, $middlename, $lastname, $position, $username, $adminFlag, $officeID, $editUserID]);
            }
            $editSuccess = "Account updated successfully.";
        } catch(PDOException $e) {
            $error = "Error updating account: " . $e->getMessage();
        }
    }
}

// Retrieve all accounts along with their office names and IDs.
$stmt = $pdo->query("SELECT u.*, o.officeID, o.officename FROM tbluser u LEFT JOIN officeid o ON u.officeID = o.officeID ORDER BY u.userID ASC");
$accounts = $stmt->fetchAll();

include 'view/manage_accounts_content.php';
?>
