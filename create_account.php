<?php
// Start the session if it hasn't been started yet
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}
require 'config.php'; // Ensure this file exists and contains PDO connection

// Allow only admin users to create accounts.
if (!isset($_SESSION['username']) || $_SESSION['admin'] != 1) {
    redirect('index.php');
    exit();
}

$success = false;
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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve and trim the form values.
    $firstname   = trim($_POST['firstname']);
    $middlename  = trim($_POST['middlename'] ?? "");
    $lastname    = trim($_POST['lastname']);
    $position    = trim($_POST['position'] ?? "");
    $username    = trim($_POST['username']);
    $password    = trim($_POST['password']);  // Plain text for now (not recommended for production)
    $adminFlag   = isset($_POST['admin']) ? 1 : 0;
    $officeName  = trim($_POST['office']);      // Now comes from a select dropdown

    // Basic validation—check that required fields are filled.
    // Also check that a valid office was selected (not the empty default option)
    if(empty($firstname) || empty($lastname) || empty($username) || empty($password) || empty($officeName)){
       $error = "Please fill in all required fields.";
    } else {
        try {
            // Extract the office ID from the selected option (format: "1 - OSDS")
            $officeID = intval(explode(' - ', $officeName)[0]);
            
            // Verify the office ID exists
            $stmtOffice = $pdo->prepare("SELECT officeID FROM officeid WHERE officeID = ?");
            $stmtOffice->execute([$officeID]);
            $office = $stmtOffice->fetch();
            
            if (!$office) {
                // If somehow the office ID doesn't exist, use a default (1)
                $officeID = 1;
            }

            // Now insert the new user into tbluser.
            $stmtUser = $pdo->prepare("INSERT INTO tbluser (firstname, middlename, lastname, position, username, password, admin, officeID) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            $stmtUser->execute([$firstname, $middlename, $lastname, $position, $username, $password, $adminFlag, $officeID]);

            $success = true;
            // Retrieve the newly created account details using the auto-generated userID.
            $newAccountID = $pdo->lastInsertId();
            $stmt2 = $pdo->prepare("SELECT u.*, o.officename FROM tbluser u LEFT JOIN officeid o ON u.officeID = o.officeID WHERE u.userID = ?");
            $stmt2->execute([$newAccountID]);
            $newAccount = $stmt2->fetch();

        } catch (PDOException $e) {
            $error = "Error creating account: " . $e->getMessage();
        }
    }
}
include 'view/create_account_content.php';
?>
