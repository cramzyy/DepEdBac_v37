<?php
// index.php

// Ensure session is started at the very beginning of the main page.
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Include your database configuration and URL helper.
require 'config.php';
require_once 'url_helper.php';

// Redirect if user is not logged in.
if (!isset($_SESSION['username'])) {
    redirect('login.php');
}

// Handle search
$search = isset($_GET['search']) ? trim($_GET['search']) : "";

// Fetch all projects with user info
$sql = "SELECT p.*, u.firstname, u.lastname
        FROM tblproject p
        JOIN tbluser u ON p.userID = u.userID";
if ($search !== "") {
    $sql .= " WHERE p.projectDetails LIKE ? OR p.prNumber LIKE ?";
}
$sql .= " ORDER BY COALESCE(p.editedAt, p.createdAt) DESC";
$stmt = $pdo->prepare($sql);
if ($search !== "") {
    $stmt->execute(["%$search%", "%$search%"]);
} else {
    $stmt->execute();
}
$projects = $stmt->fetchAll();

// Fetch Mode of Procurement options
$mopList = [];
$stmtMop = $pdo->query("SELECT MoPID, MoPDescription FROM mode_of_procurement ORDER BY MoPID");
while ($row = $stmtMop->fetch()) {
    $mopList[$row['MoPID']] = $row['MoPDescription'];
}

// Fetch Office options
$officeList = [];
$stmtOffices = $pdo->query("SELECT officeID, officename FROM officeid ORDER BY officeID");
while ($office = $stmtOffices->fetch()) {
    $officeList[$office['officeID']] = $office['officename'];
}

// Fetch stage order from reference table
$stmtStageRef = $pdo->query("SELECT stageName FROM stage_reference ORDER BY stageOrder ASC");
$stagesOrder = $stmtStageRef->fetchAll(PDO::FETCH_COLUMN);

// For each project, fetch its stages (ordered by stageID) and determine current stage
foreach ($projects as &$project) {
    // Fetch all stages for this project
    $stmtStages = $pdo->prepare("SELECT * FROM tblproject_stages WHERE projectID = ? ORDER BY stageID ASC");
    $stmtStages->execute([$project['projectID']]);
    $stages = $stmtStages->fetchAll(PDO::FETCH_ASSOC);

    // Map stages by stageName for easy access
    $stagesMap = [];
    $currentStage = null;
    
    foreach ($stagesOrder as $stageName) {
        $stage = null;
        foreach ($stages as $s) {
            if ($s['stageName'] === $stageName) {
                $stage = $s;
                break;
            }
        }
        if ($stage) {
            $stagesMap[$stageName] = $stage;
        }
    }
    
    // Determine current stage - find the submitted stage with the highest stageOrder
    $isFinished = ($project['projectStatus'] ?? 'in-progress') === 'finished';
    if (!$isFinished) {
        // Find the submitted stage with the highest stageID (most recent submission)
        $highestSubmittedStageID = 0;
        $highestSubmittedStageName = null;
        
        foreach ($stages as $stage) {
            if ($stage['isSubmitted'] == 1) {
                // Get the stageID from stage_reference table
                $stmtStageOrder = $pdo->prepare("SELECT stageOrder FROM stage_reference WHERE stageName = ?");
                $stmtStageOrder->execute([$stage['stageName']]);
                $stageOrderResult = $stmtStageOrder->fetch();
                
                if ($stageOrderResult && $stageOrderResult['stageOrder'] > $highestSubmittedStageID) {
                    $highestSubmittedStageID = $stageOrderResult['stageOrder'];
                    $highestSubmittedStageName = $stage['stageName'];
                }
            }
        }
        
        $currentStage = $highestSubmittedStageName;
    }
    
    $project['first_unsubmitted_stage'] = $currentStage;
}
unset($project); // break reference

// Handle project addition
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['addProject'])) {
    // Gather and validate form data
    $prNumber = trim($_POST['prNumber'] ?? '');
    $projectDetails = trim($_POST['projectDetails'] ?? '');
    $MoPID = $_POST['MoPID'] ?? null;
    $programOwner = trim($_POST['programOwner'] ?? '');
    $programOffice = trim($_POST['programOffice'] ?? '');
    $totalABC = $_POST['totalABC'] ?? null;
    $userID = $_SESSION['userID'];
    $remarks = null; // or from form if you have it

    // Basic validation (add more as needed)
    if ($prNumber && $projectDetails && $MoPID && $programOwner && $programOffice && $totalABC !== null) {
        // Insert into tblproject (new projects start as 'in-progress')
        $stmt = $pdo->prepare("INSERT INTO tblproject (prNumber, projectDetails, userID, createdAt, editedAt, projectStatus, MoPID, programOwner, programOffice, totalABC)
                               VALUES (?, ?, ?, NOW(), NOW(), 'in-progress', ?, ?, ?, ?)");
        $stmt->execute([$prNumber, $projectDetails, $userID, $MoPID, $programOwner, $programOffice, $totalABC]);
        $newProjectID = $pdo->lastInsertId();

        // Insert only Mode of Procurement stage (auto-submitted)
        $stmtInsertStage = $pdo->prepare("INSERT INTO tblproject_stages (projectID, stageName, createdAt, approvedAt, isSubmitted) VALUES (?, ?, ?, ?, 1)");
        $stmtInsertStage->execute([$newProjectID, 'Mode Of Procurement', date("Y-m-d H:i:s"), date("Y-m-d H:i:s")]);
        // Optionally redirect to avoid form resubmission
        header("Location: index.php");
        exit;
    } else {
        $projectError = "Please fill in all required fields.";
    }
}

// Handle project deletion
if (isset($_GET['deleteProject'])) {
    $deleteProjectID = intval($_GET['deleteProject']);
    // Only allow admins to delete, or add your own permission logic
    if (isset($_SESSION['admin']) && $_SESSION['admin'] == 1) {
        // Delete all stages for this project first (to maintain referential integrity)
        $stmt = $pdo->prepare("DELETE FROM tblproject_stages WHERE projectID = ?");
        $stmt->execute([$deleteProjectID]);
        // Then delete the project itself
        $stmt = $pdo->prepare("DELETE FROM tblproject WHERE projectID = ?");
        $stmt->execute([$deleteProjectID]);
        // Optionally, redirect to avoid resubmission
        header("Location: index.php");
        exit;
    } else {
        $deleteProjectError = "You do not have permission to delete projects.";
    }
}

// Calculate Statistics
$totalProjects = count($projects);
$finishedProjects = 0;
foreach ($projects as $project) {
    if (strtolower(trim($project['projectStatus'] ?? 'in-progress')) === 'finished') {
        $finishedProjects++;
    }
}
$ongoingProjects = $totalProjects - $finishedProjects;
$percentageDone = ($totalProjects > 0) ? round(($finishedProjects / $totalProjects) * 100, 2) : 0;
$percentageOngoing = ($totalProjects > 0) ? round(($ongoingProjects / $totalProjects) * 100, 2) : 0;

// Define $showTitleRight for the header.php
$showTitleRight = false; // Hide "Bids and Awards Committee Tracking System" on dashboard

include 'view/index_content.php';

?>
