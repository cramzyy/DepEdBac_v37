<?php
// Start the session if it hasn't been started yet
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}
require 'config.php'; // Ensure your PDO connection is set up correctly
require_once 'url_helper.php';

// Redirect if user is not logged in.
if (!isset($_SESSION['username'])) {
    // For AJAX requests, return an error message instead of redirecting
    if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        echo '<div class="error-message">Session expired. Please <a href="' . url('login.php') . '">login</a> again.</div>';
        exit();
    } else {
        redirect('login.php');
    }
}

// Initialize variables
$totalProjects = 0;
$finishedProjects = 0;
$ongoingProjects = 0;
$stageCounts = [];
$ongoingBreakdownData = [];
$percentageDone = 0;
$percentageOngoing = 0;
$ongoingProjectsList = [];
$finishedProjectsList = [];

try {
    // Fetch stage order from reference table
    $stmtStageRef = $pdo->query("SELECT stageName FROM stage_reference ORDER BY stageOrder ASC");
    $stagesOrder = $stmtStageRef->fetchAll(PDO::FETCH_COLUMN);

    // Initialize stage counts
    foreach ($stagesOrder as $stage) {
        $stageCounts[$stage] = 0;
    }
    $stageCounts['Finished'] = 0;

    // First, get total number of projects
    $stmtTotal = $pdo->query("SELECT COUNT(*) as total FROM tblproject");
    $totalResult = $stmtTotal->fetch();
    $totalProjects = $totalResult['total'];

    if ($totalProjects > 0) {
        // Fetch all projects with their projectStatus
        $sql = "SELECT p.projectID, p.prNumber, p.projectDetails, p.projectStatus
                FROM tblproject p";
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute();
        $projects = $stmt->fetchAll();

        foreach ($projects as $project) {
            if (strtolower(trim($project['projectStatus'] ?? 'in-progress')) === 'finished') {
                $finishedProjects++;
                $stageCounts['Finished']++;
            } else {
                $ongoingProjects++;
                
                // Find the current stage for this project - highest submitted stageID
                $currentStage = null;
                
                // Get the submitted stage with the highest stageOrder (most recent submission)
                $stageSQL = "SELECT ps.stageName 
                            FROM tblproject_stages ps 
                            JOIN stage_reference sr ON ps.stageName = sr.stageName 
                            WHERE ps.projectID = ? AND ps.isSubmitted = 1
                            ORDER BY sr.stageOrder DESC 
                            LIMIT 1";
                
                $stageStmt = $pdo->prepare($stageSQL);
                $stageStmt->execute([$project['projectID']]);
                $currentStage = $stageStmt->fetch();
                
                if ($currentStage && isset($stageCounts[$currentStage['stageName']])) {
                    $stageCounts[$currentStage['stageName']]++;
                }
            }
        }

        // Calculate percentages
        $percentageDone = round(($finishedProjects / $totalProjects) * 100, 1);
        $percentageOngoing = round(($ongoingProjects / $totalProjects) * 100, 1);

        // Populate ongoingBreakdownData for the nested grid
        foreach ($stagesOrder as $stage) {
            if (!empty($stageCounts[$stage]) && $stageCounts[$stage] > 0) {
                $shortForm = '';
                switch ($stage) {
                    case 'Mode Of Procurement': $shortForm = 'MoP'; break;
                    case 'Purchase Request': $shortForm = 'PR'; break;
                    case 'Philgeps Posting': $shortForm = 'Philgeps'; break;
                    case 'Certification of Posting': $shortForm = 'CoP'; break;
                    case 'Request For Quotation': $shortForm = 'RFQ'; break;
                    case 'Abstract of Quotation': $shortForm = 'AoQ'; break;
                    case 'Resolution to Award': $shortForm = 'RtA'; break;
                    case 'Notice of Award': $shortForm = 'NoA'; break;
                    case 'Purchase Order': $shortForm = 'PO'; break;
                    case 'Notice to Proceed': $shortForm = 'NtP'; break;
                    default: $shortForm = substr($stage, 0, 3); break;
                }
                $ongoingBreakdownData[] = [
                    'name' => $shortForm,
                    'count' => $stageCounts[$stage]
                ];
            }
        }
    }

} catch (PDOException $e) {
    // Handle database errors gracefully
    error_log("Statistics query error: " . $e->getMessage());
    $totalProjects = 0;
    $finishedProjects = 0;
    $ongoingProjects = 0;
    $stageCounts = [];
    $ongoingBreakdownData = [];
}



include 'view/statistics_content.php';
?>
