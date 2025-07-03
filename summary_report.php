<?php
// summary_report.php - Generate HTML summary report of dashboard projects

// Start the session if it hasn't been started yet
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

require 'config.php';
require_once 'url_helper.php';

// Redirect if user is not logged in
if (!isset($_SESSION['username'])) {
    http_response_code(403);
    echo "<!DOCTYPE html><html><head><title>Access Denied</title></head><body><h1>Access Denied</h1><p>Please <a href='login.php'>login</a> to access this report.</p></body></html>";
    exit;
}

// Get current date and time for the report
$reportDate = date('F j, Y');
$reportTime = date('h:i A');

// Handle search filter if provided
$search = isset($_GET['search']) ? trim($_GET['search']) : "";

// Fetch all projects with user info (same query as index.php)
$sql = "SELECT p.*, u.firstname, u.lastname, mop.MoPDescription as mode_of_procurement
        FROM tblproject p
        LEFT JOIN tbluser u ON p.userID = u.userID
        LEFT JOIN mode_of_procurement mop ON p.MoPID = mop.MoPID";

if ($search !== "") {
    $sql .= " WHERE (p.prNumber LIKE ? OR p.projectDetails LIKE ?)";
}
$sql .= " ORDER BY COALESCE(p.editedAt, p.createdAt) DESC";

$stmt = $pdo->prepare($sql);
if ($search !== "") {
    $stmt->execute(["%$search%", "%$search%"]);
} else {
    $stmt->execute();
}
$projects = $stmt->fetchAll();

// Fetch stage order from reference table
$stmtStageRef = $pdo->query("SELECT stageName FROM stage_reference ORDER BY stageOrder ASC");
$stagesOrder = $stmtStageRef->fetchAll(PDO::FETCH_COLUMN);

// For each project, fetch its stages and determine status (same logic as index.php)
foreach ($projects as &$project) {
    // Fetch all stages for this project
    $stmtStages = $pdo->prepare("SELECT * FROM tblproject_stages WHERE projectID = ? ORDER BY stageID ASC");
    $stmtStages->execute([$project['projectID']]);
    $stages = $stmtStages->fetchAll(PDO::FETCH_ASSOC);

    // Map stages by stageName for easy access
    $stagesMap = [];
    foreach ($stages as $stage) {
        $stagesMap[$stage['stageName']] = $stage;
    }
    
    // Use projectStatus directly from database instead of checking stages
    $isFinished = strtolower(trim($project['projectStatus'] ?? 'in-progress')) === 'finished';
    
    // Determine current stage - highest submitted stageID
    $currentStage = null;
    if (!$isFinished) {
        $highestSubmittedStageID = 0;
        $highestSubmittedStageName = null;
        
        foreach ($stages as $stage) {
            if ($stage['isSubmitted'] == 1) {
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
    
    $project['current_stage'] = $currentStage;
}
unset($project); // break reference

// Calculate statistics
$totalProjects = count($projects);
$finishedProjects = 0;
foreach ($projects as $project) {
    if (strtolower(trim($project['projectStatus'] ?? 'in-progress')) === 'finished') {
        $finishedProjects++;
    }
}
$ongoingProjects = $totalProjects - $finishedProjects;

// Output the HTML directly - no PDF conversion needed
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DepEd BAC Summary Report</title>
    <link rel="stylesheet" href="assets/css/background.css">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 0; 
            color: #333; 
            line-height: 1.4; 
            background-color: #fdf0d3;
            min-height: 100vh;
        }
        
        .main-container {
            max-width: 1400px;
            margin: 20px auto;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            position: relative;
            z-index: 1;
        }
        
        .header { 
            text-align: center; 
            margin-bottom: 30px; 
            border-bottom: 2px solid #c62828; 
            padding-bottom: 20px; 
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .header-content {
            flex: 1;
            text-align: center;
        }
        .header-logo {
            width: 80px;
            height: 80px;
            object-fit: contain;
        }
        .header-logo.left {
            margin-right: 20px;
        }
        .header-logo.right {
            margin-left: 20px;
        }
        .header h1 { color: #c62828; margin: 0; font-size: 24px; }
        .header h2 { color: #666; margin: 5px 0; font-size: 18px; }
        .report-info { 
            display: flex; 
            justify-content: space-between; 
            align-items: flex-start; 
            margin-bottom: 20px; 
            font-size: 12px; 
            color: #666; 
        }
        .report-info-left {
            text-align: left;
            font-size: 10px;
            color: #888;
            line-height: 1.3;
        }
        .report-info-right {
            text-align: right;
        }
        .stats-summary { 
            margin-bottom: 30px; 
            background-color: #fdf0d3; 
            padding: 25px; 
            border-radius: 8px; 
            border: 1px solid #e0e0e0;
        }
        .stats-summary h3 { margin-top: 0; color: #c62828; font-size: 28px; }
        .stats-grid { display: flex; justify-content: space-around; text-align: center; }
        .stat-item { flex: 1; padding: 20px; }
        .stat-value { font-size: 36px; font-weight: bold; display: block; margin: 10px 0; }
        .stat-value.total { color: #6c757d; }
        .stat-value.done { color: #28a745; }
        .stat-value.ongoing { color: #007bff; }
        
        .table-container {
            width: 100%;
            overflow-x: auto;
            margin-top: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
        }
        
        table { 
            width: 100%; 
            border-collapse: collapse; 
            font-size: 12px; 
            min-width: 1100px;
            table-layout: auto;
            margin: 0;
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 10px 8px; 
            text-align: left; 
            vertical-align: top;
            word-wrap: break-word;
            word-break: break-word;
            overflow-wrap: break-word;
            white-space: normal;
            line-height: 1.3;
        }
        th { 
            background-color: #c62828; 
            color: white; 
            font-weight: bold; 
            position: sticky;
            top: 0;
            z-index: 10;
            font-size: 13px;
        }
        
        /* Optimized column widths for better fit */
        th:nth-child(1), td:nth-child(1) { width: 110px; min-width: 110px; } /* Mode of Procurement */
        th:nth-child(2), td:nth-child(2) { width: 70px; min-width: 70px; }  /* PR Number */
        th:nth-child(3), td:nth-child(3) { 
            width: 250px; 
            min-width: 200px;
            max-width: 300px;
            word-wrap: break-word !important;
            word-break: break-all !important;
            overflow-wrap: break-word !important;
            white-space: normal !important;
            hyphens: auto;
        } /* Project Details */
        th:nth-child(4), td:nth-child(4) { width: 90px; min-width: 90px; } /* Project Owner */
        th:nth-child(5), td:nth-child(5) { width: 90px; min-width: 90px; } /* Created By */
        th:nth-child(6), td:nth-child(6) { width: 100px; min-width: 100px; } /* Date Created */
        th:nth-child(7), td:nth-child(7) { width: 100px; min-width: 100px; } /* Date Edited */
        th:nth-child(8), td:nth-child(8) { width: 110px; min-width: 110px; } /* Current Stage */
        th:nth-child(9), td:nth-child(9) { width: 80px; min-width: 80px; }  /* Status */
        tr:nth-child(even) { background-color: #f9f9f9; }
        .status-done { 
            color: #28a745;
            font-weight: bold;
            font-size: 12px;
        }
        .status-ongoing { 
            color: #007bff;
            font-weight: bold;
            font-size: 12px;
        }
        .no-projects { text-align: center; padding: 20px; color: #666; }
        .footer { margin-top: 30px; text-align: center; font-size: 10px; color: #666; border-top: 1px solid #ddd; padding-top: 10px; }
        
        /* Print Controls */
        .print-controls {
            text-align: center;
            margin-bottom: 20px;
            padding: 15px;
            background-color: #e9ecef;
            border-radius: 5px;
        }
        
        .action-btn {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 10px 20px;
            margin: 0 10px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .print-btn {
            background-color: #28a745;
            color: white;
        }
        
        .print-btn:hover {
            background-color: #218838;
        }
        
        .pdf-btn {
            background-color: #dc3545;
            color: white;
        }
        
        .pdf-btn:hover {
            background-color: #c82333;
        }
        
        /* Developer credits footer - hidden on screen, only visible when printing */
        .developer-credits {
            display: none !important;
        }
        
        /* Print controls */
        .print-controls { text-align: center; margin: 20px 0; background: #f8f9fa; padding: 15px; border-radius: 8px; }
        .action-btn { 
            border: none; 
            padding: 12px 20px; 
            border-radius: 5px; 
            cursor: pointer; 
            font-size: 16px;
            margin: 0 10px;
            transition: all 0.3s;
            font-weight: 500;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .print-btn {
            background-color: #28a745;
            color: white;
        }
        .print-btn:hover { 
            background-color: #218838; 
            transform: translateY(-1px);
        }
        .pdf-btn {
            background-color: #dc3545;
            color: white;
        }
        .pdf-btn:hover { 
            background-color: #c82333;
            transform: translateY(-1px);        }
        
        /* Screen-only styles - ensure credits are hidden */
        @media screen {
            .developer-credits {
                display: none !important;
            }
        }
    
        /* Hide print controls when printing */
        @media print {
            /* Suggest landscape orientation for better table layout */
            @page {
                size: A4 landscape;
                margin: 0.3in 0.2in;
            }
            
            .print-controls { display: none !important; }
            body { 
                margin: 0; 
                font-size: 10px; 
                background-color: white !important;
                line-height: 1.1;
            }
            .main-container {
                max-width: none;
                margin: 0;
                padding: 5px;
                box-shadow: none;
                border-radius: 0;
            }
            .header { 
                page-break-after: avoid;
                flex-direction: row;
                justify-content: center;
                align-items: center;
                margin-bottom: 8px;
                padding-bottom: 5px;
            }
            .header-logo {
                width: 40px;
                height: 40px;
            }
            .header h1 { font-size: 16px; margin: 0; }
            .header h2 { font-size: 12px; margin: 1px 0; }
            
            .stats-summary {
                background-color: white !important;
                border: 1px solid #ddd;
                margin-bottom: 8px;
                padding: 8px;
            }
            .stats-summary h3 { font-size: 14px; margin: 0 0 5px 0; }
            .stat-value { font-size: 16px; margin: 2px 0; }
            
            .table-container {
                overflow: visible !important;
                border: none;
                margin: 0;
                padding: 0;
            }
            
            table { 
                page-break-inside: auto; 
                font-size: 8px;
                table-layout: fixed;
                width: 100%;
                min-width: auto !important;
                border-collapse: collapse;
                margin: 0;
                page-break-before: auto;
                page-break-after: auto;
            }
            
            /* Allow table rows to break across pages */
            tbody {
                page-break-inside: auto;
            }
            
            tr {
                page-break-inside: avoid;
                page-break-after: auto;
            }
            th, td { 
                padding: 2px 1px;
                word-wrap: break-word;
                word-break: break-word;
                overflow-wrap: break-word;
                white-space: normal;
                vertical-align: top;
                font-size: 8px;
                line-height: 1.1;
            }
            
            /* Optimized print column widths to fit in landscape */
            th:nth-child(1), td:nth-child(1) { width: 11%; } /* Mode of Procurement */
            th:nth-child(2), td:nth-child(2) { width: 7%; }  /* PR Number */
            th:nth-child(3), td:nth-child(3) { 
                width: 25%;
                word-wrap: break-word !important;
                word-break: break-all !important;
                overflow-wrap: break-word !important;
                white-space: normal !important;
                hyphens: auto;
                font-size: 7px;
            } /* Project Details */
            th:nth-child(4), td:nth-child(4) { width: 9%; }  /* Project Owner */
            th:nth-child(5), td:nth-child(5) { width: 9%; }  /* Created By */
            th:nth-child(6), td:nth-child(6) { width: 11%; } /* Date Created */
            th:nth-child(7), td:nth-child(7) { width: 11%; } /* Date Edited */
            th:nth-child(8), td:nth-child(8) { width: 10%; }  /* Current Stage */
            th:nth-child(9), td:nth-child(9) { width: 7%; }  /* Status */
            
            /* Status text styling for print - smaller font size */
            .status-done, .status-ongoing {
                font-size: 7px !important;
                font-weight: normal !important;
            }
            
            /* Ensure text doesn't rotate and fits properly */
            th:nth-child(8), td:nth-child(8),
            th:nth-child(9), td:nth-child(9) {
                writing-mode: horizontal-tb !important;
                text-orientation: mixed !important;
            }
            
            .report-info {
                font-size: 7px;
                margin-bottom: 5px;
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
            }
            .report-info-left {
                font-size: 6px;
                line-height: 1.2;
            }
            .report-info-right {
                font-size: 7px;
                text-align: right;
            }
            
            .footer {
                font-size: 6px;
                margin-top: 8px;
                padding-top: 3px;
            }
        }
        
        /* Responsive adjustments */
        @media (max-width: 768px) {
            body { 
                margin: 0; 
                background-color: #fdf0d3;
                padding-top: 70px;
            }
            .main-container {
                margin: 10px;
                padding: 15px;
                border-radius: 8px;
            }
            .header {
                flex-direction: column;
                padding: 15px;
                margin-bottom: 15px;
            }
            .header-logo {
                width: 50px;
                height: 50px;
                margin: 8px 0 !important;
            }
            .header-content h1 {
                font-size: 16px;
                margin: 5px 0;
            }
            .header-content h2 {
                font-size: 12px;
                margin: 2px 0;
            }
            .report-info {
                flex-direction: column;
                gap: 10px;
                margin-bottom: 15px;
                font-size: 10px;
            }
            .report-info-left {
                font-size: 8px;
                text-align: left;
            }
            .report-info-right {
                font-size: 10px;
                text-align: left;
            }
            .stats-summary {
                padding: 15px;
                margin-bottom: 15px;
            }
            .stats-summary h3 {
                font-size: 16px;
                margin-bottom: 10px;
            }
            .table-container {
                margin: 10px -15px; /* Extend beyond container padding */
                border-radius: 0;
            }
            table { 
                font-size: 9px;
                min-width: 600px; /* Reduced for mobile */
            }
            th, td { 
                padding: 4px 2px;
                font-size: 9px;
            }
            th:nth-child(3), td:nth-child(3) {
                max-width: 120px;
                font-size: 8px;
            }
            .stats-grid { 
                flex-direction: column; 
                gap: 10px;
            }
            .stat-item { 
                margin-bottom: 8px; 
                padding: 12px;
            }
            .stat-value {
                font-size: 24px;
            }
            .print-controls {
                margin: 10px -15px 15px -15px;
                padding: 10px;
            }
            .action-btn {
                display: block;
                margin: 8px auto;
                width: 180px;
                justify-content: center;
                font-size: 13px;
                padding: 10px 15px;
            }
        }
        
        @media (max-width: 480px) {
            body {
                padding-top: 60px;
            }
            .main-container {
                margin: 5px;
                padding: 10px;
            }
            .header {
                padding: 10px;
            }
            .header-logo {
                width: 40px;
                height: 40px;
            }
            .header-content h1 {
                font-size: 14px;
            }
            .header-content h2 {
                font-size: 10px;
            }
            .report-info {
                font-size: 9px;
                margin-bottom: 10px;
            }
            .report-info-left {
                font-size: 7px;
            }
            .report-info-right {
                font-size: 9px;
            }
            .stats-summary {
                padding: 10px;
                margin-bottom: 10px;
            }
            .stats-summary h3 {
                font-size: 14px;
                margin-bottom: 8px;
            }
            .table-container {
                margin: 5px -10px;
            }
            table {
                font-size: 8px;
                min-width: 500px;
            }
            th, td {
                padding: 3px 1px;
                font-size: 8px;
            }
            th:nth-child(3), td:nth-child(3) {
                max-width: 100px;
                font-size: 7px;
            }
            .stat-item {
                padding: 8px;
                margin-bottom: 6px;
            }
            .stat-value {
                font-size: 20px;
            }
            .print-controls {
                margin: 5px -10px 10px -10px;
                padding: 8px;
            }
            .action-btn {
                width: 160px;
                font-size: 12px;
                padding: 8px 12px;
                margin: 6px auto;
            }
        }
    </style>
</head>
<body>
    <div class='main-container'>
        <div class='header'>
            <img src='assets/images/DEPED-LAOAG_SEAL_Glow.png' alt='DepEd Laoag Seal' class='header-logo left'>
            <div class='header-content'>
                <h1>SCHOOLS DIVISION OF LAOAG CITY</h1>
                <h2>DEPARTMENT OF EDUCATION</h2>
                <h2>BAC TRACKING SYSTEM - SUMMARY REPORT</h2>
            </div>
            <img src='assets/images/DepEd_Logo.png' alt='DepEd Logo' class='header-logo right'>
        </div>
    
    <div class='report-info'>
        <div class='report-info-left'>
            <strong>DEPEDBAC_TS DEVELOPED BY:</strong><br>
            N. LUCAS - N. SANTOS - M. BUMANGLAG - M. VILLANUEVA
        </div>
        <div class='report-info-right'>
            <strong>Report Generated:</strong> <?php echo $reportDate; ?> at <?php echo $reportTime; ?><br>
            <strong>Generated by:</strong> <?php echo htmlspecialchars($_SESSION['username']); ?><?php echo $search ? " (Filtered by: '" . htmlspecialchars($search) . "')" : ""; ?>
        </div>
    </div>
    
    <div class='print-controls'>
        <button class='action-btn print-btn' onclick='printReport()'>
            🖨️ Print Report
        </button>
        <button class='action-btn pdf-btn' onclick='saveAsPDF()'>
            📄 Save as PDF
        </button>
    </div>
    
    <div class='main-content'>
        <div class='stats-summary'>
            <h3>Project Statistics Overview</h3>
            <div class='stats-grid'>
                <div class='stat-item'>
                    <span class='stat-value total'><?php echo $totalProjects; ?></span>
                    <div>Total Projects</div>
                </div>
                <div class='stat-item'>
                    <span class='stat-value done'><?php echo $finishedProjects; ?></span>
                    <div>Completed Projects</div>
                </div>
                <div class='stat-item'>
                    <span class='stat-value ongoing'><?php echo $ongoingProjects; ?></span>
                    <div>Ongoing Projects</div>
                </div>
            </div>
        </div>

    <?php if (!empty($projects)): ?>
        <div class='table-container'>
            <table>
                <thead>
                    <tr>
                        <th>Mode of Procurement</th>
                        <th>PR Number</th>
                        <th>Project Details</th>
                        <th>Project Owner</th>
                        <th>Created By</th>
                        <th>Date Created</th>
                        <th>Date Edited</th>
                        <th>Current Stage</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($projects as $project): ?>
                    <?php
                    $currentStageDisplay = 'N/A';
                    $statusClass = 'status-ongoing';
                    $statusText = 'Ongoing';
                    
                    if (strtolower(trim($project['projectStatus'] ?? 'in-progress')) === 'finished') {
                        $currentStageDisplay = 'Finished';
                        $statusClass = 'status-done';
                        $statusText = 'Done';
                    } elseif ($project['current_stage']) {
                        $currentStageDisplay = htmlspecialchars($project['current_stage']);
                    }
                    
                    $dateCreated = $project['createdAt'] ? date("m-d-Y h:i A", strtotime($project['createdAt'])) : 'N/A';
                    $dateEdited = $project['editedAt'] ? date("m-d-Y h:i A", strtotime($project['editedAt'])) : 'N/A';
                    ?>
                    <tr>
                        <td><?php echo htmlspecialchars($project['mode_of_procurement'] ?? 'N/A'); ?></td>
                        <td><?php echo htmlspecialchars($project['prNumber'] ?? 'N/A'); ?></td>
                        <td><?php echo htmlspecialchars($project['projectDetails'] ?? 'N/A'); ?></td>
                        <td><?php echo htmlspecialchars($project['programOwner'] ?? 'N/A'); ?></td>
                        <td><?php echo htmlspecialchars(($project['firstname'] ?? '') . ' ' . ($project['lastname'] ?? '')); ?></td>
                        <td><?php echo $dateCreated; ?></td>
                        <td><?php echo $dateEdited; ?></td>
                        <td><?php echo $currentStageDisplay; ?></td>
                        <td class='<?php echo $statusClass; ?>'><?php echo $statusText; ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        </div> <!-- End table-container -->
    <?php else: ?>
        <div class='no-projects'>No projects found matching the criteria.</div>
    <?php endif; ?>
    
    <div class='footer'>
        This report was generated automatically by the DepEd BAC Tracking System.<br>
        For questions or concerns, please contact the system administrator.
    </div>
    </div> <!-- End main-container -->
    
    <script>
        // Auto-focus for better user experience
        window.onload = function() {
            console.log('Summary report loaded successfully');
        };
        
        // Handle print button - opens print dialog
        function printReport() {
            window.print();
        }
        
        // Handle save as PDF - uses browser's print to PDF functionality
        function saveAsPDF() {
            // For modern browsers, we can suggest Print to PDF
            if (window.navigator.userAgent.indexOf('Chrome') > -1 || 
                window.navigator.userAgent.indexOf('Firefox') > -1 || 
                window.navigator.userAgent.indexOf('Safari') > -1) {
                
                // Show a helpful message
                alert('To save as PDF:\n\n1. Click OK to open the print dialog\n2. Select "Save as PDF" or "Microsoft Print to PDF" as your printer\n3. Click Print/Save to download the PDF file');
                
                // Open print dialog
                window.print();
            } else {
                // Fallback for older browsers
                window.print();
            }
        }
    </script>
</body>
</html>
