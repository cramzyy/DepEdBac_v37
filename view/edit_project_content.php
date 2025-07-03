<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Edit Project - DepEd BAC Tracking System</title>
    <link rel="stylesheet" href="assets/css/edit_project.css">
    <link rel="stylesheet" href="assets/css/background.css">
</head>
<body class="<?php echo $isAdmin ? 'admin-view' : 'user-view'; ?>">
    <?php include 'header.php'; ?>

    <script>
        // Pass PHP variables to JavaScript
        window.firstUnsubmittedStageName = <?php echo json_encode($firstUnsubmittedStageName); ?>;
        window.showSuccessToast = <?php echo isset($_SESSION['stageSuccess']) ? 'true' : 'false'; ?>;
        window.isAdmin = <?php echo $isAdmin ? 'true' : 'false'; ?>;
    </script>

    <div class="dashboard-container">
        
        <a href="<?php echo url('index.php'); ?>" class="back-btn">&larr; </a>  

        <h1>Edit Project</h1>

        <?php
            if (isset($errorHeader)) { echo "<p class='project-error-message'>$errorHeader</p>"; }
            if (isset($successHeader)) { echo "<p class='project-success-message'>$successHeader</p>"; }
            if (isset($stageError)) { echo "<p class='project-error-message'>$stageError</p>"; }
        ?>

        <div class="project-info-card">
            <h3>Project Information</h3>
            <?php if ($isAdmin): ?>
                <form action="edit_project.php?projectID=<?php echo $projectID; ?>" method="post" class="project-form">
            <?php endif; ?>
            
            <div class="project-info-grid">
                <div class="project-info-item">
                    <label for="prNumber">PR Number</label>
                    <?php if ($isAdmin): ?>
                        <input type="text" name="prNumber" id="prNumber" value="<?php echo htmlspecialchars($project['prNumber']); ?>" required>
                    <?php else: ?>
                        <div class="value"><?php echo htmlspecialchars($project['prNumber']); ?></div>
                    <?php endif; ?>
                </div>

                <div class="project-info-item">
                    <label>Project Status</label>
                    <div class="value">
                        <?php if ($isAdmin): ?>
                            <span class="status-badge <?php echo ($project['projectStatus'] ?? 'in-progress') === 'finished' ? 'finished' : 'in-progress'; ?> clickable" 
                                  onclick="showStatusModal('<?php echo ($project['projectStatus'] ?? 'in-progress') === 'finished' ? 'in-progress' : 'finished'; ?>')">
                                <?php echo ($project['projectStatus'] ?? 'in-progress') === 'finished' ? 'Finished' : 'In Progress'; ?>
                            </span>
                        <?php else: ?>
                            <span class="status-badge <?php echo ($project['projectStatus'] ?? 'in-progress') === 'finished' ? 'finished' : 'in-progress'; ?>">
                                <?php echo ($project['projectStatus'] ?? 'in-progress') === 'finished' ? 'Finished' : 'In Progress'; ?>
                            </span>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="project-info-item project-details-full">
                    <label for="projectDetails">Project Details</label>
                    <?php if ($isAdmin): ?>
                        <textarea name="projectDetails" id="projectDetails" rows="3" required><?php echo htmlspecialchars($project['projectDetails']); ?></textarea>
                    <?php else: ?>
                        <div class="value"><?php echo htmlspecialchars($project['projectDetails']); ?></div>
                    <?php endif; ?>
                </div>

                <div class="project-info-item">
                    <label>Total ABC</label>
                    <?php if ($isAdmin): ?>
                        <input type="number" name="totalABC" id="totalABC"
                            value="<?php echo htmlspecialchars($project['totalABC']); ?>"
                            required min="0" step="1">
                    <?php else: ?>
                        <div class="value">
                            <?php echo isset($project['totalABC']) ? '₱' . number_format($project['totalABC']) : 'N/A'; ?>
                        </div>
                    <?php endif; ?>
                </div>

                <div class="project-info-item">
                    <label>Mode of Procurement</label>
                    <div class="value"><?php echo htmlspecialchars($project['MoPDescription'] ?? 'N/A'); ?></div>
                </div>

                <div class="project-info-item">
                    <label>Date Created</label>
                    <div class="value"><?php echo date("M d, Y h:i A", strtotime($project['createdAt'])); ?></div>
                </div>

                <div class="project-info-item">
                    <label>Last Accessed By</label>
                    <div class="value">
                        <?php
                        if (!empty($project['lastAccessedBy']) && !empty($project['lastAccessedAt']) && isset($lastAccessedByName) && $lastAccessedByName !== "N/A") {
                            // Get office info for the last accessed user
                            $stmtAccessUserOffice = $pdo->prepare("SELECT o.officename FROM tbluser u LEFT JOIN officeid o ON u.officeID = o.officeID WHERE u.userID = ?");
                            $stmtAccessUserOffice->execute([$project['lastAccessedBy']]);
                            $accessUserOffice = $stmtAccessUserOffice->fetch();
                            $accessOfficeInfo = $accessUserOffice ? htmlspecialchars($accessUserOffice['officename'] ?? 'N/A') : 'N/A';
                            
                            echo $lastAccessedByName . "<br><small>Office: " . $accessOfficeInfo . "</small><br><small>" . date("M d, Y h:i A", strtotime($project['lastAccessedAt'])) . "</small>";
                        } else {
                            echo "Not Available";
                        }
                        ?>
                    </div>
                </div>

                <div class="project-info-item">
                    <label>Created By</label>
                    <div class="value"><?php echo htmlspecialchars($project['creator_firstname'] . " " . $project['creator_lastname']); ?><br>
                    <small>Office: <?php echo htmlspecialchars($project['officename'] ?? 'N/A'); ?></small></div>
                </div>

                <div class="project-info-item">
                    <label>Last Updated</label>
                    <div class="value">
                        <?php
                        $lastUpdatedInfo = "Not Available";
                        if (!empty($project['editedBy']) && !empty($project['editedAt'])) {
                            $stmtEditUser = $pdo->prepare("SELECT u.firstname, u.lastname, o.officename FROM tbluser u LEFT JOIN officeid o ON u.officeID = o.officeID WHERE u.userID = ?");
                            $stmtEditUser->execute([$project['editedBy']]);
                            $editUser = $stmtEditUser->fetch();
                            if ($editUser) {
                                $editUserFullName = htmlspecialchars($editUser['firstname'] . " " . $editUser['lastname']);
                                $editUserOffice = htmlspecialchars($editUser['officename'] ?? 'N/A');
                                echo $editUserFullName . "<br><small>Office: " . $editUserOffice . "</small><br><small>" . date("M d, Y h:i A", strtotime($project['editedAt'])) . "</small>";
                            } else {
                                echo $lastUpdatedInfo;
                            }
                        } else {
                            echo $lastUpdatedInfo;
                        }
                        ?>
                    </div>
                </div>

                <div class="project-info-item">
                    <label>Program Owner</label>
                    <div class="value">
                        <?php echo htmlspecialchars($project['programOwner'] ?? 'N/A'); ?>
                        <?php if (!empty($project['programOffice'])): ?>
                            <br><small>Office: <?php echo htmlspecialchars($project['programOffice']); ?></small>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            
            <?php if ($isAdmin): ?>
                <button type="submit" name="update_project_header" class="update-project-btn">
                    Update Project Information
                </button>
                </form>
            <?php endif; ?>
        </div>

        <div class="stage-management-card">
            <h3>Project Stages Management</h3>
            
            <!-- Stage Selection Dropdown -->
            <!-- Replace the existing stage dropdown form with this -->
            <div class="stage-dropdown-container" id="stageDropdownSection">
                <form method="post" id="stageDropdownForm">
                    <label for="stageDropdown">Create New Stage</label>
                    <select id="stageDropdown" name="stageName" required>
                        <option value="">-- Select a Stage to Create --</option>
                        <?php foreach ($stagesOrder as $stage): ?>
                            <?php if ($stage !== 'Mode Of Procurement' && !isset($stagesMap[$stage])): ?>
                                <option value="<?php echo htmlspecialchars($stage); ?>"><?php echo htmlspecialchars($stage); ?></option>
                            <?php endif; ?>
                        <?php endforeach; ?>
                    </select>
                    <button type="button" onclick="showStageModal()">Create Stage</button>
                    <input type="hidden" name="create_stage" id="create_stage_hidden">
                </form>
            </div>

            <!-- Stages Table -->
            <div class="stages-table-container">
                <table id="stagesTable">
                    <thead>
                        <tr>
                        <th class="col-stage">Stage Name</th>
                        <th class="col-created">Date Created</th>
                        <th class="col-approved">Date Approved</th>
                        <th class="col-office">Office</th>
                        <th class="col-remark">Remarks</th>
                        <th class="col-status">Status</th>
                    </tr>
                </thead>
                <!-- Replace the stages table section in edit_project_content.php -->
                 <tbody>
                    <?php
                    // Display only Mode Of Procurement and created stages
                    foreach ($stagesOrder as $index => $stage):
                        // Always show Mode Of Procurement
                        if ($stage === 'Mode Of Procurement'):
                    ?>
                        <tr data-stage="<?php echo htmlspecialchars($stage); ?>">
                            <td><?php echo htmlspecialchars($stage); ?></td>
                            <td colspan="4">
                                <div class="readonly-field">
                                    <?php echo htmlspecialchars($project['MoPDescription'] ?? 'N/A'); ?>
                                </div>
                            </td>
                            <td>
                                <button type="button" class="submit-stage-btn autofilled" disabled>Autofilled</button>
                            </td>
                        </tr>
                    <?php
                            continue;
                        endif;

                        // Only show stages that exist in $stagesMap (i.e., created)
                        if (!isset($stagesMap[$stage])) continue;

                        $safeStage = str_replace(' ', '_', $stage);
                        $currentStageData = $stagesMap[$stage] ?? null;
                        $currentSubmitted = ($currentStageData && $currentStageData['isSubmitted'] == 1);

                        $value_created = ($currentStageData && !empty($currentStageData['createdAt']))
                            ? date("Y-m-d\TH:i", strtotime($currentStageData['createdAt'])) : "";
                        $value_approved = ($currentStageData && !empty($currentStageData['approvedAt']))
                            ? date("Y-m-d\TH:i", strtotime($currentStageData['approvedAt'])) : "";
                        $value_remark = ($currentStageData && !empty($currentStageData['remarks']))
                            ? htmlspecialchars($currentStageData['remarks']) : "";

                        $displayOfficeName = "Not set";
                        if (isset($currentStageData['officeID']) && isset($officeList[$currentStageData['officeID']])) {
                            $displayOfficeName = htmlspecialchars($currentStageData['officeID'] . ' - ' . $officeList[$currentStageData['officeID']]);
                        }
                    ?>
                    <tr data-stage="<?php echo htmlspecialchars($stage); ?>">
                        <td><?php echo htmlspecialchars($stage); ?></td>
                        <td>
                            <input type="datetime-local" value="<?php echo $value_created; ?>" disabled>
                        </td>
                        <td>
                            <?php if ($currentSubmitted): ?>
                                <input type="datetime-local" value="<?php echo $value_approved; ?>" disabled>
                            <?php else: ?>
                                <input type="datetime-local" 
                                    id="approvedAt_<?php echo $safeStage; ?>" 
                                    value="<?php echo ($currentStageData && !empty($currentStageData['approvedAt'])) ? date("Y-m-d\TH:i", strtotime($currentStageData['approvedAt'])) : ""; ?>" 
                                    required>
                            <?php endif; ?>
                        </td>
                        <td>
                            <div class="readonly-office-field"><?php echo $displayOfficeName; ?></div>
                        </td>
                        <td>
                            <?php if ($currentSubmitted): ?>
                                <input type="text" value="<?php echo $value_remark; ?>" disabled>
                            <?php else: ?>
                                <input type="text" 
                                    id="remark_<?php echo $safeStage; ?>" 
                                    value="<?php echo $value_remark; ?>" 
                                    placeholder="Remarks (optional)">
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ($currentSubmitted): ?>
                                <?php if ($isAdmin): ?>
                                    <button type="button" 
                                            class="submit-stage-btn unsubmit-btn" 
                                            onclick="showDeleteModal('<?php echo htmlspecialchars($stage); ?>')">
                                        Delete
                                    </button>
                                <?php else: ?>
                                    <button type="button" class="submit-stage-btn completed" disabled>Submitted</button>
                                <?php endif; ?>
                            <?php else: ?>
                                <button type="button" 
                                        class="submit-stage-btn available" 
                                        onclick="showSubmitModal('<?php echo htmlspecialchars($stage); ?>')">
                                    Submit
                                </button>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
          </div>
            
            <!-- Mobile Stages Cards -->
            <div class="mobile-stages-cards">
                <?php
                // Display only Mode Of Procurement and created stages for mobile
                foreach ($stagesOrder as $index => $stage):
                    // Always show Mode Of Procurement
                    if ($stage === 'Mode Of Procurement'):
                ?>
                    <div class="mobile-stage-card" data-stage="<?php echo htmlspecialchars($stage); ?>">
                        <div class="mobile-stage-card-header">
                            <div class="mobile-stage-card-title"><?php echo htmlspecialchars($stage); ?></div>
                            <div class="mobile-stage-card-status autofilled">Autofilled</div>
                        </div>
                        <div class="mobile-stage-card-body">
                            <div class="mobile-stage-card-item">
                                <div class="mobile-stage-card-label">Description</div>
                                <div class="mobile-stage-card-value">
                                    <?php echo htmlspecialchars($project['MoPDescription'] ?? 'N/A'); ?>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php
                        continue;
                    endif;

                    // Only show stages that exist in $stagesMap (i.e., created)
                    if (!isset($stagesMap[$stage])) continue;

                    $safeStage = str_replace(' ', '_', $stage);
                    $currentStageData = $stagesMap[$stage] ?? null;
                    $currentSubmitted = ($currentStageData && $currentStageData['isSubmitted'] == 1);

                    $value_created = ($currentStageData && !empty($currentStageData['createdAt']))
                        ? date("M d, Y h:i A", strtotime($currentStageData['createdAt'])) : "Not set";
                    $value_approved = ($currentStageData && !empty($currentStageData['approvedAt']))
                        ? date("M d, Y h:i A", strtotime($currentStageData['approvedAt'])) : "Not set";
                    $value_remark = ($currentStageData && !empty($currentStageData['remarks']))
                        ? htmlspecialchars($currentStageData['remarks']) : "No remarks";

                    $displayOfficeName = "Not set";
                    if (isset($currentStageData['officeID']) && isset($officeList[$currentStageData['officeID']])) {
                        $displayOfficeName = htmlspecialchars($currentStageData['officeID'] . ' - ' . $officeList[$currentStageData['officeID']]);
                    }

                    $statusClass = $currentSubmitted ? 'completed' : 'available';
                    $statusText = $currentSubmitted ? 'Submitted' : 'Pending';
                ?>
                    <div class="mobile-stage-card" data-stage="<?php echo htmlspecialchars($stage); ?>">
                        <div class="mobile-stage-card-header">
                            <div class="mobile-stage-card-title"><?php echo htmlspecialchars($stage); ?></div>
                            <div class="mobile-stage-card-status <?php echo $statusClass; ?>"><?php echo $statusText; ?></div>
                        </div>
                        <div class="mobile-stage-card-body">
                            <div class="mobile-stage-card-item">
                                <div class="mobile-stage-card-label">Date Created</div>
                                <div class="mobile-stage-card-value"><?php echo $value_created; ?></div>
                            </div>
                            <div class="mobile-stage-card-item">
                                <div class="mobile-stage-card-label">Date Approved</div>
                                <div class="mobile-stage-card-value">
                                    <?php if ($currentSubmitted): ?>
                                        <?php echo $value_approved; ?>
                                    <?php else: ?>
                                        <input type="datetime-local" 
                                            id="mobile_approvedAt_<?php echo $safeStage; ?>" 
                                            value="<?php echo ($currentStageData && !empty($currentStageData['approvedAt'])) ? date("Y-m-d\TH:i", strtotime($currentStageData['approvedAt'])) : date("Y-m-d\TH:i"); ?>">
                                    <?php endif; ?>
                                </div>
                            </div>
                            <div class="mobile-stage-card-item">
                                <div class="mobile-stage-card-label">Office</div>
                                <div class="mobile-stage-card-value"><?php echo $displayOfficeName; ?></div>
                            </div>
                            <div class="mobile-stage-card-item">
                                <div class="mobile-stage-card-label">Remarks</div>
                                <div class="mobile-stage-card-value">
                                    <?php if ($currentSubmitted): ?>
                                        <?php echo $value_remark; ?>
                                    <?php else: ?>
                                        <input type="text" 
                                            id="mobile_remark_<?php echo $safeStage; ?>" 
                                            value="<?php echo ($currentStageData && !empty($currentStageData['remarks'])) ? htmlspecialchars($currentStageData['remarks']) : ""; ?>" 
                                            placeholder="Enter remarks (optional)">
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                        <div class="mobile-stage-card-actions">
                            <?php if ($currentSubmitted): ?>
                                <?php if ($isAdmin): ?>
                                    <button type="button" 
                                            class="mobile-stage-action-btn delete-btn" 
                                            onclick="showDeleteModal('<?php echo htmlspecialchars($stage); ?>')">
                                        Delete
                                    </button>
                                <?php else: ?>
                                    <button type="button" class="mobile-stage-action-btn" disabled>Submitted</button>
                                <?php endif; ?>
                            <?php else: ?>
                                <button type="button" 
                                        class="mobile-stage-action-btn submit-btn" 
                                        onclick="showSubmitModal('<?php echo htmlspecialchars($stage); ?>')">
                                    Submit
                                </button>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
            
          </div>
        </div>


        
        <!-- Add this modal HTML before the closing </div> of dashboard-container -->
        <div id="stageModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h4>Create New Stage</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to create the stage "<span id="stageNameText"></span>"?</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-cancel" onclick="closeStageModal()">Cancel</button>
                    <button type="button" class="btn-confirm" onclick="confirmCreateStage()">Create Stage</button>
                </div>
            </div>
        </div>
        
       <div id="submitModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h4>Submit Stage</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to submit the stage "<span id="submitStageNameText"></span>"?</p>
                    <p class="modal-warning">This action cannot be undone.</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-cancel" onclick="closeSubmitModal()">Cancel</button>
                    <button type="button" class="btn-confirm" onclick="confirmSubmitStage()">Submit Stage</button>
                </div>
            </div>
        </div>

        <div id="deleteModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h4>Delete Stage</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to delete the stage "<span id="deleteStageNameText"></span>"?</p>
                    <p class="modal-warning" style="color: #dc3545; font-weight: bold;">This action will permanently remove the stage and all its data. This cannot be undone.</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-cancel" onclick="closeDeleteModal()">Cancel</button>
                    <button type="button" class="btn-confirm" style="background-color: #dc3545;" onclick="confirmDeleteStage()">Delete Stage</button>
                </div>
            </div>
        </div>

        <div id="statusModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h4>Change Project Status</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to change the project status to "<span id="newStatusText"></span>"?</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-cancel" onclick="closeStatusModal()">Cancel</button>
                    <button type="button" class="btn-confirm" onclick="confirmStatusChange()">Change Status</button>
                </div>
            </div>
        </div>

        <!-- Toast Success Notification -->
        <?php if (isset($_SESSION['stageSuccess'])): ?>
        <div id="toast-success" class="toast-success">
            <?php echo htmlspecialchars($_SESSION['stageSuccess']); ?>
        </div>
        <?php unset($_SESSION['stageSuccess']); endif; ?>
    </div>

    <script src="assets/js/edit_project.js"></script>
</body>
</html>