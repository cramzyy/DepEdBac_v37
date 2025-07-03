<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard - DepEd BAC Tracking System</title>
    <link rel="stylesheet" href="assets/css/index.css">
    <link rel="stylesheet" href="assets/css/background.css">

    
</head>
<body>
    <?php
    // $showTitleRight is already set to false above
    include 'header.php';
    ?>

    <div class="main-content-wrapper">
        <div class="table-top-bar">
            <div class="left-controls">

                <button class="add-pr-button" id="showAddProjectForm">
                    <img src="assets/images/Add_Button.png" alt="Add" class="add-pr-icon">
                    Add Project
                </button>
            </div>

            <div class="center-search">
                <input type="text" id="searchInput" class="dashboard-search-bar" placeholder="Search by PR Number or Project Details..." value="<?php echo htmlspecialchars($search); ?>">
            </div>

            <div class="right-controls">
                <button class="view-stats-button" onclick="loadAndShowStatistics()">
                    <img src="assets/images/stats_icon.png" alt="Stats" class="icon-24">
                    View Statistics
                </button>
                <button class="summary-report-button" onclick="generateSummaryReport()" title="Generate a printable summary report of all projects">
                    <img src="assets/images/Magni_Icon.png" alt="Report" class="icon-24">
                    Summary Report
                </button>
            </div>
        </div>

        <?php if (!empty($deleteProjectError)): // Display delete error on main page ?>
            <p class="delete-error"><?php echo htmlspecialchars($deleteProjectError); ?></p>
        <?php endif; ?>
        

        <div class="container main-container">
            <!-- Desktop Table View -->
            <table class="dashboard-table">
                <thead>
                    <tr>
                        <th class="col-mode">
                            MODE OF PROCUREMENT
                            <div class="mode-filter-container">
                                <select id="filterMoP" class="mode-filter-select">
                                    <option value="">All Modes</option>
                                    <?php foreach ($mopList as $id => $desc): ?>
                                        <option value="<?php echo $id; ?>"><?php echo htmlspecialchars($desc); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                        </th>
                        <th class="col-pr-number">PR NUMBER</th>
                        <th class="col-project-details">PROJECT DETAILS</th>
                        <th class="col-project-owner">PROJECT OWNER</th> 
                        <th class="col-created-by">CREATED BY</th>
                        <th class="col-date-created">DATE CREATED</th>
                        <th class="col-date-edited">DATE EDITED</th>
                        <th class="col-status">STATUS</th>
                        <th class="col-actions">ACTIONS</th> 
                    </tr>
                </thead>
                <tbody>
                
                    <?php if (count($projects) > 0): ?>
                        <?php foreach ($projects as $project): ?>
                            <tr data-mop="<?php echo (int)$project['MoPID']; ?>">
                                <td>
                                    <?php
                                    if (!empty($project['MoPID'])) {
                                        echo htmlspecialchars($mopList[$project['MoPID']] ?? 'N/A');
                                    } else {
                                        echo 'N/A';
                                    }
                                    ?>
                                </td>
                
                                <td data-label="PR Number" class="pr-number-cell">
                                    <?php echo htmlspecialchars($project['prNumber']); ?>
                                </td>
                                <td data-label="Project Details" class="project-details-cell">
                                    <?php
                                        $details = htmlspecialchars($project['projectDetails']);
                                        $maxLength = 80; // Adjust as needed (character count)
                                        $id = 'details_' . $project['projectID'];
                                        if (mb_strlen($details) > $maxLength) {
                                            $short = mb_substr($details, 0, $maxLength) . '...';
                                            echo '<div class="project-details-container">';
                                            echo '<span class="project-details-short" id="' . $id . '_short">' . $short . ' <button class="see-more-btn" onclick="showFullDetails(\'' . $id . '\')">See more</button></span>';
                                            echo '<span class="project-details-full" id="' . $id . '_full">' . $details . ' <button class="see-less-btn" onclick="hideFullDetails(\'' . $id . '\')">See less</button></span>';
                                            echo '</div>';
                                        } else {
                                            echo '<div class="project-details-container">' . $details . '</div>';
                                        }
                                    ?>
                                </td>
                                <td data-label="Project Owner">
                                    <?php
                                        // Assuming programOwner might contain a first and last name separated by space
                                        $ownerParts = explode(' ', $project['programOwner'] ?? 'N/A', 2); // Limit to 2 parts in case of middle names
                                        $formattedOwner = 'N/A';

                                        if (count($ownerParts) > 1) {
                                            $formattedOwner = htmlspecialchars(substr($ownerParts[0], 0, 1) . ". " . $ownerParts[1]);
                                        } else if (count($ownerParts) == 1 && $ownerParts[0] !== 'N/A') {
                                            // If only one part, use it as the last name with a default initial or just the name
                                            $formattedOwner = htmlspecialchars(substr($ownerParts[0], 0, 1) . ". " . $ownerParts[0]);
                                        }

                                        echo $formattedOwner;

                                        if (!empty($project['programOffice'])) {
                                            echo " <br>(" . htmlspecialchars($project['programOffice']) . ")";
                                        }
                                    ?>
                                </td>
                                <td data-label="Created By">
                                    <?php
                                        if (!empty($project['firstname']) && !empty($project['lastname'])) {
                                            echo htmlspecialchars(substr($project['firstname'], 0, 1) . ". " . $project['lastname']);
                                        } else {
                                            echo "N/A";
                                        }
                                    ?>
                                </td>
                                <td data-label="Date Created"><?php echo $project['createdAt'] ? date("m-d-Y h:i A", strtotime($project['createdAt'])) : 'N/A'; ?></td>
                                <td data-label="Date Edited"><?php echo $project['editedAt'] ? date("m-d-Y h:i A", strtotime($project['editedAt'])) : 'N/A'; ?></td>
                                <td data-label="Status">
                                    <?php
                                        if (strtolower(trim($project['projectStatus'] ?? 'in-progress')) === 'finished') {
                                            echo 'Finished';
                                        } else {
                                            echo htmlspecialchars($project['first_unsubmitted_stage'] ?? 'No Stages Started');
                                        }
                                    ?>
                                </td>
                                <td data-label="Actions">
                                    <a href="<?php echo url('edit_project.php', ['projectID' => $project['projectID']]); ?>" class="edit-project-btn action-btn-spacing" title="Edit Project">
                                        <img src="assets/images/Edit_Icon.png" alt="Edit Project" class="icon-24">
                                    </a>
                                    <?php if (isset($_SESSION['admin']) && $_SESSION['admin'] == 1): ?>
                                    <button type="button" class="delete-btn" onclick="showDeleteProjectModal('<?php echo htmlspecialchars($project['prNumber']); ?>', '<?php echo $project['projectID']; ?>')" title="Delete Project">
                                        <img src="assets/images/delete.png" alt="Delete Project" class="icon-24">
                                    </button>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="9" id="noResults" class="no-results">No projects found.</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
            
            <!-- Mobile Card View -->
            <div class="mobile-project-cards">
                <?php if (count($projects) > 0): ?>
                    <?php foreach ($projects as $project): ?>
                        <div class="project-card" data-mop="<?php echo (int)$project['MoPID']; ?>">
                            <div class="project-card-header">
                                <div class="project-card-title">
                                    <div class="project-card-pr">PR: <?php echo htmlspecialchars($project['prNumber']); ?></div>
                                    <div class="project-card-mode">
                                        <?php
                                        if (!empty($project['MoPID'])) {
                                            echo htmlspecialchars($mopList[$project['MoPID']] ?? 'N/A');
                                        } else {
                                            echo 'N/A';
                                        }
                                        ?>
                                    </div>
                                </div>
                                <div class="project-card-actions">
                                    <a href="<?php echo url('edit_project.php', ['projectID' => $project['projectID']]); ?>" class="edit-project-btn mobile-action-btn" title="Edit Project">
                                        <img src="assets/images/Edit_Icon.png" alt="Edit" class="icon-24">
                                    </a>
                                    <?php if ($_SESSION['admin'] == 1): ?>
                                        <button type="button" class="delete-btn mobile-action-btn" onclick="showDeleteProjectModal('<?php echo htmlspecialchars($project['prNumber']); ?>', '<?php echo $project['projectID']; ?>')" title="Delete Project">
                                            <img src="assets/images/delete.png" alt="Delete" class="icon-24">
                                        </button>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <div class="project-card-body">
                                <div class="project-card-details" id="mobile_details_<?php echo $project['projectID']; ?>">
                                    <?php echo htmlspecialchars($project['projectDetails']); ?>
                                </div>
                                <?php if (mb_strlen($project['projectDetails']) > 100): ?>
                                    <button class="expand-toggle" onclick="toggleMobileDetails(<?php echo $project['projectID']; ?>)">
                                        Show more
                                    </button>
                                <?php endif; ?>
                                <div class="project-card-meta">
                                    <div class="project-card-meta-item">
                                        <span class="project-card-meta-label">Project Owner</span>
                                        <span>
                                            <?php
                                            $ownerParts = explode(' ', $project['programOwner'] ?? 'N/A', 2);
                                            $formattedOwner = 'N/A';
                                            if (count($ownerParts) > 1) {
                                                $formattedOwner = htmlspecialchars(substr($ownerParts[0], 0, 1) . ". " . $ownerParts[1]);
                                            } else if (count($ownerParts) == 1 && $ownerParts[0] !== 'N/A') {
                                                $formattedOwner = htmlspecialchars($ownerParts[0]);
                                            }
                                            echo $formattedOwner;
                                            ?>
                                        </span>
                                    </div>
                                    <div class="project-card-meta-item">
                                        <span class="project-card-meta-label">Created By</span>
                                        <span>
                                            <?php
                                            if (!empty($project['firstname']) && !empty($project['lastname'])) {
                                                echo htmlspecialchars(substr($project['firstname'], 0, 1) . ". " . $project['lastname']);
                                            } else {
                                                echo "N/A";
                                            }
                                            ?>
                                        </span>
                                    </div>
                                    <div class="project-card-meta-item">
                                        <span class="project-card-meta-label">Date Created</span>
                                        <span><?php echo $project['createdAt'] ? date("m/d/Y", strtotime($project['createdAt'])) : 'N/A'; ?></span>
                                    </div>
                                    <div class="project-card-meta-item">
                                        <span class="project-card-meta-label">Date Edited</span>
                                        <span><?php echo $project['editedAt'] ? date("m/d/Y", strtotime($project['editedAt'])) : 'N/A'; ?></span>
                                    </div>
                                </div>
                            </div>
                            <div class="project-card-footer">
                                <div class="project-card-status <?php echo (strtolower(trim($project['projectStatus'] ?? 'in-progress')) === 'finished') ? 'done' : 'ongoing'; ?>">
                                    <?php
                                    if (strtolower(trim($project['projectStatus'] ?? 'in-progress')) === 'finished') {
                                        echo 'Finished';
                                    } else {
                                        echo 'Ongoing';
                                    }
                                    ?>
                                </div>
                                <div class="project-card-stage">
                                    <?php
                                    if (strtolower(trim($project['projectStatus'] ?? 'in-progress')) === 'finished') {
                                        echo 'Project Complete';
                                    } else {
                                        echo htmlspecialchars($project['first_unsubmitted_stage'] ?? 'No Stages Started');
                                    }
                                    ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <div class="project-card">
                        <div class="project-card-body" style="text-align: center; color: #666;">
                            No projects found.
                        </div>
                    </div>
                <?php endif; ?>
            </div>
            
            <!-- Mobile Pagination -->
            <div class="mobile-pagination">
                <button class="mobile-load-more" id="mobileLoadMore" onclick="loadMoreMobileProjects()">
                    Load More Projects
                </button>
                <div class="mobile-pagination-info" id="mobilePaginationInfo">
                    Showing <span id="mobileCurrentCount">0</span> of <span id="mobileTotalCount">0</span> projects
                </div>
            </div>
            
            <div class="pagination-controls">
                <div class="pagination-arrows">
                    <button class="pagination-arrow" id="prevPage">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M15 18L9 12L15 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </button>
                    <button class="pagination-arrow" id="nextPage">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M9 18L15 12L9 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </button>
                </div>
                <div class="lines-per-page">
                    <span>LINES PER PAGE</span>
                    <select id="linesPerPage">
                        <option value="10">10</option>
                        <option value="20">20</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                    </select>
                </div>
            </div>
        </div>
    </div>

    <div id="addProjectModal" class="modal">
        <div class="modal-content">
            <span class="close" id="addProjectClose">&times;</span>
            <h2>Add Project</h2>
            <?php if (!empty($projectError)): // Display add project error inside the modal ?>
                <p class="project-error"><?php echo htmlspecialchars($projectError); ?></p>
            <?php endif; ?>
            <form id="addProjectForm" action="<?php echo url('index.php'); ?>" method="post">
                <label for="MoPID">Mode of Procurement*</label>
                <select name="MoPID" id="MoPID" required>
                    <option value="" disabled selected>Select Mode of Procurement</option>
                    <?php foreach ($mopList as $id => $desc): ?>
                        <option value="<?php echo $id; ?>" <?php echo (isset($_POST['MoPID']) && $_POST['MoPID'] == $id) ? 'selected' : ''; ?>><?php echo htmlspecialchars($desc); ?></option>
                    <?php endforeach; ?>
                </select>

                <label for="prNumber">Project Number (PR Number)*</label>
                <input type="text" name="prNumber" id="prNumber" required value="<?php echo htmlspecialchars($_POST['prNumber'] ?? ''); ?>">
                
                <label for="projectDetails">Project Details*</label>
                <textarea name="projectDetails" id="projectDetails" rows="4" required><?php echo htmlspecialchars($_POST['projectDetails'] ?? ''); ?></textarea>
                
                <label for="programOwner">Program Owner*</label>
                <input type="text" name="programOwner" id="programOwner" required placeholder="Enter Program Owner" value="<?php echo htmlspecialchars($_POST['programOwner'] ?? ''); ?>">

                <label for="programOffice">Program Owner Office*</label>
                <select name="programOffice" id="programOffice" required>
                    <option value="" disabled selected>Select Program Owner Office</option>
                    <?php foreach ($officeList as $officeID => $officeName): ?>
                        <option value="<?php echo htmlspecialchars($officeName); ?>" <?php echo (isset($_POST['programOffice']) && $_POST['programOffice'] == $officeName) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($officeName); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
                
                <label for="totalABC">Total ABC (Approved Budget for the Contract)*</label>
                <input type="number" name="totalABC" id="totalABC" required min="0" step="1" placeholder="Enter Total ABC" value="<?php echo htmlspecialchars($_POST['totalABC'] ?? ''); ?>">
                
                <button type="submit" name="addProject">Add Project</button>
            </form>
        </div>
    </div>

    <div id="statsModal" class="modal">
        <div class="modal-content stats-modal">
            <span class="close" id="statsClose">&times;</span>
            <div id="statsModalContentPlaceholder">
                <p class="loading-message">Loading statistics...</p>
            </div>
        </div>
    </div>

    <!-- Delete Project Modal -->
    <div id="deleteProjectModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h4>Delete Project</h4>
            </div>
            <div class="modal-body">
                <p>Are you sure you want to delete this project?</p>
                <p class="modal-warning" style="color: #dc3545; font-weight: bold;">This action will permanently remove the project and all its stages. This cannot be undone.</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-cancel" onclick="closeDeleteProjectModal()">Cancel</button>
                <button type="button" class="btn-confirm" style="background-color: #dc3545;" onclick="confirmDeleteProject()">Delete Project</button>
            </div>
        </div>
    </div>

    <script>
        // Pass PHP variables to JavaScript
        window.showAddProjectModal = <?php echo !empty($projectError) ? 'true' : 'false'; ?>;
        window.statisticsUrl = '<?php echo url('statistics.php'); ?>';
    </script>
    <script src="assets/js/index.js"></script>
</body>
</html>