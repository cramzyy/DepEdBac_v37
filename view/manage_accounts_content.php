<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Manage Accounts - DepEd BAC Tracking System</title>
    <link rel="stylesheet" href="assets/css/manage_accounts.css">
    <link rel="stylesheet" href="assets/css/background.css">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
</head>
<body>
    <?php
    // Include your header.php file here.
    // This will insert the header HTML, its inline styles, and its inline JavaScript.
    include 'header.php';
    ?>

    <div class="accounts-container">
        <a href="<?php echo url('index.php'); ?>" class="back-btn">&#8592;</a>
        <h2 class="page-title">Manage User Accounts</h2>
        <?php
            if ($deleteSuccess != "") { echo "<p class='msg success'>" . htmlspecialchars($deleteSuccess) . "</p>"; }
            if ($editSuccess != "") { echo "<p class='msg success'>" . htmlspecialchars($editSuccess) . "</p>"; }
            // Changed class to 'error' for consistency
            if ($error != "") { echo "<p class='msg error'>" . htmlspecialchars($error) . "</p>"; }
        ?>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>User ID</th>
                        <th>Name</th>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Office ID & Name</th>
                        <th>Position</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($accounts as $account): ?>
                        <tr>
                            <td data-label="User ID"><?php echo htmlspecialchars($account['userID']); ?></td>
                            <td data-label="Name"><?php echo htmlspecialchars($account['firstname'] . " " . $account['middlename'] . " " . $account['lastname']); ?></td>
                            <td data-label="Username"><?php echo htmlspecialchars($account['username']); ?></td>
                            <td data-label="Role"><?php echo ($account['admin'] == 1) ? "Admin" : "User"; ?></td>
                            <td data-label="Office"><?php echo htmlspecialchars($account['officeID'] . ' - ' . ($account['officename'] ?? "")); ?></td>
                            <td data-label="Position"><?php echo htmlspecialchars($account['position'] ?? "N/A"); ?></td>
                            <td data-label="Actions">
                                <div class="action-buttons">
                                    <button class="edit-btn icon-btn" data-id="<?php echo $account['userID']; ?>">
                                        <img src="assets/images/Edit_icon.png" alt="Edit" class="action-icon">
                                    </button>
                                    <button class="account-delete-btn icon-btn" data-id="<?php echo $account['userID']; ?>">
                                        <img src="assets/images/delete.png" alt="Delete" class="action-icon">
                                    </button>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div id="editModal" class="modal">
        <div class="modal-content">
            <span class="close" id="editClose">&times;</span>
            <h2>Edit Account</h2>
            <form id="editAccountForm" action="manage_accounts.php" method="post">
                <input type="hidden" name="editUserID" id="editUserID">
                
                <div class="form-group">
                    <label for="editFirstname">First Name<span class="required">*</span></label>
                    <input type="text" name="firstname" id="editFirstname" required>
                </div>

                <div class="form-group">
                    <label for="editMiddlename">Middle Name</label>
                    <input type="text" name="middlename" id="editMiddlename">
                </div>

                <div class="form-group">
                    <label for="editLastname">Last Name<span class="required">*</span></label>
                    <input type="text" name="lastname" id="editLastname" required>
                </div>

                <div class="form-group">
                    <label for="editPosition">Position</label>
                    <input type="text" name="position" id="editPosition">
                </div>

                <div class="form-group">
                    <label for="editUsername">Username<span class="required">*</span></label>
                    <input type="text" name="username" id="editUsername" required>
                </div>

                <div class="form-group">
                    <label for="editPassword">Password (leave blank to keep unchanged)</label>
                    <input type="password" name="password" id="editPassword">
                </div>

                <div class="form-group">
                    <label for="editOffice">Office Name<span class="required">*</span></label>
                    <select name="office" id="editOffice" required>
                        <?php foreach ($officeList as $officeID => $officeName): ?>
                            <option value="<?php echo htmlspecialchars($officeName); ?>"><?php echo htmlspecialchars($officeName); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="form-group checkbox-group">
                    <input type="checkbox" name="admin" id="editAdmin">
                    <label for="editAdmin">Admin User</label>
                </div>

                <button type="submit" name="editAccount" class="submit-btn">Save Changes</button>
            </form>
        </div>
    </div>

    <div id="deleteConfirmModal" class="modal">
        <div class="modal-content">
            <span class="close" id="deleteClose">&times;</span>
            <h2>Confirm Deletion</h2>
            <p>Are you sure you want to delete this account? This action cannot be undone.</p>
            <div class="modal-buttons">
                <button id="confirmDeleteBtn" class="delete-btn">Yes, Delete</button>
                <button id="cancelDeleteBtn" class="cancel-btn">Cancel</button>
            </div>
        </div>
    </div>

    <script src="assets/js/manage_accounts.js"></script>
</body>
</html>