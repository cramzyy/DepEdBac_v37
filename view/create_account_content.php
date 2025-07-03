<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Account - DepEd BAC Tracking System</title>
    <link rel="stylesheet" href="assets/css/create_account.css">
    <link rel="stylesheet" href="assets/css/background.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    
</head>
<body>
     <?php
    include 'header.php';
    ?>
    
    <div class="container">
        <div class="aheader">
            <button class="close-btn" onclick="window.location.href='<?php echo url('index.php'); ?>'" title="Close">
                <i class="fas fa-times"></i>
            </button>
            <h3><i class="fas fa-user-plus"></i> Create Account</h3>
            <div class="subtitle">Add a new user to the system</div>
        </div>

        <div class="form-container">
            <?php if ($error != ""): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i>
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>

            <?php if (!$success): ?>
                <form action="create_account.php" method="post" id="createAccountForm">
                    <div class="form-group">
                        <label for="firstname">First Name <span class="required">*</span></label>
                        <div class="input-wrapper">
                            <input type="text" name="firstname" id="firstname" class="form-control" required>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="middlename">Middle Name</label>
                        <div class="input-wrapper">
                            <input type="text" name="middlename" id="middlename" class="form-control">
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="lastname">Last Name <span class="required">*</span></label>
                        <div class="input-wrapper">
                            <input type="text" name="lastname" id="lastname" class="form-control" required>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="position">Position</label>
                        <div class="input-wrapper">
                            <input type="text" name="position" id="position" class="form-control">
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="username">Username <span class="required">*</span></label>
                        <div class="input-wrapper">
                            <input type="text" name="username" id="username" class="form-control" required>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="password">Password <span class="required">*</span></label>
                        <div class="input-wrapper">
                            <input type="password" name="password" id="password" class="form-control" required>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="office">Office Name <span class="required">*</span></label>
                        <div class="input-wrapper">
                            <select name="office" id="office" class="form-control" required>
                                <option value="" disabled selected>Select an Office</option>
                                <?php foreach ($officeList as $officeID => $officeName): ?>
                                    <option value="<?php echo htmlspecialchars($officeName); ?>">
                                        <?php echo htmlspecialchars($officeName); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <div class="checkbox-wrapper">
                            <input type="checkbox" name="admin" id="admin">
                            <label for="admin">Grant Admin Privileges</label>
                        </div>
                    </div>

                    <button type="submit" class="btn" id="submitBtn">
                        <i class="fas fa-user-plus"></i> Create Account
                    </button>
                </form>
            <?php else: ?>
                <div class="success-card">
                    <div class="success-icon">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <h3>Account Created Successfully!</h3>
                    
                    <div class="user-details">
                        <div class="detail-row">
                            <span class="detail-label">User ID:</span>
                            <span class="detail-value"><?php echo htmlspecialchars($newAccount['userID']); ?></span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Username:</span>
                            <span class="detail-value"><?php echo htmlspecialchars($newAccount['username']); ?></span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Full Name:</span>
                            <span class="detail-value"><?php echo htmlspecialchars($newAccount['firstname'] . " " . $newAccount['middlename'] . " " . $newAccount['lastname']); ?></span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Office:</span>
                            <span class="detail-value"><?php echo htmlspecialchars($newAccount['officeID'] . ' - ' . $newAccount['officename']); ?></span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Role:</span>
                            <span class="detail-value">
                                <span class="role-badge <?php echo ($newAccount['admin'] == 1) ? 'role-admin' : 'role-user'; ?>">
                                    <?php echo ($newAccount['admin'] == 1) ? 'Admin' : 'User'; ?>
                                </span>
                            </span>
                        </div>
                    </div>

                    <button class="btn" onclick="window.location.href='<?php echo url('manage_accounts.php'); ?>'">
                        <i class="fas fa-users-cog"></i> Proceed to Manage Accounts
                    </button>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script src="assets/js/create_account.js"></script>
</body>
</html>