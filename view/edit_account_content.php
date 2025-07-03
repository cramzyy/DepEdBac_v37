<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Edit Account - DepEd BAC Tracking System</title>
  <link rel="stylesheet" href="assets/css/edit_account.css" />
  <link rel="stylesheet" href="assets/css/background.css" />

</head>
<body>

    <?php
    include 'header.php';
    ?>


  <?php if ($success): ?>
  <style>
    .modal .modal-content.success-modal {
      max-width: 500px !important;
      margin: 10% auto !important;
      border-radius: 8px !important;
      box-shadow: 0 4px 12px rgba(0,0,0,0.2) !important;
      overflow: hidden !important;
      padding: 0 !important;
      background-color: #fefefe !important;
      border: none !important;
    }
    
    .modal .modal-content.success-modal .modal-header {
      background-color: #28a745 !important;
      color: white !important;
      padding: 15px 20px !important;
      border-radius: 8px 8px 0 0 !important;
      text-align: center !important;
      border-bottom: none !important;
      margin-bottom: 0 !important;
      padding-bottom: 15px !important;
    }
    
    .modal .modal-content.success-modal .modal-header h4 {
      margin: 0 !important;
      font-size: 1.3em !important;
      font-weight: 600 !important;
      color: white !important;
    }
    
    .modal .modal-content.success-modal .modal-body {
      padding: 30px 20px !important;
      text-align: center !important;
      background: white !important;
      margin-bottom: 0 !important;
      line-height: 1.6 !important;
    }
    
    .modal .modal-content.success-modal .success-icon-large {
      width: 80px !important;
      height: 80px !important;
      background: linear-gradient(135deg, #28a745, #20c997) !important;
      border-radius: 50% !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      margin: 0 auto 20px !important;
      box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3) !important;
    }
    
    .modal .modal-content.success-modal .success-icon-large .checkmark {
      font-size: 40px !important;
      font-weight: bold !important;
      color: white !important;
      text-shadow: 0 2px 4px rgba(0,0,0,0.2) !important;
      font-style: normal !important;
    }
    
    .modal .modal-content.success-modal .success-details {
      background-color: #f8f9fa !important;
      border: 1px solid #e9ecef !important;
      border-radius: 6px !important;
      padding: 15px !important;
      margin: 20px 0 !important;
      text-align: left !important;
    }
    
    .modal .modal-content.success-modal .success-details p {
      margin: 8px 0 !important;
      font-size: 0.95em !important;
      color: #495057 !important;
    }
    
    .modal .modal-content.success-modal .success-details strong {
      color: #28a745 !important;
      font-weight: 600 !important;
    }
    
    .modal .modal-content.success-modal .modal-footer {
      padding: 20px !important;
      text-align: center !important;
      border-top: 1px solid #eee !important;
      background: #fafafa !important;
    }
    
    .modal .modal-content.success-modal .btn-success {
      background-color: #28a745 !important;
      color: white !important;
      border: none !important;
      padding: 12px 30px !important;
      border-radius: 6px !important;
      cursor: pointer !important;
      font-size: 1em !important;
      font-weight: 600 !important;
      transition: all 0.3s ease !important;
      box-shadow: 0 2px 8px rgba(40, 167, 69, 0.3) !important;
      text-transform: uppercase !important;
      letter-spacing: 0.5px !important;
    }
    
    .modal .modal-content.success-modal .btn-success:hover {
      background-color: #218838 !important;
      transform: translateY(-2px) !important;
      box-shadow: 0 4px 15px rgba(40, 167, 69, 0.4) !important;
    }
  </style>
  <?php endif; ?>

  <div class="modal">
    <div class="modal-content <?php echo $success ? 'success-modal' : ''; ?>">
      <?php if ($success): ?>
        <div class="modal-header success-header">
          <h4>Password Updated Successfully!</h4>
        </div>
        <div class="modal-body">
          <div class="success-icon-large">
            <i class="checkmark">✓</i>
          </div>
          <p>Your password has been been successfully changed.</p>
          <div class="success-details">
            <p><strong>Account:</strong> <?= htmlspecialchars($_SESSION['username']) ?></p>
            <p><strong>Updated:</strong> <?= date('F j, Y \a\t g:i A') ?></p>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn-success" onclick="window.location.href='<?php echo url('index.php'); ?>'">Return to Dashboard</button>
        </div>
      <?php else: ?>
      <span class="close" onclick="window.location.href='<?php echo url('index.php'); ?>'">&times;</span>

      <?php if ($error): ?>
        <p class="error-text"><?php echo htmlspecialchars($error); ?></p>
      <?php endif; ?>
      <div class="card-container">
        <!-- User Info Card -->
        <div class="info-card">
          <h3>Account Information</h3>
          <div class="info-row">
            <span class="info-label">Name:</span>
            <span class="info-value"><?= htmlspecialchars($user['firstname'] . ' ' . $user['middlename'] . ' ' . $user['lastname']) ?></span>
          </div>
          <div class="info-row">
            <span class="info-label">Position:</span>
            <span class="info-value"><?= htmlspecialchars($user['position']) ?></span>
          </div>
          <div class="info-row">
            <span class="info-label">Username:</span>
            <span class="info-value"><?= htmlspecialchars($user['username']) ?></span>
          </div>
          <div class="info-row">
            <span class="info-label">Office:</span>
            <span class="info-value"><?= htmlspecialchars($user['officeID'] . ' - ' . $user['officename']) ?></span>
          </div>
        </div>
        
        <!-- Password Change Card -->
        <div class="password-card">
          <h3>Change Password</h3>
          <form method="post">
            <div class="form-group">
              <label for="old_password">Old Password*</label>
              <input type="password" id="old_password" name="old_password" required />
            </div>

            <div class="form-group">
              <label for="new_password">New Password*</label>
              <input type="password" id="new_password" name="new_password" required />
            </div>

            <div class="form-group">
              <label for="confirm_new_password">Confirm New Password*</label>
              <input type="password" id="confirm_new_password" name="confirm_new_password" required />
            </div>

            <button type="submit">Update Password</button>
          </form>
        </div>
      </div>
      <?php endif; ?>
    </div>
  </div>
</body>
</html>