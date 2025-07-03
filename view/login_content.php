<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login - DepEd BAC Tracking System</title>
  <link rel="stylesheet" href="assets/css/Login.css">
  <!-- Include header.php for styles and layout -->
  <?php include 'header.php'; ?>
</head>
<body class="home-bg">
  
  <div class="login-flex-wrapper">
    <div class="login-container">
      <div class="login-box">
        <img src="assets/images/DepEd_Name_Logo.png" alt="DepEd" class="login-logo">
        <!-- Display error messages from PHP -->
        <?php if (isset($error)): ?>
          <p class="error-message"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        <!-- Form updated to use POST and include name attributes -->
        <form id="loginForm" action="login.php" method="post">
          <label for="username">Username</label>
          <input type="text" id="username" name="username" placeholder="Enter your username" required>

          <label for="password">Password</label>
          <input type="password" id="password" name="password" placeholder="Enter your password" required>

          <button type="submit">Sign In</button>
        </form>
      </div>
    </div>
    <img src="assets/images/DepEd_Logo.png" alt="DepEd Logo" class="side-logo-login">
  </div>

  <!-- Server-side authentication is used instead of client-side login.js -->
</body>
</html>