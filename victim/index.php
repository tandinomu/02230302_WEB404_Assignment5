<?php require __DIR__ . '/config.php';

// If the user is already logged in, skip straight to their account page.
if (!empty($_SESSION['user'])) {
    header('Location: /account.php');
    exit;
}

$error = '';

// Handle the login form when it is submitted.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['username'] ?? '';
    $pass = $_POST['password'] ?? '';

    if ($user === VALID_USER && $pass === VALID_PASS) {
        // Correct credentials: record who they are in the session and give
        // them a starting email address that we will be able to change later.
        $_SESSION['user']  = $user;
        $_SESSION['email'] = 'alice@example.com';
        header('Location: /account.php');
        exit;
    }
    $error = 'Invalid username or password.';
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SecureBank — Login</title>
</head>
<body style="font-family: sans-serif; max-width: 420px; margin: 60px auto;">
  <h1>🏦 SecureBank</h1>
  <p>Please log in to your account.</p>

  <?php if ($error): ?>
    <p style="color: red;"><?= htmlspecialchars($error) ?></p>
  <?php endif; ?>

  <form method="POST" action="/index.php">
    <p><input name="username" placeholder="username" style="width:100%"></p>
    <p><input name="password" type="password" placeholder="password" style="width:100%"></p>
    <p><button type="submit">Log in</button></p>
  </form>

  <p style="color:#888; font-size: 0.9em;">Demo login — user: <code>alice</code> / pass: <code>password123</code></p>
</body>
</html>
