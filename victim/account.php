<?php require __DIR__ . '/config.php';
require __DIR__ . '/csrf.php';

// Guard: only logged-in users may view this page.
if (empty($_SESSION['user'])) {
    header('Location: /index.php');
    exit;
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SecureBank — My Account</title>
</head>
<body style="font-family: sans-serif; max-width: 480px; margin: 60px auto;">
  <h1>🏦 SecureBank</h1>
  <p>Logged in as <strong><?= htmlspecialchars($_SESSION['user']) ?></strong>.</p>

  <p>Your current email on file is:</p>
  <p style="font-size: 1.3em;"><strong><?= htmlspecialchars($_SESSION['email']) ?></strong></p>

  <hr>

  <h2>Change email address</h2>
  <!--
    This is the STATE-CHANGING action.
    In the vulnerable version there is NOTHING here that proves the request
    really came from this page: no secret token, nothing unguessable.
  -->
  <form method="POST" action="/change_email.php">
    <!--
      THE FIX (part 1): embed the session's secret CSRF token as a hidden
      field. Only pages served by SecureBank can read this value, because
      the attacker's site is a different origin and the browser's
      same-origin policy stops it from reading our page's contents.
    -->
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
    <p><input name="email" placeholder="new email" style="width:100%"></p>
    <p><button type="submit">Update email</button></p>
  </form>

  <p><a href="/logout.php">Log out</a></p>
</body>
</html>
