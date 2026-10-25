<?php require __DIR__ . '/config.php';

// Throw away all session data and send the user back to the login page.
$_SESSION = [];
session_destroy();

header('Location: /index.php');
exit;
