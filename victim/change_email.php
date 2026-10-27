<?php require __DIR__ . '/config.php';
require __DIR__ . '/csrf.php';

// Must be logged in to change anything.
if (empty($_SESSION['user'])) {
    http_response_code(403);
    exit('You must be logged in.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // ---------------------------------------------------------------
    // THE FIX (part 2): verify the CSRF token BEFORE doing anything.
    // ---------------------------------------------------------------
    // A genuine request came from our own form, so it carries the secret
    // token that matches this session. A forged cross-site request cannot
    // include it, because the attacker's page was not allowed to read it.
    // No valid token -> reject the request and change nothing.
    if (!csrf_check($_POST['csrf_token'] ?? null)) {
        http_response_code(403);
        exit('CSRF token missing or invalid. Request rejected.');
    }

    // Token is valid: this really is our logged-in user acting through our
    // own form, so it is safe to perform the state change.
    $_SESSION['email'] = $_POST['email'] ?? $_SESSION['email'];

    header('Location: /account.php');
    exit;
}

// Not a POST — nothing to do.
header('Location: /account.php');
exit;
