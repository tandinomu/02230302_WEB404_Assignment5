<?php require __DIR__ . '/config.php';

// Must be logged in to change anything.
if (empty($_SESSION['user'])) {
    http_response_code(403);
    exit('You must be logged in.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // ---------------------------------------------------------------
    // THE VULNERABILITY
    // ---------------------------------------------------------------
    // We happily accept ANY POST request that carries a valid session
    // cookie. We never check *where* the request came from, and we never
    // ask for a secret that only our own page would know.
    //
    // The browser automatically attaches the SecureBank session cookie to
    // every request to SecureBank — EVEN requests triggered by a different
    // website. So the server cannot tell a real click from a forged one.
    // ---------------------------------------------------------------
    $_SESSION['email'] = $_POST['email'] ?? $_SESSION['email'];

    header('Location: /account.php');
    exit;
}

// Not a POST — nothing to do.
header('Location: /account.php');
exit;
