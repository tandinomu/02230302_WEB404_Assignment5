<?php
// config.php — shared setup, included at the top of every page
// so that all pages use the SAME session.

// Configure the session cookie BEFORE the session is created.
//
// We deliberately WEAKEN the cookie here so the classic CSRF attack works:
//   samesite => 'None'  tells the browser "send this cookie even on
//                       requests started by another website."
//                       This mimics older apps built before browsers
//                       started defaulting to SameSite=Lax.
//   secure   => true    is REQUIRED whenever SameSite=None. Browsers make
//                       an exception for localhost, so it still works here
//                       over plain http.
//   httponly => true    hides the cookie from JavaScript (good practice;
//                       it is NOT a CSRF defence, it is an XSS defence).
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'None',
    'secure'   => true,
]);

session_start();

// A tiny hardcoded "user database" — perfectly fine for a lab.
const VALID_USER = 'alice';
const VALID_PASS = 'password123';
