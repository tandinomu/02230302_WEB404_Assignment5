<?php
// csrf.php — helpers for the "synchronizer token pattern".
// config.php has already called session_start() before this is included.

// Return this session's CSRF token, creating one the first time it is needed.
function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        // 32 random bytes -> 64 hex characters.
        // random_bytes() is cryptographically secure, so the value is
        // effectively impossible for an attacker to guess.
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Return true only if the submitted token matches the one in the session.
function csrf_check(?string $submitted): bool {
    // hash_equals() compares in constant time, so an attacker cannot learn
    // the token one character at a time by measuring how long checks take.
    return !empty($_SESSION['csrf_token'])
        && is_string($submitted)
        && hash_equals($_SESSION['csrf_token'], $submitted);
}
