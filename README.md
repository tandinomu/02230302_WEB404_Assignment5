# CSRF: Vulnerable Form and Fixing It with CSRF Tokens

**Module:** WEB404 — Secure Coding Practices
**Practical Assignment 5**
**Student ID:** 02230302

---

## 1. What is CSRF?

**Cross-Site Request Forgery (CSRF)** tricks a logged-in user's browser into
sending a request they never meant to send.

It works because of one browser rule: **the browser automatically attaches a
site's cookies to every request going to that site — even when another website
started the request.** So if I am logged into my bank and then visit a bad
website, that bad website can make my browser send a request to my bank, and my
bank's session cookie goes along automatically.

The attacker never sees the response and never steals the cookie. They only need
the *action* to happen — email changed, money moved, password reset.

**Impact:** account takeover (change my email → reset my password), money
transfer, changing settings — any action I am allowed to do.

**OWASP:** CSRF was its own category (A8) in the OWASP Top Ten 2013; in 2021 it
is part of **A01 – Broken Access Control**. See the
[OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

---

## 2. Lab setup (two websites)

CSRF is a *cross-site* attack, so I need **two separate websites**:

| Role | Address |
|------|---------|
| **Victim** — "SecureBank" | `http://localhost:8090` |
| **Attacker** — bad site | `http://127.0.0.1:9090` |

Both run as `php:8.2-apache` containers (`docker-compose.yml`).

**Why two origins?** A website's *origin* is its scheme + host + port. The two
sites have different hosts (`localhost` vs `127.0.0.1`), so they are a **different
origin**. This matters twice:
- The attack must come from a *different* site — that is what makes it "cross-site".
- The browser's **same-origin policy** stops the attacker site from *reading* the
  victim's pages — which later stops it from stealing the CSRF token.

**Ethics:** both ports are bound to `127.0.0.1` only, so nothing is reachable
from the network. The attack only targets my own practice app with fake data.

**Run it:**
```bash
docker compose up -d
# victim:   http://localhost:8090   (login: alice / password123)
# attacker: http://127.0.0.1:9090
docker compose down   # stop
```

---

## 3. Step 1 — The form works normally

Logged in as `alice`, I change my email using the form. It updates — this is the
feature working as intended.

![Normal email change](screenshots/01_normal_change.png)

---

## 4. Step 2 — The vulnerable code

The action that changes the email (`victim/change_email.php`) trusts **any** POST
that carries a valid session cookie:

```php
// change_email.php — VULNERABLE
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // No check for where the request came from.
    $_SESSION['email'] = $_POST['email'] ?? $_SESSION['email'];
    header('Location: /account.php');
    exit;
}
```

The cookie tells the server *who* I am, but **not** whether the request really
came from SecureBank's own page. That is the hole.

---

## 5. Step 3 — The attacker page

The attacker site (`attacker/index.html`) has a hidden form that submits itself
to the victim as soon as the page loads:

```html
<form id="forge" action="http://localhost:8090/change_email.php" method="POST">
  <input type="hidden" name="email" value="attacker@evil.example">
</form>
<script>
  document.getElementById('forge').submit();   // runs automatically
</script>
```

The victim just sees "Congratulations!" flash for a split second. The forged
request fires silently.

![Attacker page source](screenshots/03_attacker_page.png)

---

## 6. Step 4 — The attack succeeds

**Steps:** (1) log into SecureBank as `alice`, (2) in the same browser, open the
attacker site `http://127.0.0.1:9090`.

The hidden form submits, the browser attaches my SecureBank cookie, and my email
is changed to `attacker@evil.example` — **without my consent**. The browser even
lands back on SecureBank's account page showing the new email.

![Attack succeeds](screenshots/02_attack_success.png)

**Why it worked:**
- I have a live session → my browser holds SecureBank's cookie.
- The attacker page tells my browser to POST to SecureBank.
- The browser **auto-attaches the cookie**, no matter who started the request.
- The server sees a valid cookie and cannot tell the forged request from a real
  one, because the real form carries nothing secret.

---

## 7. Step 5 — The fix: CSRF tokens

The fix is to require a **secret random token** that only a real SecureBank page
knows. The attacker's site cannot read it (different origin → blocked by the
same-origin policy), so it cannot send a valid one.

**(a) Make and check the token (`victim/csrf.php`):**
```php
function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // unguessable
    }
    return $_SESSION['csrf_token'];
}
function csrf_check(?string $submitted): bool {
    return !empty($_SESSION['csrf_token'])
        && is_string($submitted)
        && hash_equals($_SESSION['csrf_token'], $submitted); // constant-time
}
```

**(b) Put the token in the real form (`account.php`):**
```php
<input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
```

The token is a long random value in the page. The attacker cannot read it.

![Token in page source](screenshots/07_token_in_source.png)

**(c) Check it before acting (`change_email.php`):**
```php
if (!csrf_check($_POST['csrf_token'] ?? null)) {
    http_response_code(403);
    exit('CSRF token missing or invalid — request rejected.');
}
```

---

## 8. Step 6 — The same attack now fails

I run the **exact same attack** (attacker page unchanged). This time it is
rejected with HTTP 403:

![Attack blocked](screenshots/05_attack_blocked.png)

My email is left unchanged:

![Email unchanged](screenshots/06_email_unchanged.png)

The real form still works, because it carries the token:

![Legit still works](screenshots/04_legit_still_works.png)

---

## 9. Vulnerable vs secure

| | Vulnerable | Secure |
|---|-----------|--------|
| Real form | email only | email **+ hidden token** |
| Server check | cookie only | cookie **+ token check** |
| Forged POST | accepted (302) | **rejected (403)** |
| Real POST | works | works |

```diff
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
+     if (!csrf_check($_POST['csrf_token'] ?? null)) {
+         http_response_code(403);
+         exit('CSRF token missing or invalid — request rejected.');
+     }
      $_SESSION['email'] = $_POST['email'] ?? $_SESSION['email'];
  }
```

### Defence in depth (layers)
1. **CSRF token** *(what I built)* — a secret the attacker cannot read. Main fix.
2. **`SameSite` cookies** — `SameSite=Lax` (modern default) already blocks
   cross-site POSTs. I set `SameSite=None` on purpose so the attack could be
   shown; in production you use `Lax` **and** tokens together.
3. **Origin/Referer check** — reject requests not coming from my own site. A
   supporting check, not the only one.

### CSRF vs XSS (why they differ)
- **CSRF**: attacker makes my browser send a request but never sees the response
  or runs code on the site.
- **XSS**: attacker runs their own JavaScript *inside* the site's origin.
- **XSS breaks CSRF tokens**: if attacker JS runs on the site, it can read the
  token and send a valid request. So tokens assume no XSS — you must fix both.

---

## 10. Conclusion

A session cookie proves *who* the user is, but not that the request came from the
site's own page. I showed a separate attacker site silently changing a logged-in
user's email, then stopped it with a CSRF token: the same attack failed (403)
while normal use still worked. Tokens are the core defence, backed up by
`SameSite` cookies, Origin checks, and keeping the site free of XSS.

---

## Files and git history

```
docker-compose.yml     two servers, bound to 127.0.0.1
victim/                SecureBank (localhost:8090)
  config.php  index.php  account.php  change_email.php  csrf.php  logout.php
attacker/index.html    hidden forged form (127.0.0.1:9090)
screenshots/           evidence 01–07
```

The git history follows the same order: vulnerable app → attacker page → fix.
Run `git log --oneline` and `git show <commit>` to see the vulnerable version.
