# 🆔 **A07: IDENTIFICATION AND AUTHENTICATION FAILURES TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Identity & Authentication Weaknesses*

---

## 📋 **TABLE OF CONTENTS**

1. [Weak Password Policies Allowing Brute Force](#1-weak-password-policies-allowing-brute-force)
2. [No Account Lockout or Rate Limiting](#2-no-account-lockout-or-rate-limiting)
3. [Credential Stuffing Vulnerability](#3-credential-stuffing-vulnerability)
4. [Predictable Password Reset Tokens](#4-predictable-password-reset-tokens)
5. [Insecure Password Recovery (Security Questions)](#5-insecure-password-recovery-security-questions)
6. [Missing Multi-Factor Authentication (MFA) for Privileged Accounts](#6-missing-multi-factor-authentication-mfa-for-privileged-accounts)
7. [MFA Bypass via Brute Force or Session Reuse](#7-mfa-bypass-via-brute-force-or-session-reuse)
8. [Weak Session Tokens (Predictable Session IDs)](#8-weak-session-tokens-predictable-session-ids)
9. [Session Fixation](#9-session-fixation)
10. [Missing Session Invalidation on Logout](#10-missing-session-invalidation-on-logout)
11. [Insecure Session Cookie Flags (HttpOnly, Secure, SameSite)](#11-insecure-session-cookie-flags-httponly-secure-samesite)
12. [Username Enumeration via Different Error Messages](#12-username-enumeration-via-different-error-messages)
13. [Username Enumeration via Response Timing](#13-username-enumeration-via-response-timing)
14. [Weak Password Storage (Plaintext, Weak Hashing)](#14-weak-password-storage-plaintext-weak-hashing)
15. [Password Change Without Current Password Verification](#15-password-change-without-current-password-verification)
16. [Default Credentials Left Active](#16-default-credentials-left-active)
17. [Missing CAPTCHA on Authentication Endpoints](#17-missing-captcha-on-authentication-endpoints)
18. [Insecure JWT Handling (None Algorithm, Weak Secret)](#18-insecure-jwt-handling-none-algorithm-weak-secret)
19. [JWT Expiration Not Enforced (Missing `exp` Claim)](#19-jwt-expiration-not-enforced-missing-exp-claim)
20. [Insecure OAuth Implementation (Redirect URI, State Parameter)](#20-insecure-oauth-implementation-redirect-uri-state-parameter)
21. [SAML Authentication Flaws (Signature Stripping, XML Wrapping)](#21-saml-authentication-flaws-signature-stripping-xml-wrapping)
22. [Authentication Bypass via SQL Injection](#22-authentication-bypass-via-sql-injection)
23. [Authentication Bypass via Parameter Manipulation (e.g., `admin=true`)](#23-authentication-bypass-via-parameter-manipulation)
24. [Insecure API Authentication (Missing Token, API Key in URL)](#24-insecure-api-authentication-missing-token-api-key-in-url)
25. [Weak Password Reset Functionality (No Identity Verification)](#25-weak-password-reset-functionality-no-identity-verification)
26. [Open Redirect in Authentication Flow](#26-open-redirect-in-authentication-flow)
27. [Weak Registration Controls (No Email Verification)](#27-weak-registration-controls-no-email-verification)
28. [Account Takeover via Race Condition (Concurrent Requests)](#28-account-takeover-via-race-condition-concurrent-requests)
29. [Insecure Credential Transmission (HTTP not HTTPS)](#29-insecure-credential-transmission-http-not-https)
30. [Password Spraying Resistance](#30-password-spraying-resistance)

---

## 1. WEAK PASSWORD POLICIES ALLOWING BRUTE FORCE

**Description**  
Weak password policies (short length, no complexity, common passwords) allow attackers to easily brute force or guess user credentials.

**What to Look For**
- Passwords shorter than 8 characters accepted.
- No requirement for uppercase, lowercase, digits, or special characters.
- Common passwords (e.g., "password123", "admin") accepted.
- No password history check.

**What to Ignore**
- Policies enforcing minimum length, complexity, and common password blacklist.

**How to Test with Burp Suite**
1. Register a new account or change password.
2. Attempt to set weak passwords: `123456`, `password`, `qwerty`, same as username.
3. Use Burp Repeater to directly call the change endpoint.

**Example**
```http
POST /register HTTP/1.1
{"username":"test","password":"123"}
```
If successful, weak password policy.

**Tools**
- Burp Repeater
- Manual testing

**Risk Rating**  
Medium to High

**Remediation**
- Enforce password length (≥8, preferably ≥12).
- Require mixed case, digits, and special characters.
- Reject common and breached passwords (use API like HaveIBeenPwned).
- Implement password history (prevents reuse of last 5–10 passwords).

---

## 2. NO ACCOUNT LOCKOUT OR RATE LIMITING

**Description**  
Without account lockout or rate limiting, attackers can perform unlimited login attempts, leading to successful brute force or credential stuffing.

**What to Look For**
- No increase in response time or error message after multiple failed attempts.
- No temporary lockout after a threshold (e.g., 5 failures).
- No CAPTCHA after repeated failures.

**What to Ignore**
- Lockout after a reasonable number of failures (e.g., 5–10), with progressive delays.

**How to Test with Burp Suite**
1. Use Intruder to send 100+ failed login attempts for the same account.
2. Observe if any request returns a lockout message or different response.
3. Try to log in with correct credentials after many failures.

**Example**
```http
POST /login
username=admin&password=wrong
```
Repeated 100 times; if correct password still works, no lockout.

**Tools**
- Burp Intruder
- Turbo Intruder

**Risk Rating**  
High

**Remediation**
- Implement account lockout after X failures (temporary lock, e.g., 15 min).
- Use progressive delays (increase delay after each failure).
- Add CAPTCHA after a few failures.

---

## 3. CREDENTIAL STUFFING VULNERABILITY

**Description**  
If the application does not detect or block automated login attempts with large lists of credentials, attackers can use leaked passwords from other breaches to compromise accounts.

**What to Look For**
- No rate limiting or CAPTCHA on login.
- No anomaly detection for many login attempts from different IPs.
- No notification of new device logins.

**What to Ignore**
- Rate limiting, CAPTCHA, and multi-factor authentication.

**How to Test with Burp Suite**
1. Obtain a list of common breached credentials (e.g., SecLists).
2. Use Intruder to attempt logins with different username/password pairs.
3. Observe if the application blocks after many attempts.

**Example**
```http
POST /login
username=user1&password=leakedpass1
...
username=user100&password=leakedpass100
```
If many succeed without interruption, vulnerable.

**Tools**
- Burp Intruder
- Hydra (password spraying)

**Risk Rating**  
High

**Remediation**
- Implement rate limiting by IP and by user.
- Use CAPTCHA after a few failures.
- Require MFA for suspicious logins.
- Notify users of new device logins.

---

## 4. PREDICTABLE PASSWORD RESET TOKENS

**Description**  
Password reset tokens that are sequential, based on timestamps, or derived from user IDs can be guessed, allowing account takeover.

**What to Look For**
- Reset tokens in URLs: `?token=1001`, `?token=abc123`.
- Tokens that are short (e.g., 6 digits) without rate limiting.
- Tokens that do not expire quickly.

**What to Ignore**
- Cryptographically random tokens (≥128 bits) with short expiry.

**How to Test with Burp Suite**
1. Request password reset for your account and capture the token.
2. Analyze token pattern (Burp Sequencer).
3. Try to brute force tokens for another user (if numeric, use Intruder).

**Example**
```http
GET /reset?token=123456
```
If token is sequential, attacker can guess next token.

**Tools**
- Burp Sequencer
- Burp Intruder
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Generate cryptographically random tokens (e.g., UUIDv4, random bytes).
- Set token expiry (e.g., 15 minutes).
- Invalidate token after use.

---

## 5. INSECURE PASSWORD RECOVERY (SECURITY QUESTIONS)

**Description**  
Security questions with guessable answers (e.g., mother's maiden name, pet name) are weak and can be easily researched or guessed.

**What to Look For**
- Use of common security questions.
- No account lockout on security question attempts.
- Answers stored in plaintext or weakly hashed.

**What to Ignore**
- Multi-factor recovery (e.g., email + SMS) or modern recovery methods.

**How to Test with Burp Suite**
1. Attempt password recovery and answer security questions.
2. Try common answers (e.g., "Smith", "Fluffy") or research public data.
3. Test if answer is case-sensitive or allows close matches.

**Example**
```
Question: "What is your mother's maiden name?"
Answer: "Smith"
```
Easily guessable.

**Tools**
- Manual research
- Social engineering

**Risk Rating**  
Medium

**Remediation**
- Avoid security questions; use email/SMS for recovery.
- If unavoidable, use questions with non‑public answers and rate limit attempts.

---

## 6. MISSING MULTI-FACTOR AUTHENTICATION (MFA) FOR PRIVILEGED ACCOUNTS

**Description**  
Admin or other privileged accounts without MFA are at high risk of takeover.

**What to Look For**
- Admin login does not require MFA.
- MFA is optional or can be bypassed.

**What to Ignore**
- MFA enforced for all privileged accounts.

**How to Test with Burp Suite**
1. Log in as an admin account (if test account available).
2. Check if MFA is required.
3. Try to access admin functions without MFA.

**Example**
```http
POST /admin/login
username=admin&password=admin123
```
If login succeeds without MFA, missing MFA.

**Tools**
- Burp Proxy
- Manual testing

**Risk Rating**  
Critical

**Remediation**
- Enforce MFA for all privileged accounts (TOTP, SMS, or hardware token).
- Use risk‑based MFA for other accounts.

---

## 7. MFA BYPASS VIA BRUTE FORCE OR SESSION REUSE

**Description**  
MFA can be bypassed if the second factor (e.g., TOTP code) can be brute‑forced, or if the session can be used without completing MFA.

**What to Look For**
- TOTP code length too short (4 digits) without rate limiting.
- Ability to skip MFA step by directly accessing authenticated pages.
- MFA code not invalidated after use.

**What to Ignore**
- Rate‑limited TOTP, session flag enforcement, and short code expiry.

**How to Test with Burp Suite**
1. Complete first factor, then intercept the MFA step.
2. Try to access a protected resource directly (e.g., `/dashboard`).
3. If it loads, MFA is bypassed.
4. For TOTP brute force, use Intruder with 000000–999999.

**Example**
```http
POST /2fa
{"code":"000000"}
```
If after many attempts the code works, vulnerable.

**Tools**
- Burp Intruder
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Rate limit MFA attempts (e.g., 3 attempts).
- Invalidate MFA session after failed attempts.
- Enforce MFA completion server-side for all sensitive actions.

---

## 8. WEAK SESSION TOKENS (PREDICTABLE SESSION IDS)

**Description**  
Session identifiers that are sequential, short, or based on user data can be guessed, leading to session hijacking.

**What to Look For**
- Session IDs like `1001`, `abc123`, or base64 of username.
- IDs without sufficient randomness.

**What to Ignore**
- Cryptographically random session IDs (≥128 bits).

**How to Test with Burp Suite**
1. Collect multiple session IDs (e.g., by logging in repeatedly).
2. Send to Burp Sequencer to analyze randomness.
3. If entropy is low, tokens are predictable.

**Example**
```http
Set-Cookie: sessionid=1001; Path=/
```
Next session may be 1002.

**Tools**
- Burp Sequencer
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Use secure random number generators (e.g., `java.security.SecureRandom`, `random_bytes` in PHP).
- Ensure session ID length ≥ 128 bits.

---

## 9. SESSION FIXATION

**Description**  
Session fixation occurs when an application does not regenerate the session ID after authentication, allowing an attacker to force a known session ID on a victim.

**What to Look For**
- Session cookie remains the same before and after login.
- Application accepts session IDs from URL parameters.

**What to Ignore**
- Session ID regenerated after successful login.

**How to Test with Burp Suite**
1. Visit the login page and capture the session cookie.
2. Log in and note if the cookie value changes.
3. If unchanged, session fixation is possible.

**Example**
```http
GET /login HTTP/1.1
Cookie: JSESSIONID=abc123
```
After login, same `JSESSIONID=abc123`.

**Tools**
- Burp Proxy
- Manual observation

**Risk Rating**  
High

**Remediation**
- Regenerate session ID after successful authentication.
- Never accept session IDs from URL parameters.
- Use `HttpOnly` and `Secure` flags.

---

## 10. MISSING SESSION INVALIDATION ON LOGOUT

**Description**  
When a user logs out, the session should be destroyed on the server. If not, an attacker with a captured session token can continue to use it.

**What to Look For**
- After logout, the session token still allows access to authenticated resources.
- No server-side session deletion.

**What to Ignore**
- Session invalidated server-side; token no longer accepted.

**How to Test with Burp Suite**
1. Log in and capture a valid request (e.g., `GET /profile`).
2. Log out normally.
3. Replay the captured request with the same session cookie.
4. If profile data is returned, session not invalidated.

**Example**
```http
GET /profile HTTP/1.1
Cookie: session=abc123
```
After logout, same request returns profile → vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Invalidate session on server upon logout.
- Clear session cookie (set expiry in the past).

---

## 11. INSECURE SESSION COOKIE FLAGS (HTTPONLY, SECURE, SAMESITE)

**Description**  
Cookies missing `HttpOnly` are accessible to JavaScript (XSS risk). Missing `Secure` allows transmission over HTTP. Missing `SameSite` increases CSRF risk.

**What to Look For**
- `Set-Cookie` without `HttpOnly`, `Secure`, or `SameSite`.
- Cookie `Domain` too broad (e.g., `.example.com`).

**What to Ignore**
- Cookies with all flags set appropriately.

**How to Test with Burp Suite**
1. Intercept responses that set session cookies.
2. Examine flags.
3. In browser console, try `document.cookie` to see if HttpOnly cookies appear.

**Example**
```http
Set-Cookie: session=abc123; Path=/
```
Missing `HttpOnly`, `Secure`, `SameSite`.

**Tools**
- Burp Proxy
- Browser DevTools

**Risk Rating**  
Medium to High

**Remediation**
- Set `HttpOnly` to prevent JavaScript access.
- Set `Secure` to enforce HTTPS-only transmission.
- Set `SameSite=Lax` or `Strict` for CSRF protection.

---

## 12. USERNAME ENUMERATION VIA DIFFERENT ERROR MESSAGES

**Description**  
Different error messages for existing vs non‑existing usernames allow attackers to build a list of valid usernames.

**What to Look For**
- "Invalid username" vs "Invalid password".
- "Email not registered" vs "Incorrect password".

**What to Ignore**
- Generic error message: "Invalid username or password".

**How to Test with Burp Suite**
1. Send login requests with a known valid and an invalid username.
2. Compare responses (error text, status code, timing).

**Example**
```http
POST /login
username=known@example.com&password=wrong
Response: "Invalid password"

POST /login
username=unknown@example.com&password=wrong
Response: "User not found"
```

**Tools**
- Burp Intruder (grep match)
- Manual comparison

**Risk Rating**  
Medium

**Remediation**
- Use generic error messages for all login failures.
- Use constant response times (add artificial delay if needed).

---

## 13. USERNAME ENUMERATION VIA RESPONSE TIMING

**Description**  
Even with generic error messages, response times may differ because valid usernames cause password hash verification (slower). Attackers can measure timing.

**What to Look For**
- Consistent timing difference between valid and invalid usernames.
- No delay added for invalid usernames.

**What to Ignore**
- Uniform response times (e.g., always hash a fake password).

**How to Test with Burp Suite**
1. Send requests for known valid and invalid usernames.
2. Use Repeater and observe the `Time` column.
3. Use Intruder with multiple requests to average timing.

**Example**
- Valid username: 500ms response.
- Invalid username: 50ms response.

**Tools**
- Burp Repeater (time column)
- Custom scripts with precise timing

**Risk Rating**  
Low to Medium

**Remediation**
- Always perform password hash verification even for non‑existent users.
- Add random delay or constant-time comparison.

---

## 14. WEAK PASSWORD STORAGE (PLAINTEXT, WEAK HASHING)

**Description**  
Passwords stored in plaintext or with weak hashing (MD5, SHA1 without salt) can be easily recovered after a breach.

**What to Look For**
- Passwords visible in database (via SQLi) or logs.
- Password hashes of fixed length (e.g., 32 hex chars = MD5).

**What to Ignore**
- Strong adaptive hashing (bcrypt, Argon2) with per‑user salt.

**How to Test with Burp Suite**
1. If you can extract data (e.g., via SQLi), examine password fields.
2. Look for known hash patterns (e.g., `$2y$` for bcrypt, `$argon2` for Argon2).
3. Attempt to crack weak hashes with Hashcat.

**Example**
```sql
SELECT username, password FROM users;
```
Result: `admin, 5f4dcc3b5aa765d61d8327deb882cf99` (MD5 of "password").

**Tools**
- SQLMap
- Hashcat / John the Ripper

**Risk Rating**  
Critical

**Remediation**
- Use bcrypt (cost ≥10), Argon2, or PBKDF2 (≥100,000 iterations).
- Always use a unique, random salt per user.

---

## 15. PASSWORD CHANGE WITHOUT CURRENT PASSWORD VERIFICATION

**Description**  
If a user can change their password without providing the current password, an attacker with a logged‑in session (e.g., via XSS) can change the password and lock out the legitimate user.

**What to Look For**
- Change password endpoint that does not require `old_password`.
- No re‑authentication for sensitive changes.

**What to Ignore**
- Current password required.

**How to Test with Burp Suite**
1. Log in and intercept a password change request.
2. Remove or omit the `old_password` parameter.
3. If request succeeds, vulnerable.

**Example**
```http
POST /change-password
{"new_password":"attacker123"}
```
If old password not required, vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Require current password for any password change.
- For high‑risk actions, require re‑authentication (password or MFA).

---

## 16. DEFAULT CREDENTIALS LEFT ACTIVE

**Description**  
Default credentials (admin/admin, root/root) are often left unchanged on applications, devices, or frameworks.

**What to Look For**
- Admin panels using known default credentials.
- Default accounts not disabled.

**What to Ignore**
- Default accounts removed or forced password change.

**How to Test with Burp Suite**
1. Identify admin endpoints (e.g., `/admin`, `/phpmyadmin`).
2. Try common default username/password pairs.

**Example**
```http
POST /admin/login
username=admin&password=admin
```
If successful, default credentials active.

**Tools**
- Burp Intruder (default credential wordlists)
- Hydra

**Risk Rating**  
Critical

**Remediation**
- Change default credentials during deployment.
- Remove default accounts or disable them.

---

## 17. MISSING CAPTCHA ON AUTHENTICATION ENDPOINTS

**Description**  
CAPTCHA helps prevent automated brute force and credential stuffing. Its absence makes these attacks easier.

**What to Look For**
- No CAPTCHA on login, registration, or password reset.
- CAPTCHA only client‑side (bypassable).

**What to Ignore**
- CAPTCHA implemented and enforced server‑side.

**How to Test with Burp Suite**
1. Attempt to send many login requests without solving CAPTCHA.
2. If all requests are processed, CAPTCHA missing.

**Example**
```http
POST /login
username=admin&password=guess
```
Repeated 100 times, no CAPTCHA.

**Tools**
- Burp Intruder

**Risk Rating**  
Medium to High

**Remediation**
- Add CAPTCHA (e.g., reCAPTCHA v3) on authentication endpoints.
- Ensure CAPTCHA validation on server side.

---

## 18. INSECURE JWT HANDLING (NONE ALGORITHM, WEAK SECRET)

**Description**  
JWT vulnerabilities allow attackers to forge tokens, bypass authentication, or escalate privileges.

**What to Look For**
- JWT with `alg: none` accepted.
- Weak HMAC secret (e.g., "secret", "password").
- Missing signature validation (modify payload, keep signature).

**What to Ignore**
- Strong signature validation with secure algorithms (RS256, ES256).

**How to Test with Burp Suite**
1. Capture a JWT token.
2. Modify header to `{"alg":"none"}` and remove signature.
3. Send modified token; if accepted, vulnerable.
4. Use `jwt_tool` to brute force weak secret.

**Example**
```json
{
  "alg": "none",
  "typ": "JWT"
}
{
  "user": "admin"
}
```

**Tools**
- jwt_tool
- Burp JWT Editor extension

**Risk Rating**  
Critical

**Remediation**
- Reject `none` algorithm.
- Use strong secrets (≥256 bits) or asymmetric keys (RS256/ES256).
- Validate signature properly.

---

## 19. JWT EXPIRATION NOT ENFORCED (MISSING `exp` CLAIM)

**Description**  
If a JWT has no expiration claim (`exp`), it remains valid forever, increasing the risk of session hijacking.

**What to Look For**
- JWT payload missing `exp` field.
- `exp` value set to far future (e.g., year 2099).

**What to Ignore**
- JWT with short expiration (e.g., 15 minutes) and refresh token.

**How to Test with Burp Suite**
1. Decode JWT at jwt.io.
2. Check for `exp` claim.
3. Replay the same token after a long period (e.g., days).

**Example**
```json
{
  "user": "admin",
  "iat": 1700000000
}
```
No `exp` claim.

**Tools**
- jwt.io
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Always include `exp` claim with reasonable lifetime.
- Implement refresh token rotation.

---

## 20. INSECURE OAUTH IMPLEMENTATION (REDIRECT URI, STATE PARAMETER)

**Description**  
Flaws in OAuth 2.0 / OpenID Connect can lead to authorization code interception and account takeover.

**What to Look For**
- `redirect_uri` not validated (attacker can change to their domain).
- Missing `state` parameter (CSRF).
- Authorization code exposed in URL (may leak via referer).

**What to Ignore**
- Whitelisted redirect URIs, state parameter, PKCE for public clients.

**How to Test with Burp Suite**
1. Intercept OAuth authorization request.
2. Change `redirect_uri` to `https://evil.com/callback`.
3. If the provider redirects the code to evil.com, vulnerable.

**Example**
```
https://auth.com/authorize?client_id=123&redirect_uri=https://evil.com/callback&response_type=code
```

**Tools**
- Burp Repeater
- OAuth testing tools

**Risk Rating**  
Critical

**Remediation**
- Validate `redirect_uri` against a whitelist.
- Use and verify `state` parameter.
- Use PKCE for mobile and single‑page apps.

---

## 21. SAML AUTHENTICATION FLAWS (SIGNATURE STRIPPING, XML WRAPPING)

**Description**  
SAML SSO implementations can be vulnerable to signature stripping and XML wrapping attacks, allowing attackers to forge assertions.

**What to Look For**
- SAML response accepted without signature.
- Ability to wrap a malicious assertion inside a valid signature.

**What to Ignore**
- Strict signature validation and secure XML parsing.

**How to Test with Burp Suite**
1. Use SAML Raider extension.
2. Remove signature element from SAML response.
3. Send; if accepted, signature stripping works.
4. Use XML wrapping techniques to inject new assertions.

**Example**
```xml
<saml:Assertion>
  <!-- original signature -->
  <saml:Subject>admin</saml:Subject>
</saml:Assertion>
```
Remove `<ds:Signature>`.

**Tools**
- Burp SAML Raider
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Validate SAML signatures strictly.
- Use secure XML parsers that prevent wrapping attacks.
- Check for multiple assertions.

---

## 22. AUTHENTICATION BYPASS VIA SQL INJECTION

**Description**  
SQL injection in login forms can bypass authentication by modifying the SQL query logic.

**What to Look For**
- Login fields that are vulnerable to SQLi (e.g., `' OR '1'='1`).
- Error messages indicating SQL syntax.

**What to Ignore**
- Parameterized queries and prepared statements.

**How to Test with Burp Suite**
1. In the username field, input `' OR '1'='1' --`.
2. Use any password.
3. If login succeeds, authentication bypass is possible.

**Example**
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' -- ' AND password = 'anything'
```
The comment `--` ignores password check.

**Tools**
- Burp Repeater
- SQLMap

**Risk Rating**  
Critical

**Remediation**
- Use parameterized queries (prepared statements).
- Use stored procedures with parameters.

---

## 23. AUTHENTICATION BYPASS VIA PARAMETER MANIPULATION (E.G., `ADMIN=TRUE`)

**Description**  
Some applications trust client‑supplied parameters to determine authentication status or privileges.

**What to Look For**
- Parameters like `admin=true`, `authenticated=1`, `role=admin`.
- Hidden fields controlling access.

**What to Ignore**
- Server‑side session‑based privileges.

**How to Test with Burp Suite**
1. Intercept a login request or authenticated request.
2. Add parameters: `&admin=true`, `&isAdmin=1`.
3. If you gain admin access, vulnerable.

**Example**
```http
POST /login
username=user&password=pass&isAdmin=true
```

**Tools**
- Burp Repeater
- Param Miner

**Risk Rating**  
High to Critical

**Remediation**
- Never trust client‑side parameters for authorization.
- Store privilege information server‑side (session).

---

## 24. INSECURE API AUTHENTICATION (MISSING TOKEN, API KEY IN URL)

**Description**  
APIs may lack proper authentication or may expose API keys in URLs, which can be logged or leaked via referer.

**What to Look For**
- API endpoints accessible without any token.
- API keys in URL query strings (e.g., `?api_key=123`).
- API keys in client‑side code (JavaScript).

**What to Ignore**
- Strong API authentication (e.g., HMAC, OAuth, or keys in headers with TLS).

**How to Test with Burp Suite**
1. Identify API endpoints (from JS, spidering).
2. Attempt to access them without any authentication header.
3. Check for keys in URLs or exposed in responses.

**Example**
```http
GET /api/user?api_key=abc123
```
API key in URL is insecure.

**Tools**
- Burp Proxy
- Postman

**Risk Rating**  
Critical

**Remediation**
- Require authentication for all API endpoints.
- Use API keys in request headers (e.g., `Authorization: Bearer`).
- Never expose keys in URLs or client‑side code.

---

## 25. WEAK PASSWORD RESET FUNCTIONALITY (NO IDENTITY VERIFICATION)

**Description**  
If password reset only requires an email address without additional verification, an attacker with access to the email (or who can guess the reset link) can take over the account.

**What to Look For**
- Reset token sent via email only (no extra factor).
- No requirement to answer security questions or provide additional info.
- Token predictable.

**What to Ignore**
- Multi‑factor reset (email + SMS) or strong token with short expiry.

**How to Test with Burp Suite**
1. Request a password reset for an account you control.
2. Observe if the reset link alone is sufficient.
3. Try to reset another account using the same pattern.

**Example**
```http
GET /reset?email=victim@example.com
```
If reset link is sent only to that email, and no other verification, weak.

**Tools**
- Burp Proxy
- Manual testing

**Risk Rating**  
High

**Remediation**
- Send reset link to email, but also require additional verification (e.g., answer security question, enter OTP from SMS).
- Ensure tokens are random and expire quickly.

---

## 26. OPEN REDIRECT IN AUTHENTICATION FLOW

**Description**  
After login or logout, the application may redirect to a user‑controlled URL. Attackers can use this for phishing.

**What to Look For**
- Parameters like `redirect`, `return_to`, `next` after login.
- No validation of redirect target.

**What to Ignore**
- Whitelist of allowed redirect URLs.

**How to Test with Burp Suite**
1. After login, intercept the redirect response.
2. Change the redirect parameter to an external domain (e.g., `https://evil.com`).
3. If the browser redirects to evil.com, open redirect exists.

**Example**
```http
GET /login?redirect=https://evil.com
```
After login, user is sent to evil.com.

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Validate redirect URL against a whitelist.
- Use relative paths instead of full URLs.

---

## 27. WEAK REGISTRATION CONTROLS (NO EMAIL VERIFICATION)

**Description**  
If registration does not require email verification, attackers can create many fake accounts, leading to spam, abuse, or brute force of limited resources.

**What to Look For**
- Registration completes without email confirmation.
- No CAPTCHA or rate limiting.

**What to Ignore**
- Email verification required before account activation.

**How to Test with Burp Suite**
1. Register a new account with any email (including disposable).
2. If you can log in immediately, email verification is missing.

**Example**
```http
POST /register
{"username":"attacker","email":"temp@temp.com","password":"pass"}
```
Login possible without verification.

**Tools**
- Burp Repeater
- Scripted registration

**Risk Rating**  
Medium

**Remediation**
- Require email verification before account activation.
- Use CAPTCHA to prevent automated registration.

---

## 28. ACCOUNT TAKEOVER VIA RACE CONDITION (CONCURRENT REQUESTS)

**Description**  
Race conditions in authentication flows (e.g., password reset, registration) can allow attackers to take over accounts.

**What to Look For**
- Password reset token generation not atomic.
- Ability to reset the same account multiple times concurrently.
- Registration allowing duplicate usernames.

**What to Ignore**
- Proper locking or atomic operations.

**How to Test with Burp Suite**
1. Send multiple concurrent password reset requests for the same account.
2. Use Turbo Intruder to send many requests.
3. Observe if multiple reset tokens are generated or if the process fails inconsistently.

**Example**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=100)
    for i in range(20):
        engine.queue(target.req, ['email=victim@example.com'])
```

**Tools**
- Burp Turbo Intruder

**Risk Rating**  
High

**Remediation**
- Use database transactions and locks for sensitive operations.
- Implement idempotency keys.

---

## 29. INSECURE CREDENTIAL TRANSMISSION (HTTP NOT HTTPS)

**Description**  
Credentials sent over HTTP can be intercepted by attackers on the same network (e.g., public Wi‑Fi).

**What to Look For**
- Login form submits to HTTP URL.
- Application accessible via HTTP.

**What to Ignore**
- Full HTTPS with HSTS.

**How to Test with Burp Suite**
1. Browse to the login page over HTTP.
2. Observe if credentials are sent in plaintext.
3. Use Wireshark to capture traffic.

**Example**
```http
POST http://target.com/login HTTP/1.1
username=admin&password=secret
```
Credentials transmitted in plaintext.

**Tools**
- Burp Proxy (check scheme)
- Wireshark

**Risk Rating**  
Critical

**Remediation**
- Enforce HTTPS site‑wide.
- Redirect all HTTP traffic to HTTPS.
- Use HSTS to prevent downgrade attacks.

---

## 30. PASSWORD SPRAYING RESISTANCE

**Description**  
Password spraying is an attack where attackers try a single common password against many usernames. Without detection, it can bypass lockout policies.

**What to Look For**
- No detection of many failed logins across different accounts.
- No anomaly detection for the same password used across multiple accounts.

**What to Ignore**
- Monitoring for password spraying patterns.

**How to Test with Burp Suite**
1. Choose one common password (e.g., "Password123!").
2. Attempt to log in with that password for 50+ different usernames.
3. If no lockout or alert, password spraying is possible.

**Example**
```http
POST /login
username=user1&password=CommonPass123
...
username=user50&password=CommonPass123
```
No account lockout (since each account gets only 1 failure).

**Tools**
- Burp Intruder (usernames list, single password)

**Risk Rating**  
High

**Remediation**
- Monitor for password spraying (same password across many accounts).
- Implement CAPTCHA after multiple failures per IP.
- Use MFA to mitigate.

---

## ✅ **SUMMARY**

Identification and Authentication Failures (A07) encompass a wide range of weaknesses, from weak password policies and lack of MFA to session management flaws and insecure credential recovery. This guide covers 30 critical test cases.

### **Key Testing Areas Summary**

| Failure Type | Key Indicators | Risk |
|--------------|----------------|------|
| Weak Passwords | Short, no complexity | Medium-High |
| No Lockout | Unlimited attempts | High |
| Credential Stuffing | No rate limiting | High |
| Predictable Reset Tokens | Sequential tokens | High |
| Insecure Recovery | Security questions | Medium |
| Missing MFA | Admin without MFA | Critical |
| MFA Bypass | Step skipping, brute force | Critical |
| Weak Session IDs | Sequential, low entropy | High |
| Session Fixation | Same ID before/after login | High |
| No Session Invalidation | Token works after logout | High |
| Insecure Cookie Flags | Missing HttpOnly, Secure | Medium-High |
| Username Enumeration | Different error messages | Medium |
| Timing Enumeration | Response time differences | Low-Medium |
| Weak Password Storage | Plaintext, MD5 | Critical |
| Password Change | No current password | High |
| Default Credentials | admin/admin | Critical |
| Missing CAPTCHA | No protection | Medium-High |
| Insecure JWT | none alg, weak secret | Critical |
| JWT No Expiry | Missing `exp` claim | High |
| Insecure OAuth | redirect_uri tampering | Critical |
| SAML Flaws | Signature stripping | Critical |
| SQLi Bypass | `' OR '1'='1` | Critical |
| Parameter Manipulation | `admin=true` | High-Critical |
| Insecure API Auth | Missing token, key in URL | Critical |
| Weak Password Reset | No verification | High |
| Open Redirect | Unvalidated redirect | Medium |
| Weak Registration | No email verification | Medium |
| Race Condition | Concurrent reset requests | High |
| HTTP Transmission | Plaintext credentials | Critical |
| Password Spraying | Same password many users | High |

### **Pro Tips for Testing Authentication Failures**
1. **Automate enumeration** – Use Burp Intruder for username/password checks.
2. **Test both functional and negative cases** – Valid and invalid credentials, session reuse, token reuse.
3. **Check all authentication flows** – login, logout, registration, password reset, MFA, session management.
4. **Use specialized extensions** – Autorize, AuthMatrix, JWT Editor, SAML Raider.
5. **Simulate real attacks** – credential stuffing, password spraying, race conditions.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
