# 🔐 **AUTHENTICATION TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive*

---

## 📋 **TABLE OF CONTENTS**

1. [Username/User Enumeration](#1-usernameuser-enumeration)
2. [Password Brute Force & Credential Stuffing](#2-password-brute-force--credential-stuffing)
3. [Default Credentials](#3-default-credentials)
4. [Weak Password Policy](#4-weak-password-policy)
5. [Password Reset Token Prediction / Leakage](#5-password-reset-token-prediction--leakage)
6. [Password Reset Poisoning (Host Header Injection)](#6-password-reset-poisoning-host-header-injection)
7. [Insecure Password Reset Functionality](#7-insecure-password-reset-functionality)
8. [OTP/2FA Bypass (Brute Force, Reuse, Leakage)](#8-otp2fa-bypass-brute-force-reuse-leakage)
9. [OTP/2FA Implementation Flaws](#9-otp2fa-implementation-flaws)
10. [Session Fixation](#10-session-fixation)
11. [Session Hijacking (via XSS, Cookie Theft)](#11-session-hijacking-via-xss-cookie-theft)
12. [Insecure Session Tokens (Predictable, Not Regenerated)](#12-insecure-session-tokens-predictable-not-regenerated)
13. [JWT Weaknesses (None Algorithm, Weak Secret, Missing Validation)](#13-jwt-weaknesses-none-algorithm-weak-secret-missing-validation)
14. [Remember Me Functionality Flaws](#14-remember-me-functionality-flaws)
15. [Authentication Bypass via Parameter Manipulation](#15-authentication-bypass-via-parameter-manipulation)
16. [Bypassing Authentication via Direct Page Access (Forceful Browsing)](#16-bypassing-authentication-via-direct-page-access-forceful-browsing)
17. [Multi-Factor Authentication Bypass (Skip MFA Step)](#17-multi-factor-authentication-bypass)
18. [Insecure Password Storage (Exposure via Other Vulnerabilities)](#18-insecure-password-storage-exposure-via-other-vulnerabilities)
19. [CAPTCHA Bypass](#19-captcha-bypass)
20. [Race Conditions in Authentication](#20-race-conditions-in-authentication)
21. [Account Lockout Policy Flaws (DoS or Brute Force Bypass)](#21-account-lockout-policy-flaws)
22. [Insecure API Authentication (Missing Tokens, Weak API Keys)](#22-insecure-api-authentication-missing-tokens-weak-api-keys)
23. [Social Login / OAuth Flaws](#23-social-login--oauth-flaws)
24. [SAML Authentication Flaws](#24-saml-authentication-flaws)
25. [LDAP / Active Directory Injection](#25-ldap--active-directory-injection)
26. [SQL Injection in Authentication](#26-sql-injection-in-authentication)
27. [XML Injection in Authentication](#27-xml-injection-in-authentication)
28. [NoSQL Injection in Authentication](#28-nosql-injection-in-authentication)
29. [Authentication Timing Attacks](#29-authentication-timing-attacks)
30. [Credential Leakage via Referer, Logs, or Other Channels](#30-credential-leakage-via-referer-logs-or-other-channels)

---

## 1. USERNAME/USER ENUMERATION

**Description**  
Attackers can determine whether a username/email exists based on differences in server responses. This is the first step for targeted attacks like credential stuffing or password spraying.

**What to Look For**
- Different error messages: "Invalid username" vs "Invalid password"
- Different response status codes (e.g., 200 vs 403)
- Different response times (valid user may cause a database lookup → slower)
- Redirects or cookies set only for valid users
- Password reset functionality that reveals if an email is registered

**What to Ignore**
- Generic "Invalid username or password" message (safe)
- Identical response times for all attempts
- Rate limiting that prevents excessive requests

**How to Test with Burp Suite**
1. Send a login request with a known valid username and an incorrect password. Capture the request.
2. Send to **Intruder**.
3. Set payload position on the username field.
4. Load a list of potential usernames (or use a wordlist).
5. Add a **grep extract** rule to capture the response body or status code.
6. Run the attack and compare responses.
7. Alternatively, manually test with **Repeater** by sending one valid and one invalid username and observing differences.

**Example**
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=john@example.com&password=wrong
```
Response: `{"error": "Invalid password"}`

```http
POST /login HTTP/1.1
username=nonexistent@example.com&password=wrong
```
Response: `{"error": "User not found"}`

**Tools**  
- Burp Intruder (with grep match)  
- OWASP ZAP Fuzzer  
- Custom Python script using `requests`

**Risk Rating**  
Low → Medium (enables further attacks)

**Remediation**  
- Return generic error messages: "Invalid username or password"  
- Ensure uniform response timing (use constant-time comparisons)  
- Apply rate limiting to all authentication endpoints

---

## 2. PASSWORD BRUTE FORCE & CREDENTIAL STUFFING

**Description**  
Attackers guess passwords by trying many combinations (brute force) or using lists of known credentials from data breaches (credential stuffing).

**What to Look For**
- No rate limiting on login attempts
- No account lockout after multiple failures
- No CAPTCHA after a few attempts
- Ability to use many passwords against a single account
- Ability to use one password against many accounts (password spraying)

**What to Ignore**
- Accounts protected by CAPTCHA and rate limiting
- Lockout after reasonable attempts

**How to Test with Burp Suite**
1. Capture a login request.
2. Send to **Intruder** (or **Turbo Intruder** for speed).
3. Set payload position on the password field.
4. Load a password wordlist (e.g., SecLists).
5. Configure **Resource Pool** with low threads to avoid triggering defenses.
6. Run attack and look for different response length/status (success).
7. For password spraying, set payload on username field with many usernames, and use a single common password.

**Example**
```http
POST /login HTTP/1.1
Host: target.com
Cookie: session=...

username=admin&password=§FUZZ§
```

**Tools**  
- Burp Intruder / Turbo Intruder  
- Hydra  
- Medusa  
- Ncrack  
- Custom scripts with rotating proxies

**Risk Rating**  
High

**Remediation**  
- Enforce strong password policies  
- Implement account lockout after X failed attempts (temporary lock)  
- Deploy rate limiting (per IP, per account)  
- Use CAPTCHA after few failures  
- Enable multi-factor authentication (MFA)

---

## 3. DEFAULT CREDENTIALS

**Description**  
Many applications, devices, or CMS platforms come with default usernames/passwords (admin/admin) that are often left unchanged.

**What to Look For**
- Known default credentials for the identified technology (Apache Tomcat, Jenkins, WordPress, routers, etc.)
- Admin panels, API endpoints, or hidden directories that accept default credentials

**What to Ignore**
- Systems where default credentials are disabled by policy

**How to Test with Burp Suite**
1. Identify the application type (e.g., via HTTP headers, favicon, URL patterns).
2. Search for default credentials online (CIRT.net, default-password.info).
3. Send a login request to the suspected admin page.
4. Use **Intruder** with a list of common default username/password pairs (or use a combined wordlist).
5. Observe responses for successful authentication.

**Example**
```http
GET /admin/ HTTP/1.1
Host: target.com
Authorization: Basic YWRtaW46YWRtaW4=  # base64 of admin:admin
```
If access granted, default credentials are in use.

**Tools**  
- Burp Intruder (with default credential wordlists)  
- Hydra  
- Nmap with `http-default-accounts` script

**Risk Rating**  
Critical

**Remediation**  
- Force password change on first login  
- Remove or disable default accounts  
- Implement secure deployment guidelines

---

## 4. WEAK PASSWORD POLICY

**Description**  
The application allows weak passwords (short length, no complexity, common passwords), making brute force easier.

**What to Look For**
- Registration page allows passwords less than 8 characters
- No requirement for mixed case, numbers, or special characters
- Password "strength meter" only client-side (bypass by direct API call)
- Common passwords like "password123" accepted

**What to Ignore**
- Policies that meet industry standards (NIST recommends at least 8 characters, no complexity if length is sufficient, but best practice is complexity)

**How to Test with Burp Suite**
1. Register a new account (or use password change functionality).
2. Intercept the request.
3. Modify the password parameter to weak values:
   - `123456`
   - `password`
   - `admin`
   - `qwerty`
4. Send the request and check if it is accepted.
5. Also test if the same password can be set as the username.

**Example**
```http
POST /register HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "username": "testuser",
  "password": "123"
}
```
If response indicates success → weak password policy.

**Tools**  
- Burp Repeater  
- Manual testing

**Risk Rating**  
Medium

**Remediation**  
- Enforce minimum length (at least 8 characters)  
- Require mixed case, numbers, special characters  
- Check against breached password lists (HaveIBeenPwned API)  
- Reject common passwords

---

## 5. PASSWORD RESET TOKEN PREDICTION / LEAKAGE

**Description**  
Password reset tokens may be weak (predictable, short, or exposed) allowing account takeover.

**What to Look For**
- Tokens in response bodies (JSON, HTML)
- Tokens in URLs (GET parameters)
- Tokens that are sequential (e.g., 1001, 1002)
- Tokens based on timestamps or user IDs
- Tokens that do not expire quickly

**What to Ignore**
- Random tokens (UUIDv4, cryptographically secure) sent only via email (not in response)

**How to Test with Burp Suite**

**a) Token Leakage**  
1. Request password reset for your own account.
2. Intercept the response; look for token in JSON or HTML.
3. If found, it's leaked.

**b) Token Predictability**  
1. Request multiple resets for the same account.
2. Collect tokens and analyze pattern (use **Burp Sequencer**).
3. If tokens are sequential, try to brute force tokens for another user.

**Example (leakage)**
```http
POST /reset-password HTTP/1.1
{"email": "victim@example.com"}

Response: {"reset_token": "reset_123456"}
```

**Example (predictable)**
Reset tokens: reset_1001, reset_1002, reset_1003 → attacker can guess reset_1004 for another user.

**Tools**  
- Burp Sequencer (randomness analysis)  
- Custom scripts  
- Burp Scanner (passive scan)

**Risk Rating**  
High

**Remediation**  
- Generate cryptographically random tokens (at least 128 bits)  
- Store tokens hashed in database  
- Expire tokens after short time (e.g., 15 minutes)  
- Send token via secure channel (email body, not URL)  
- Invalidate token after use

---

## 6. PASSWORD RESET POISONING (HOST HEADER INJECTION)

**Description**  
Attackers manipulate the Host header in password reset requests to make the reset link point to their domain, then capture the token.

**What to Look For**
- Password reset link constructed dynamically using the `Host` header
- Application trusts the `Host` header without validation
- Email contains a link like `http://[Host]/reset?token=xxx`

**What to Ignore**
- Applications that use relative paths or have a fixed base URL configured

**How to Test with Burp Suite**
1. Intercept a password reset request.
2. Change the `Host` header to your attacker-controlled domain (e.g., `evil.com`).
3. Forward the request.
4. Check your email (or the victim's if you control it) to see if the reset link uses `evil.com`.

**Example**
```http
POST /reset-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```
If the email contains `https://evil.com/reset?token=xxx` → vulnerable.

**Tools**  
- Burp Repeater  
- Custom scripts

**Risk Rating**  
High

**Remediation**  
- Use relative URLs or server-side configuration (don't rely on Host header)  
- Validate Host header against a whitelist  
- Use absolute URLs based on configured server name

---

## 7. INSECURE PASSWORD RESET FUNCTIONALITY

**Description**  
Flaws in the password reset process beyond tokens, such as allowing reset without verification, weak security questions, or bypassing steps.

**What to Look For**
- Password change without providing current password
- Security questions with guessable answers (e.g., "What is your favorite color?")
- Ability to skip steps in the reset flow (e.g., directly access the final reset page)
- Email parameter tampering (changing email after verification)
- No password history check (reusing old passwords)

**What to Ignore**
- Properly implemented reset flows with token validation and step enforcement

**How to Test with Burp Suite**

**a) Direct Reset Without Old Password**  
1. Log in and intercept password change request.
2. Remove or modify the "old_password" parameter.
3. See if the password is still accepted.

**b) Step Skipping**  
1. Walk through the reset flow (e.g., /forgot → /verify → /reset).
2. Try to directly access /reset without a valid token.

**c) Email Tampering**  
1. After receiving a reset token, intercept the request that submits the new password.
2. Change the email parameter to another user's email.
3. See if the password is changed for that user.

**Example**
```http
POST /change-password HTTP/1.1
Cookie: session=...

old_password=currentpass&new_password=newpass
```
If `old_password` is not required or can be omitted → insecure.

**Tools**  
- Burp Repeater  
- Manual flow testing

**Risk Rating**  
Medium to High

**Remediation**  
- Require current password for password change (when logged in)  
- Use strong, randomly generated security questions or avoid them  
- Store answers hashed, not plaintext  
- Maintain a password history to prevent reuse

---

## 8. OTP/2FA BYPASS (BRUTE FORCE, REUSE, LEAKAGE)

**Description**  
One-Time Passwords (OTP) or 2FA codes can be bypassed due to weak implementation.

**What to Look For**
- Numeric OTPs (e.g., 6 digits) without rate limiting
- OTPs that remain valid after use (reuse)
- OTPs exposed in response bodies
- Ability to remove OTP parameter from request

**What to Ignore**
- OTPs with rate limiting and single-use enforcement

**How to Test with Burp Suite**

**a) Brute Force**  
1. Intercept the OTP verification request.
2. Send to **Intruder**.
3. Set payload on the OTP field, using numbers 000000 to 999999 (or use a smaller range for proof of concept).
4. Set a low thread count and observe if any attempt succeeds.

**b) Reuse**  
1. Successfully verify an OTP.
2. Resend the same OTP request. If accepted again → vulnerable.

**c) Leakage**  
1. Intercept the response after requesting OTP.
2. Check if OTP is present in JSON/HTML.

**d) Parameter Removal**  
1. Intercept OTP verification request.
2. Remove the OTP parameter entirely, or set it to null.
3. Forward and see if the request succeeds.

**Example (leakage)**
```http
POST /request-otp HTTP/1.1
{"phone": "1234567890"}

Response: {"otp": "123456", "message": "OTP sent"}
```

**Tools**  
- Burp Intruder  
- Custom scripts

**Risk Rating**  
High

**Remediation**  
- Rate limit OTP attempts (e.g., 3 attempts then lockout)  
- Invalidate OTP after use or short expiry  
- Never expose OTP in responses  
- Use longer OTPs or alphanumeric codes  
- Implement MFA properly with TOTP (time-based) not just SMS

---

## 9. OTP/2FA IMPLEMENTATION FLAWS

**Description**  
Beyond bypass, there are logic flaws in 2FA implementation.

**What to Look For**
- 2FA not enforced for all users (old accounts bypass)
- 2FA can be disabled without re-authentication
- Backup codes predictable or brute-forcible
- 2FA step skipping after login
- "Remember this device" tokens insecure

**What to Ignore**
- Properly enforced 2FA with secure backup codes

**How to Test with Burp Suite**

**a) 2FA Not Enforced**  
1. Log in with an account that should have 2FA enabled.
2. If you can access the dashboard without entering 2FA → vulnerable.

**b) Disable 2FA Without Re-auth**  
1. Navigate to security settings.
2. Intercept the request to disable 2FA.
3. Remove any password/OTP confirmation fields.

**c) Backup Code Predictability**  
1. Generate backup codes.
2. Analyze pattern (sequential, based on user ID). Use Burp Sequencer.

**d) Step Skipping**  
1. After successful login (first factor), note that you are redirected to /2fa.
2. Try to directly access /dashboard or any authenticated page.

**Example**
```
POST /login
(credentials correct, server redirects to /2fa)
GET /dashboard
```
If dashboard loads → 2FA bypass.

**Tools**  
- Burp Repeater  
- Manual navigation

**Risk Rating**  
High

**Remediation**  
- Enforce 2FA for all users, especially privileged ones  
- Require current password to disable 2FA  
- Use cryptographically random backup codes  
- Validate 2FA completion on server for each sensitive page

---

## 10. SESSION FIXATION

**Description**  
Attacker sets a user's session ID to a known value, then after login, the session ID remains the same, allowing the attacker to hijack the session.

**What to Look For**
- Session cookie does not change after login
- Session ID accepted via URL parameter (e.g., `?sessionid=xyz`)
- No regeneration of session ID upon authentication

**What to Ignore**
- Session ID changes after login (proper regeneration)

**How to Test with Burp Suite**
1. Visit the application and obtain a session cookie (e.g., from a fresh browser).
2. Note the cookie value.
3. Log in using valid credentials.
4. Check if the cookie value remains the same. If unchanged → vulnerable.

**Example**
- Victim visits `http://target.com/?SESSID=attacker_sessid`
- They log in, but session ID remains attacker_sessid.
- Attacker now uses that session ID and is logged in as victim.

**Tools**  
- Burp (compare session cookie before/after login)  
- Manual observation

**Risk Rating**  
Medium

**Remediation**  
- Regenerate session ID after successful login  
- Never accept session IDs from URL parameters  
- Set `HttpOnly` and `Secure` flags on cookies

---

## 11. SESSION HIJACKING (VIA XSS, COOKIE THEFT)

**Description**  
If session cookies are not properly protected, attackers can steal them via XSS, network sniffing, or other means.

**What to Look For**
- Cookies missing `HttpOnly` flag (accessible by JavaScript)
- Cookies missing `Secure` flag (sent over HTTP)
- `SameSite` attribute not set (CSRF risk, but also session leakage)
- Application vulnerable to XSS (stored/reflected)

**What to Ignore**
- Cookies with `HttpOnly`, `Secure`, `SameSite` properly set

**How to Test with Burp Suite**
1. In Burp, go to **Proxy → Options → TLS Pass Through** (not needed) but better: use **HTTP History** to examine `Set-Cookie` headers.
2. Check each cookie for `HttpOnly`, `Secure`, `SameSite` flags.
3. For XSS testing, see if you can inject script that accesses `document.cookie`.

**Example**
```http
Set-Cookie: sessionid=abc123; Path=/
```
Missing `HttpOnly` and `Secure` flags.

**Tools**  
- Browser DevTools (check cookies)  
- Burp passive scanner

**Risk Rating**  
Critical (if combined with XSS)

**Remediation**  
- Set `HttpOnly`, `Secure`, and `SameSite=Lax` or `Strict` on cookies  
- Use HTTPS site-wide  
- Implement XSS protection (CSP, input validation)

---

## 12. INSECURE SESSION TOKENS (PREDICTABLE, NOT REGENERATED)

**Description**  
Session tokens that are predictable (sequential, timestamp-based) or not regenerated after privilege changes can be guessed or reused.

**What to Look For**
- Session IDs that look like numbers, timestamps, or base64 of user data
- Session ID does not change after login, logout, or privilege escalation
- Ability to predict another user's session ID

**What to Ignore**
- Cryptographically random session IDs that change appropriately

**How to Test with Burp Suite**

**a) Predictability**  
1. Log in multiple times (or use a macro to collect many session IDs).
2. Send them to **Burp Sequencer** to analyze randomness.
3. If tokens are sequential or have low entropy → vulnerable.

**b) Not Regenerated**  
1. Log in as a low-privilege user, note session ID.
2. Perform a privilege escalation (e.g., become admin).
3. Check if session ID changed. If not → vulnerable.

**Example (predictable)**
Session tokens: 1001, 1002, 1003... → attacker can guess other users' sessions.

**Tools**  
- Burp Sequencer  
- Custom scripts

**Risk Rating**  
High

**Remediation**  
- Use cryptographically secure random session IDs  
- Regenerate session ID after login, logout, and privilege changes

---

## 13. JWT WEAKNESSES (NONE ALGORITHM, WEAK SECRET, MISSING VALIDATION)

**Description**  
JSON Web Tokens (JWT) are commonly used for authentication. Several flaws exist.

**What to Look For**
- JWT with `alg: none` in header
- Weak HMAC secret (e.g., "secret", "password")
- Missing signature validation (modify payload, keep signature)
- `kid` parameter injection (path traversal, SQLi)
- Algorithm confusion (RS256 → HS256)

**What to Ignore**
- Properly validated JWTs with strong algorithms and secrets

**How to Test with Burp Suite (using jwt_tool extension or manual)**

**a) None Algorithm**  
1. Decode JWT (e.g., at jwt.io).
2. Change header to `{"alg": "none"}`.
3. Remove signature part (keep the two dots).
4. Send modified token; if accepted → vulnerable.

**b) Weak Secret**  
1. Use `jwt_tool` to brute force secret:  
   `python jwt_tool.py <JWT> -C -d wordlist.txt`

**c) Missing Signature Validation**  
1. Modify payload (e.g., change `"user":"admin"`).
2. Keep original signature.
3. Send token; if accepted → vulnerable.

**d) Kid Injection**  
1. If `kid` header exists, try path traversal: `"kid": "../../../../dev/null"` or SQLi payloads.

**Example (none algorithm)**
```json
{
  "alg": "none",
  "typ": "JWT"
}
{
  "user": "admin"
}
[no signature]
```

**Tools**  
- jwt_tool  
- Burp extension: JSON Web Tokens  
- jwt.io for debugging

**Risk Rating**  
Critical

**Remediation**  
- Reject `none` algorithm  
- Use strong secrets (>=256 bits)  
- Validate signature properly  
- Whitelist algorithms  
- Use asymmetric keys (RS256/ES256) and keep private key secret

---

## 14. REMEMBER ME FUNCTIONALITY FLAWS

**Description**  
"Remember me" cookies often store persistent authentication tokens. Flaws include predictable tokens, no expiration, or stored insecurely.

**What to Look For**
- "Remember me" cookie that is base64 of user ID and expiry
- Token that does not expire or is not invalidated on logout
- Token can be used from different IPs/user agents
- Token predictable (sequential)

**What to Ignore**
- Random tokens stored server-side with proper expiration and binding

**How to Test with Burp Suite**
1. Log in with "remember me" checked.
2. Capture the `Set-Cookie` for the remember-me token.
3. Decode it (Burp Decoder) to see if it contains plaintext data (user ID, timestamp).
4. Log out and see if the token still works (try to access authenticated pages).
5. Change IP or user agent (using Burp's **Match and Replace** or modify headers) and test token validity.

**Example**
```http
Set-Cookie: rememberme=dXNlcj0xMjM7ZXhwaXJ5PTIwMjUtMDEtMDE=
```
Decodes to `user=123;expiry=2025-01-01`. Easily forged.

**Tools**  
- Burp Decoder  
- Custom scripts

**Risk Rating**  
Medium to High

**Remediation**  
- Generate cryptographically random tokens stored server-side  
- Bind tokens to IP, user agent, etc.  
- Set reasonable expiration  
- Invalidate on logout, password change, and after inactivity

---

## 15. AUTHENTICATION BYPASS VIA PARAMETER MANIPULATION

**Description**  
Attackers modify parameters in login/authentication requests to bypass checks.

**What to Look For**
- Extra parameters like `isAdmin=true`, `role=admin`
- `skip_verification=true` or `2fa_passed=true`
- Changing request method (GET instead of POST) to bypass authentication
- Hidden fields that control authentication logic

**What to Ignore**
- Parameters that are properly validated server-side

**How to Test with Burp Suite**
1. Intercept login request.
2. Add/modify parameters that might affect authentication:
   - `admin=true`
   - `role=administrator`
   - `verified=true`
   - `bypass=1`
3. Forward the request and see if access is granted.
4. Also try changing POST to GET or using different content types.

**Example**
```http
POST /login HTTP/1.1
...
username=user&password=pass&admin=true
```
If login succeeds with admin privileges → vulnerable.

**Tools**  
- Burp Repeater  
- Param Miner extension

**Risk Rating**  
High to Critical

**Remediation**  
- Never trust client-side parameters for security decisions  
- Use server-side session management  
- Validate all inputs

---

## 16. BYPASSING AUTHENTICATION VIA DIRECT PAGE ACCESS (FORCEFUL BROWSING)

**Description**  
Some pages lack proper access controls, allowing unauthenticated users to access authenticated content by directly navigating to the URL.

**What to Look For**
- Authenticated pages (dashboard, profile, admin) accessible without login
- Pages that redirect but then load content
- APIs that return data without authentication

**What to Ignore**
- Pages that properly redirect to login and then back

**How to Test with Burp Suite**
1. Identify protected pages by spidering or manual exploration.
2. In a private/incognito window, try to access those URLs directly.
3. If the page loads (or partially loads), note the vulnerability.
4. Also test by removing session cookies in Burp and resending requests.

**Example**
```
https://target.com/dashboard
```
Even without login, if the page shows dashboard (maybe with placeholder data), it's a flaw.

**Tools**  
- Burp Spider to discover links  
- Manual navigation  
- Dirb/gobuster

**Risk Rating**  
Medium to High

**Remediation**  
- Enforce authentication checks on every protected page  
- Use middleware/filters to verify session before serving content

---

## 17. MULTI-FACTOR AUTHENTICATION BYPASS

**Description**  
MFA can be bypassed if the application doesn't enforce it consistently.

**What to Look For**
- After successful first factor, you can directly access authenticated pages without MFA
- MFA only checked at login, not on subsequent sensitive actions
- Ability to disable MFA without re-authentication

**What to Ignore**
- Proper enforcement of MFA on every sensitive request

**How to Test with Burp Suite**
1. Complete first factor (username/password).
2. Intercept the response that would normally redirect to MFA.
3. Modify the response or simply drop it and request an authenticated page (e.g., `/dashboard`).
4. If the page loads, MFA is bypassed.
5. Also test sensitive actions (password change, money transfer) without completing MFA.

**Example**
```
POST /login
(credentials correct, server redirects to /2fa)
GET /dashboard
```
If dashboard loads → MFA bypass.

**Tools**  
- Burp Proxy (manually drop requests, modify flow)

**Risk Rating**  
High

**Remediation**  
- Enforce MFA check on server for each sensitive action  
- Use session flags to indicate MFA completed

---

## 18. INSECURE PASSWORD STORAGE (EXPOSURE VIA OTHER VULNERABILITIES)

**Description**  
Even if authentication is secure, passwords may be exposed through other vulnerabilities (SQLi, file disclosure, backup leaks).

**What to Look For**
- SQL injection that dumps user table with password hashes
- Exposed `.git`, `.env`, backup files containing database credentials
- APIs returning password hashes
- Weak hashing algorithms (MD5, SHA1 without salt)

**What to Ignore**
- Properly hashed passwords (bcrypt, Argon2) not exposed

**How to Test with Burp Suite**
1. Test for SQL injection (using **Intruder** or **SQLMap**) that could extract user data.
2. Look for common exposed files: `/backup.zip`, `/.git/config`, `/.env`.
3. Examine API responses for fields like `password_hash`, `pass`, etc.
4. Use **Burp Scanner** to check for sensitive file exposure.

**Example**
```http
GET /api/users HTTP/1.1
Response: [{"username": "admin", "password": "5f4dcc3b5aa765d61d8327deb882cf99"}]
```
MD5 hash of "password" can be cracked instantly.

**Tools**  
- Burp Scanner for sensitive files  
- SQLMap  
- Hashcat/John for cracking

**Risk Rating**  
Critical

**Remediation**  
- Use strong hashing (bcrypt, Argon2) with salt  
- Never store passwords in plaintext  
- Secure sensitive endpoints  
- Regular security audits

---

## 19. CAPTCHA BYPASS

**Description**  
CAPTCHAs meant to prevent automated attacks can be bypassed via various techniques.

**What to Look For**
- Simple text CAPTCHAs that can be read by OCR
- CAPTCHA token not invalidated after use (replay)
- CAPTCHA parameter can be removed from request
- CAPTCHA tied to session that can be reset

**What to Ignore**
- Modern CAPTCHA (reCAPTCHA v3) with proper implementation

**How to Test with Burp Suite**

**a) OCR Bypass**  
1. Download a CAPTCHA image.
2. Run it through Tesseract OCR.
3. Use the decoded text in your request.

**b) Reuse**  
1. Solve a CAPTCHA once.
2. Use the same CAPTCHA value in multiple requests. If accepted → vulnerable.

**c) Removal**  
1. Intercept a request that requires CAPTCHA.
2. Remove the CAPTCHA parameter entirely.
3. Send the request. If accepted → vulnerable.

**Example**
```http
POST /login
...
captcha=12345
```
If you send same request multiple times and it works, CAPTCHA not invalidated.

**Tools**  
- Burp Repeater  
- Tesseract OCR  
- 2captcha API

**Risk Rating**  
Medium

**Remediation**  
- Invalidate CAPTCHA after single use  
- Use modern CAPTCHA (reCAPTCHA v3)  
- Implement rate limiting as backup

---

## 20. RACE CONDITIONS IN AUTHENTICATION

**Description**  
When multiple authentication requests are sent simultaneously, the system might handle them incorrectly, leading to bypass or multiple sessions.

**What to Look For**
- Functions with limits (login attempts, OTP verification, coupon redemption) that can be exceeded by concurrency
- Registration that allows duplicate usernames when requests are concurrent

**What to Ignore**
- Properly atomic operations

**How to Test with Burp Suite**
1. Use **Turbo Intruder** to send multiple requests simultaneously.
2. For OTP verification: send 10 concurrent requests with the same OTP.
3. For login: send many attempts quickly to see if lockout is bypassed.
4. For registration: try to register the same username multiple times concurrently.

**Example (Turbo Intruder Python script)**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=100,
                           pipeline=False
                           )
    for i in range(50):
        engine.queue(target.req, [])
```

**Tools**  
- Burp Turbo Intruder  
- Custom Python threading

**Risk Rating**  
Medium

**Remediation**  
- Use atomic database operations for limits  
- Implement proper locking mechanisms  
- Use queues for critical operations

---

## 21. ACCOUNT LOCKOUT POLICY FLAWS (DoS OR BRUTE FORCE BYPASS)

**Description**  
Account lockout policies can be abused to cause Denial of Service (DoS) or bypassed.

**What to Look For**
- Lockout after few attempts (e.g., 3) without unlock mechanism (DoS risk)
- Lockout based only on IP (attacker can use many IPs)
- Lockout resets after a short time (attacker can wait and continue)
- No lockout for password spraying (many accounts, one password)

**What to Ignore**
- Progressive lockout (increasing delays) with CAPTCHA

**How to Test with Burp Suite**

**a) DoS**  
1. Attempt to log in with wrong password multiple times until lockout.
2. Try to log in with correct password; if locked out, legitimate user is denied.

**b) Bypass**  
1. Use a list of many usernames and one common password (password spraying).
2. If no lockout per account (only per IP), you can try many accounts without being locked.

**Example**  
- 5 failed attempts lock account for 24 hours.
- Attacker can lock out all users, causing DoS.

**Tools**  
- Custom scripts  
- Burp Intruder with multiple usernames

**Risk Rating**  
Medium

**Remediation**  
- Implement progressive lockout (increasing delays)  
- Use CAPTCHA after few failures instead of hard lockout  
- Allow users to unlock via email  
- Monitor for password spraying (one password many accounts)

---

## 22. INSECURE API AUTHENTICATION (MISSING TOKENS, WEAK API KEYS)

**Description**  
APIs may have weak or missing authentication, allowing unauthorized access.

**What to Look For**
- API endpoints accessible without any token
- API keys exposed in client-side code (JavaScript)
- API keys predictable (e.g., UUID v1, timestamp)
- No rate limiting on API

**What to Ignore**
- Properly authenticated APIs with strong keys

**How to Test with Burp Suite**
1. Identify API endpoints via **Target > Site map** or by analyzing JavaScript (use **JS Link Finder** extension).
2. Send requests to API endpoints without authentication headers.
3. If data is returned, it's missing auth.
4. If API keys are used, check if they are exposed in frontend code (view source, network tab).
5. Try to brute force API keys if they appear sequential (use Intruder).

**Example**
```http
GET /api/users HTTP/1.1
```
If returns user list without any token, API is wide open.

**Tools**  
- Burp  
- Postman  
- JS analysis tools

**Risk Rating**  
Critical

**Remediation**  
- Require authentication for all API endpoints  
- Use strong, random API keys  
- Never expose keys in client-side code (use backend proxy)  
- Implement rate limiting and scopes

---

## 23. SOCIAL LOGIN / OAUTH FLAWS

**Description**  
OAuth implementations can have flaws allowing account takeover.

**What to Look For**
- `redirect_uri` not validated (can be changed to attacker's domain)
- Missing or static `state` parameter (CSRF)
- Authorization code in URL (may leak via referer)
- Improper token validation (attacker can use code meant for another app)

**What to Ignore**
- Proper OAuth with PKCE, state parameter, and redirect_uri whitelist

**How to Test with Burp Suite**

**a) redirect_uri tampering**  
1. Intercept the OAuth authorization request.
2. Change `redirect_uri` to your domain (e.g., `https://evil.com/callback`).
3. If the provider redirects the code to your domain, you can capture it.

**b) Missing state**  
1. If `state` parameter is missing, attacker can initiate OAuth and intercept the code.
2. Try to replay an authorization code.

**Example**
```
https://oauth.provider.com/auth?
 client_id=123&
 redirect_uri=https://evil.com/callback&
 response_type=code
```
If provider allows, user gets code sent to evil.com.

**Tools**  
- Burp  
- Manual parameter manipulation

**Risk Rating**  
High

**Remediation**  
- Validate redirect_uri against a whitelist  
- Use and validate state parameter (CSRF token)  
- Use PKCE for mobile/public clients  
- Keep authorization codes short-lived

---

## 24. SAML AUTHENTICATION FLAWS

**Description**  
Security Assertion Markup Language (SAML) is used for SSO. Common attacks include signature stripping and XML wrapping.

**What to Look For**
- SAML response without signature accepted
- Ability to modify assertions while keeping signature valid (XML wrapping)
- Replay of SAML responses
- XML comments breaking signature validation

**What to Ignore**
- Proper signature validation with secure XML parsing

**How to Test with Burp Suite (using SAML Raider)**

**a) Signature Stripping**  
1. Intercept SAML response.
2. Remove the `<ds:Signature>` element entirely.
3. Forward the modified response; if accepted → vulnerable.

**b) XML Wrapping**  
1. Insert a new forged assertion inside the original (using SAML Raider's "Wrapping" feature).
2. Send and see if application processes the wrapped assertion.

**c) Replay**  
1. Capture a valid SAML response.
2. Replay it later; if accepted → vulnerable.

**Example (signature stripping)**
```xml
<saml:Assertion>
  <saml:Subject>...</saml:Subject>
  <!-- remove <ds:Signature> entirely -->
</saml:Assertion>
```

**Tools**  
- Burp  
- SAML Raider (Burp extension)  
- Custom scripts

**Risk Rating**  
Critical

**Remediation**  
- Validate signatures strictly  
- Use secure XML parsing  
- Check for multiple assertions  
- Use short assertion lifetimes  
- Implement replay detection

---

## 25. LDAP / ACTIVE DIRECTORY INJECTION

**Description**  
If application uses LDAP for authentication, attackers can inject LDAP filters to bypass authentication.

**What to Look For**
- Login forms that might query LDAP
- Special characters (`*`, `(`, `)`, `&`, `|`) not filtered
- Error messages indicating LDAP syntax

**What to Ignore**
- Properly escaped inputs

**How to Test with Burp Suite**
1. In the username field, try payloads like:
   - `admin*`
   - `admin)(|(uid=*`
   - `*)(uid=*`
2. Observe if login succeeds without valid password.

**Example**
LDAP filter: `(&(uid=USER)(userPassword=PASS))`
Inject: `USER = admin)(|(uid=*` → filter becomes `(&(uid=admin)(|(uid=*)(userPassword=PASS))` which may always succeed.

**Tools**  
- Burp  
- Custom payloads  
- ldapsearch (for manual testing)

**Risk Rating**  
Critical

**Remediation**  
- Escape special LDAP characters  
- Use parameterized queries (if LDAP library supports)  
- Avoid constructing filters from user input

---

## 26. SQL INJECTION IN AUTHENTICATION

**Description**  
SQL injection in login forms can bypass authentication entirely.

**What to Look For**
- Login forms that might be vulnerable to SQLi
- Error messages revealing SQL syntax
- Ability to log in without valid credentials using payloads like `' OR '1'='1`

**What to Ignore**
- Parameterized queries and proper input handling

**How to Test with Burp Suite**
1. In the username field, try:
   - `' OR '1'='1`
   - `admin'--`
   - `' UNION SELECT 1, 'admin', 'hash'--`
2. If login succeeds, vulnerable.

**Example**
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' -- ' AND password = 'anything'
```
The `--` comments out the password check.

**Tools**  
- Burp Intruder (with SQL payloads)  
- SQLMap (if vulnerable)

**Risk Rating**  
Critical

**Remediation**  
- Use parameterized queries (prepared statements)  
- Input validation  
- Least privilege DB user

---

## 27. XML INJECTION IN AUTHENTICATION

**Description**  
If authentication uses XML (e.g., SOAP), XML injection can lead to bypass.

**What to Look For**
- XML-based authentication requests
- Ability to inject new elements or modify existing ones
- XXE vulnerabilities

**What to Ignore**
- Strict schema validation

**How to Test with Burp Suite**
1. Intercept an XML authentication request.
2. Try adding an extra element like `<role>admin</role>` inside the login block.
3. Also test for XXE: inject a DOCTYPE with external entity.

**Example**
```xml
<soap:Envelope>
  <soap:Body>
    <login>
      <username>admin</username>
      <password>any</password>
      <isAdmin>true</isAdmin>  <!-- injected -->
    </login>
  </soap:Body>
</soap:Envelope>
```

**Tools**  
- Burp  
- Custom XML payloads

**Risk Rating**  
Medium to High

**Remediation**  
- Validate XML schema strictly  
- Disable external entity processing (XXE)  
- Use secure XML parsers

---

## 28. NOSQL INJECTION IN AUTHENTICATION

**Description**  
For NoSQL databases (MongoDB), injection can bypass authentication.

**What to Look For**
- JSON-based login requests
- Ability to use operators like `$ne`, `$gt`
- No input sanitization

**What to Ignore**
- Proper validation and type checking

**How to Test with Burp Suite**
1. Send login request as JSON.
2. Modify username to `{"$ne": ""}` and password to `{"$ne": ""}`.
3. If login succeeds, vulnerable.

**Example (MongoDB)**
```javascript
db.users.find({username: req.body.username, password: req.body.password})
```
If attacker sends `{"username": {"$ne": null}, "password": {"$ne": null}}`, query returns all users, and first one may be logged in.

**Tools**  
- Burp  
- Custom scripts  
- NoSQLMap

**Risk Rating**  
Critical

**Remediation**  
- Validate and sanitize input  
- Use strict type checking  
- Avoid passing raw user input to queries

---

## 29. AUTHENTICATION TIMING ATTACKS

**Description**  
If response times differ for valid vs invalid credentials (e.g., due to password hashing time), attackers can enumerate users or even guess passwords.

**What to Look For**
- Consistent timing differences between valid and invalid usernames
- Password comparison not constant-time

**What to Ignore**
- Uniform response times across all attempts

**How to Test with Burp Suite**
1. Use **Repeater** to send requests for valid and invalid users.
2. Observe response times (Burp shows time in ms).
3. Use **Intruder** with a few requests and note times.
4. For more precision, use custom Python script with `time` module.

**Example**
- Valid user: ~500ms (due to password hash verification)
- Invalid user: ~50ms
- Attacker can determine which usernames exist.

**Tools**  
- Burp (with response timing)  
- Custom Python scripts (using `time` module)

**Risk Rating**  
Low (enumeration) to Medium (if password timing)

**Remediation**  
- Use constant-time comparison for passwords  
- Always perform password hash even if user not found (to equalize timing)  
- Add random delays or use same flow

---

## 30. CREDENTIAL LEAKAGE VIA REFERER, LOGS, OR OTHER CHANNELS

**Description**  
Credentials may be leaked unintentionally through Referer headers, server logs, browser history, or third-party scripts.

**What to Look For**
- Login page containing external HTTP resources (images, scripts) → Referer leakage
- Credentials passed in URL (GET parameters) → appear in logs, browser history
- Third-party scripts on login page that could capture input
- Autofill fields that can be exploited via CSS

**What to Ignore**
- Login pages with no external resources and POST-only credentials

**How to Test with Burp Suite**

**a) Referer Leakage**  
1. Check if login page loads any resources over HTTP (Burp will show mixed content warnings).
2. If yes, when form is submitted, the Referer header (containing the login page URL) will be sent to those external domains.

**b) GET Parameters**  
1. Check if login form uses GET instead of POST. If so, credentials appear in URL.

**c) Third-party Scripts**  
1. Review all scripts loaded on login page.
2. If any from untrusted domains, they could exfiltrate data.

**Example**
```
https://target.com/login
```
Contains:
```html
<img src="http://evil.com/tracker.jpg">
```
When login POST is made, the Referer header includes the login page URL (and sometimes query params) sent to evil.com.

**Tools**  
- Burp (check for mixed content)  
- Browser DevTools (network tab)

**Risk Rating**  
Medium

**Remediation**  
- Use HTTPS site-wide  
- Avoid passing credentials in URL  
- Set `Referrer-Policy: no-referrer` or strict  
- Audit third-party scripts  
- Disable autofill on sensitive forms if not needed

---

## ✅ **SUMMARY**

Authentication is the first line of defense. A single flaw can lead to complete compromise. This comprehensive checklist covers all major attack vectors from industry-standard frameworks (OWASP, PTES, NIST). Use it to structure your VAPT testing.

**Pro Tip:** Automate where possible using Burp Suite's scanner and extensions, but manual verification is crucial for logic flaws. Always follow responsible disclosure and obtain proper authorization before testing.

--- 

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
