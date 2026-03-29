# 🔒 **A04: INSECURE DESIGN TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Design-Level Vulnerabilities*

---

## 📋 **TABLE OF CONTENTS**

1. [Lack of Input Validation at Design Level](#1-lack-of-input-validation-at-design-level)
2. [Missing Authorization Checks in Workflow Design](#2-missing-authorization-checks-in-workflow-design)
3. [Trusting Client-Side Validation Only](#3-trusting-client-side-validation-only)
4. [Insecure Default Configurations](#4-insecure-default-configurations)
5. [Lack of Rate Limiting in Design](#5-lack-of-rate-limiting-in-design)
6. [Missing Security Headers in Design](#6-missing-security-headers-in-design)
7. [Insufficient Logging and Monitoring Design](#7-insufficient-logging-and-monitoring-design)
8. [Lack of Secure Error Handling Design](#8-lack-of-secure-error-handling-design)
9. [Overly Permissive CORS Policy Design](#9-overly-permissive-cors-policy-design)
10. [Insecure Direct Object Reference (IDOR) by Design](#10-insecure-direct-object-reference-idor-by-design)
11. [Mass Assignment Vulnerabilities by Design](#11-mass-assignment-vulnerabilities-by-design)
12. [Lack of Defense in Depth](#12-lack-of-defense-in-depth)
13. [Insecure Cryptographic Storage Design](#13-insecure-cryptographic-storage-design)
14. [Insufficient Session Expiration Design](#14-insufficient-session-expiration-design)
15. [Insecure Password Recovery Design](#15-insecure-password-recovery-design)
16. [Lack of Account Lockout Mechanisms](#16-lack-of-account-lockout-mechanisms)
17. [Insufficient Input Sanitization Design](#17-insufficient-input-sanitization-design)
18. [Missing Security Testing in SDLC](#18-missing-security-testing-in-sdlc)
19. [Lack of Secure API Design (e.g., RESTful)](#19-lack-of-secure-api-design-restful)
20. [Insecure File Upload Design](#20-insecure-file-upload-design)
21. [Insecure Deserialization Design](#21-insecure-deserialization-design)
22. [Missing Anti-CSRF Tokens by Design](#22-missing-anti-csrf-tokens-by-design)
23. [Lack of Proper Access Control Model (e.g., RBAC not implemented)](#23-lack-of-proper-access-control-model-rbac-not-implemented)
24. [Insufficient Data Protection at Rest](#24-insufficient-data-protection-at-rest)
25. [Insecure Third-Party Component Integration](#25-insecure-third-party-component-integration)
26. [Lack of Secure Defaults for New Users](#26-lack-of-secure-defaults-for-new-users)
27. [Missing Security Requirements in Design Phase](#27-missing-security-requirements-in-design-phase)
28. [Inadequate Business Logic Validation](#28-inadequate-business-logic-validation)
29. [Lack of Secure Session Management Design](#29-lack-of-secure-session-management-design)
30. [Absence of Security Architecture Review](#30-absence-of-security-architecture-review)

---

## 1. LACK OF INPUT VALIDATION AT DESIGN LEVEL

**Description**  
Insecure design often manifests as the absence of input validation at the architectural level. When an application does not validate, sanitize, or reject malicious input early, it leads to injection, data corruption, and bypass of business logic.

**What to Look For**
- All input fields (forms, APIs, file uploads) are accepted without checking type, length, format, or allowed values.
- Input is used directly in queries, commands, or templates.
- No centralized input validation framework.

**What to Ignore**
- Applications that use parameterized queries and enforce strict input validation on all inputs.

**How to Test with Burp Suite**
1. Identify all input points (GET/POST parameters, JSON bodies, headers, file uploads).
2. Send unexpected data types (e.g., strings in numeric fields, extremely long strings, special characters).
3. Observe if the application rejects malformed input or processes it insecurely (e.g., SQL errors, command execution).
4. Use Burp Intruder to fuzz inputs with a payload list of special characters and injection patterns.

**Example**
```http
POST /api/user HTTP/1.1
{"name":"<script>alert(1)</script>","age":"one hundred"}
```
If the server stores the script without validation, design is flawed.

**Tools**
- Burp Intruder
- OWASP ZAP Fuzzer
- Custom scripts

**Risk Rating**  
High to Critical

**Remediation**
- Define a centralized input validation layer (e.g., validation framework, schema validation).
- Validate all inputs against a strict whitelist of allowed values.
- Use parameterized queries and safe APIs to prevent injection.

---

## 2. MISSING AUTHORIZATION CHECKS IN WORKFLOW DESIGN

**Description**  
Insecure design often omits authorization checks in multi-step workflows. For example, a user may be allowed to skip steps or access a later step directly without completing earlier steps that require verification.

**What to Look For**
- Wizards or multi-page forms where steps can be accessed out of order.
- No server-side tracking of workflow state.
- Ability to directly call final action endpoints without prerequisites.

**What to Ignore**
- Workflows that maintain state server-side and validate each step’s completion before proceeding.

**How to Test with Burp Suite**
1. Identify a multi-step process (e.g., registration, checkout, password reset).
2. Try to directly access the final step URL (e.g., `/checkout/confirm`) without completing previous steps.
3. Intercept requests and attempt to change the state parameters (e.g., `step=2` to `step=3`).
4. Observe if the application processes the request or rejects it.

**Example**
```
Directly request:
GET /password-reset/confirm?token=123
```
If the token is valid but the user never requested a reset, the design is flawed.

**Tools**
- Burp Proxy
- Burp Repeater
- Manual navigation

**Risk Rating**  
High

**Remediation**
- Maintain workflow state on the server, not just client-side.
- Validate that all required steps have been completed before processing.
- Use secure tokens that tie to the specific session and step.

---

## 3. TRUSTING CLIENT-SIDE VALIDATION ONLY

**Description**  
Relying solely on client-side validation (JavaScript) is a design flaw because attackers can bypass it by sending crafted requests directly to the server.

**What to Look For**
- JavaScript that performs validation but no equivalent server-side checks.
- Requests that can be replayed with invalid data and are accepted.

**What to Ignore**
- Server-side validation that mirrors client-side checks and cannot be bypassed.

**How to Test with Burp Suite**
1. Perform a normal action that includes validation (e.g., submit a form with required fields).
2. In Burp, capture the request and modify a field to an invalid value (e.g., empty, too long, special chars).
3. Send the request directly to the server (bypassing the browser).
4. If the server accepts the invalid data, it trusts client-side validation only.

**Example**
```html
<!-- Client-side: input maxlength=10 -->
<input type="text" name="username" maxlength="10">
```
Attacker sends:
```http
POST /register
username=thisisaverylongusernameexceedinglimits
```
If the server accepts it, design is flawed.

**Tools**
- Burp Repeater
- Burp Proxy

**Risk Rating**  
High

**Remediation**
- Always validate input on the server side, regardless of client-side checks.
- Use server-side frameworks that enforce validation rules.

---

## 4. INSECURE DEFAULT CONFIGURATIONS

**Description**  
Insecure design includes default settings that are not hardened for production, such as default passwords, enabled debug modes, or overly permissive permissions.

**What to Look For**
- Default admin credentials (admin/admin) still active.
- Debug mode enabled (stack traces, verbose error messages).
- Directory listing enabled.
- Unnecessary services or endpoints exposed.

**What to Ignore**
- Systems that force credential changes on first login and disable debug features in production.

**How to Test with Burp Suite**
1. Try common default credentials on admin panels.
2. Probe for debug endpoints: `/phpinfo.php`, `/debug`, `/status`, `/config`.
3. Check for directory listing by accessing `/uploads/`, `/static/`, etc.

**Example**
```http
GET /phpinfo.php HTTP/1.1
```
If phpinfo is accessible, the server exposes sensitive configuration.

**Tools**
- Dirb/Gobuster
- Burp Intruder with common paths
- Nmap

**Risk Rating**  
High

**Remediation**
- Harden default configurations before deployment.
- Enforce strong password policies and remove default accounts.
- Disable debug mode and unnecessary services in production.

---

## 5. LACK OF RATE LIMITING IN DESIGN

**Description**  
Designing an application without rate limiting allows attackers to brute force credentials, enumerate users, and launch denial-of-service attacks.

**What to Look For**
- Login, password reset, or API endpoints that do not limit request frequency.
- No captcha or throttling after multiple failures.
- Ability to send thousands of requests in a short time.

**What to Ignore**
- Endpoints protected by rate limiting (per IP, per user) and captcha.

**How to Test with Burp Suite**
1. Use Intruder or Turbo Intruder to send many requests to a login endpoint.
2. Observe if any responses indicate lockout or if all attempts are processed.
3. Use a list of usernames to test password spraying (one password, many usernames).

**Example**
```http
POST /login
username=admin&password=§word§
```
Send 100 attempts. If all 100 are processed, no rate limiting.

**Tools**
- Burp Intruder / Turbo Intruder
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Implement rate limiting (by IP, by user, by endpoint).
- Use captcha after a defined number of failures.
- Apply progressive delays.

---

## 6. MISSING SECURITY HEADERS IN DESIGN

**Description**  
Security headers (e.g., Content-Security-Policy, X-Frame-Options, HSTS) are often omitted in the design phase, leaving the application vulnerable to clickjacking, XSS, and protocol downgrade attacks.

**What to Look For**
- Absence of `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`.
- No `Referrer-Policy` or `Permissions-Policy`.

**What to Ignore**
- Properly configured security headers that mitigate common client-side attacks.

**How to Test with Burp Suite**
1. Intercept responses and check for security headers.
2. Use Burp Scanner (passive) to report missing headers.
3. Use online tools like securityheaders.com.

**Example**
```http
HTTP/1.1 200 OK
Server: nginx
Date: ...
```
Missing any security headers.

**Tools**
- Burp Scanner
- Browser DevTools
- Securityheaders.com

**Risk Rating**  
Medium to High

**Remediation**
- Include security headers in the application design.
- Set appropriate values: `Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, `Strict-Transport-Security: max-age=31536000`.

---

## 7. INSUFFICIENT LOGGING AND MONITORING DESIGN

**Description**  
Designing an application without sufficient logging and monitoring prevents detection of attacks and hampers incident response.

**What to Look For**
- No logs of failed logins, privilege changes, or sensitive actions.
- Logs stored locally without protection.
- No integration with SIEM or alerting.

**What to Ignore**
- Detailed logs with appropriate retention, integrity protection, and real-time alerting.

**How to Test with Burp Suite**
1. Perform actions that should be logged (e.g., login failures, password changes).
2. If you have access to logs (e.g., through debug endpoints), verify entries.
3. Attempt to perform actions that would trigger alerts (e.g., brute force) and see if any response indicates detection.

**Example**
- No logging of password reset requests may allow an attacker to reset many accounts without detection.

**Tools**
- Manual verification
- Access to log endpoints (if exposed)

**Risk Rating**  
High

**Remediation**
- Log all authentication events, privilege changes, and sensitive operations.
- Store logs securely with integrity checks.
- Implement monitoring and alerting for anomalous patterns.

---

## 8. LACK OF SECURE ERROR HANDLING DESIGN

**Description**  
Design that exposes detailed error messages (stack traces, SQL errors) to users gives attackers valuable information for exploitation.

**What to Look For**
- Stack traces displayed in responses.
- SQL errors revealing database schema.
- Debug information in HTML comments or JSON responses.

**What to Ignore**
- Custom error pages that do not reveal system details.

**How to Test with Burp Suite**
1. Trigger errors by sending malformed input.
2. Examine responses for stack traces, database errors, file paths.
3. Use Intruder to inject characters that cause errors (e.g., single quote, null byte).

**Example**
```http
GET /user?id=' HTTP/1.1
```
Response:
```
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version...
```

**Tools**
- Burp Repeater
- Burp Intruder

**Risk Rating**  
Medium to High

**Remediation**
- Use generic error messages for users.
- Log detailed errors internally.
- Disable debug mode in production.

---

## 9. OVERLY PERMISSIVE CORS POLICY DESIGN

**Description**  
A design that allows any origin to access sensitive endpoints (`Access-Control-Allow-Origin: *`) with credentials can lead to data theft via malicious websites.

**What to Look For**
- `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`.
- Dynamic origin reflection (echoing the `Origin` header) without validation.

**What to Ignore**
- Strict CORS policies with a whitelist of trusted origins and no credentials for wildcard.

**How to Test with Burp Suite**
1. Send a request with a custom `Origin` header.
2. Observe if the response includes `Access-Control-Allow-Origin` reflecting that origin and `Access-Control-Allow-Credentials: true`.
3. If so, any site can read the response.

**Example**
```http
GET /api/user HTTP/1.1
Origin: https://evil.com
```
Response:
```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```
Vulnerable.

**Tools**
- Burp Repeater
- CORS scanner extensions

**Risk Rating**  
High

**Remediation**
- Do not use wildcard with credentials.
- Validate origins against a whitelist.
- Use `SameSite` cookie attributes to mitigate.

---

## 10. INSECURE DIRECT OBJECT REFERENCE (IDOR) BY DESIGN

**Description**  
When the design uses predictable identifiers (e.g., sequential IDs) for objects and fails to enforce access control, attackers can access unauthorized data.

**What to Look For**
- Use of numeric IDs in URLs or API calls.
- No ownership checks before serving data.

**What to Ignore**
- Use of unguessable identifiers (UUID v4) with proper authorization checks.

**How to Test with Burp Suite**
1. Identify endpoints that take object IDs (e.g., `/order/123`).
2. Try changing the ID to another user’s ID.
3. Observe if data is returned without authorization.

**Example**
```http
GET /api/profile?userId=123
```
Try `userId=124` and see if another user's profile appears.

**Tools**
- Burp Repeater
- Burp Intruder for enumeration

**Risk Rating**  
High to Critical

**Remediation**
- Use indirect references or unpredictable identifiers.
- Implement server‑side authorization checks on every object access.

---

## 11. MASS ASSIGNMENT VULNERABILITIES BY DESIGN

**Description**  
When the design automatically binds request parameters to internal objects without whitelisting, attackers can inject extra parameters to modify fields they should not control (e.g., `role=admin`).

**What to Look For**
- Use of frameworks that auto‑bind parameters (Rails, Laravel, Spring) without `$fillable` or similar protection.
- No explicit validation of which fields can be updated.

**What to Ignore**
- Explicitly defined lists of allowed parameters.

**How to Test with Burp Suite**
1. Capture a request to create or update a resource.
2. Add extra parameters like `role=admin`, `isAdmin=true`.
3. Observe if the extra parameter is accepted and applied.

**Example**
```http
POST /api/user HTTP/1.1
{"name":"attacker","email":"attacker@evil.com","role":"admin"}
```
If the user is created with admin role, mass assignment is possible.

**Tools**
- Burp Repeater
- Param Miner

**Risk Rating**  
Critical

**Remediation**
- Define `fillable` or `guarded` properties in models.
- Use form requests with validation that whitelists fields.
- Never use `$request->all()` without filtering.

---

## 12. LACK OF DEFENSE IN DEPTH

**Description**  
A design that relies on a single security control (e.g., only a WAF) without layered defenses leaves the application vulnerable when that control fails.

**What to Look For**
- Only one security mechanism in place (e.g., no input validation, only output encoding).
- No segmentation between components.
- Single point of failure in security.

**What to Ignore**
- Multiple layers: input validation, output encoding, WAF, monitoring, least privilege.

**How to Test with Burp Suite**
1. Attempt to bypass a single control (e.g., by encoding payloads).
2. Observe if other layers block the attack.
3. For example, if WAF blocks SQLi but parameterized queries are not used, a bypass may still lead to injection.

**Example**
- Application relies on a WAF but uses string concatenation for SQL queries. An attacker bypasses WAF with obfuscation and exploits SQLi.

**Tools**
- Burp Repeater with encoding tricks
- Manual testing

**Risk Rating**  
High

**Remediation**
- Implement multiple independent security controls (input validation, parameterized queries, output encoding, WAF, monitoring).
- Assume any single control can be bypassed.

---

## 13. INSECURE CRYPTOGRAPHIC STORAGE DESIGN

**Description**  
Design decisions that lead to storing sensitive data (passwords, PII) with weak or no encryption, using deprecated algorithms, or storing keys alongside the data.

**What to Look For**
- Passwords stored in plaintext or with MD5.
- Encryption keys hardcoded or in source control.
- Use of ECB mode or weak ciphers.

**What to Ignore**
- Strong, adaptive hashing (bcrypt, Argon2) with per-user salt.
- Keys managed by secure key management services.

**How to Test with Burp Suite**
1. If you have access to the database (via SQLi), examine password hashes.
2. Look for patterns that indicate weak hashing (e.g., MD5 length).
3. Test if sensitive data (e.g., credit card) is stored in plaintext.

**Example**
Database row: `password = "5f4dcc3b5aa765d61d8327deb882cf99"` (MD5 of "password").

**Tools**
- SQLMap
- Hashcat (to crack weak hashes)

**Risk Rating**  
Critical

**Remediation**
- Use strong, adaptive hashing for passwords.
- Encrypt sensitive data at rest with strong algorithms (AES-256-GCM) and manage keys securely.
- Never hardcode keys.

---

## 14. INSUFFICIENT SESSION EXPIRATION DESIGN

**Description**  
Design that does not enforce session expiration allows sessions to remain valid indefinitely, increasing the window for session hijacking.

**What to Look For**
- No idle timeout (session never expires).
- Extremely long absolute timeout (e.g., years).
- No server-side session expiry.

**What to Ignore**
- Reasonable idle timeout (15-30 minutes) and absolute timeout (8 hours) enforced server-side.

**How to Test with Burp Suite**
1. Log in and obtain a session token.
2. Wait for the expected timeout (e.g., 30 minutes).
3. Replay the session token in Repeater.
4. If still accepted, timeout is insufficient.

**Example**
```http
GET /profile HTTP/1.1
Cookie: session=abc123
```
Sent after 24 hours – still returns profile data.

**Tools**
- Burp Repeater
- Custom scripts with time delays

**Risk Rating**  
Medium to High

**Remediation**
- Implement idle and absolute session timeouts.
- Store session expiry server-side and enforce it.

---

## 15. INSECURE PASSWORD RECOVERY DESIGN

**Description**  
Design flaws in password recovery, such as predictable tokens, weak security questions, or allowing recovery without identity verification, enable account takeover.

**What to Look For**
- Reset tokens in URLs that are predictable (sequential, timestamp).
- Security questions with guessable answers (e.g., “mother's maiden name”).
- Ability to reset password without verifying identity (e.g., only email).

**What to Ignore**
- Random tokens with short expiry sent via secure channel, and multi-factor identity verification.

**How to Test with Burp Suite**
1. Request a password reset and capture the token.
2. Analyze token pattern (sequential, base64 user ID).
3. Try to reset another user’s password by guessing the token.

**Example**
Reset link: `https://target.com/reset?token=123456` – sequential.

**Tools**
- Burp Sequencer
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Use cryptographically random tokens with short expiry.
- Avoid security questions; use multi‑factor verification (email + SMS).
- Invalidate tokens after use.

---

## 16. LACK OF ACCOUNT LOCKOUT MECHANISMS

**Description**  
Design that does not lock accounts after repeated failed logins allows brute force attacks.

**What to Look For**
- No account lockout after multiple failed attempts.
- Lockout resets quickly (e.g., 5 minutes) enabling continuous brute force.
- Lockout based only on IP, not on username.

**What to Ignore**
- Progressive lockout (increasing delays) or account lockout with CAPTCHA.

**How to Test with Burp Suite**
1. Send many failed login attempts for a known username.
2. If you can continue without interruption, lockout is absent.
3. Try password spraying (one password, many usernames) to see if lockout triggers.

**Example**
Send 100 incorrect logins to `admin`; still no lockout.

**Tools**
- Burp Intruder
- Turbo Intruder

**Risk Rating**  
High

**Remediation**
- Implement account lockout after a reasonable number of failures (e.g., 5).
- Use CAPTCHA to differentiate humans from bots.
- Consider progressive delays instead of hard lockout to prevent DoS.

---

## 17. INSUFFICIENT INPUT SANITIZATION DESIGN

**Description**  
Design that does not sanitize input for injection attacks (SQL, XSS, command) leads to severe vulnerabilities.

**What to Look For**
- Input is used directly in SQL queries, shell commands, or HTML output without sanitization.
- No encoding when outputting user data.

**What to Ignore**
- Use of parameterized queries, prepared statements, and output encoding (e.g., HTML entity encoding).

**How to Test with Burp Suite**
1. Inject SQL payloads (e.g., `' OR 1=1--`) in all input fields.
2. Inject XSS payloads (`<script>alert(1)</script>`).
3. Inject OS commands (`; whoami`).
4. Observe if the application is affected.

**Example**
```http
GET /search?q=' OR '1'='1
```
If results include all records, SQLi is present.

**Tools**
- Burp Intruder
- SQLMap
- XSStrike

**Risk Rating**  
Critical

**Remediation**
- Use parameterized queries for all database interactions.
- Use safe APIs for system commands.
- Encode output according to context (HTML, JavaScript, URL, etc.).

---

## 18. MISSING SECURITY TESTING IN SDLC

**Description**  
When security testing is not integrated into the software development lifecycle, vulnerabilities go undetected until after deployment.

**What to Look For**
- No evidence of static analysis, dynamic analysis, or penetration testing.
- Vulnerabilities that could have been caught early (e.g., SQLi, XSS) are present.

**What to Ignore**
- Security testing performed at every stage (design review, SAST, DAST, pentest).

**How to Test with Burp Suite**
- This is a process review rather than technical test. However, you can identify missing security controls by the prevalence of easily detectable vulnerabilities that should have been caught.

**Example**
- Multiple critical vulnerabilities (SQLi, XSS) in production that would have been found by a basic DAST scan.

**Tools**
- Manual process review
- Vulnerability scanner results

**Risk Rating**  
High

**Remediation**
- Integrate security testing in CI/CD (SAST, DAST).
- Perform threat modeling during design.
- Conduct regular penetration testing.

---

## 19. LACK OF SECURE API DESIGN (E.G., RESTFUL)

**Description**  
APIs designed without security considerations (e.g., no authentication, excessive data exposure, improper HTTP methods) expose sensitive data and functionality.

**What to Look For**
- API endpoints lacking authentication or authorization.
- Responses returning more data than needed (e.g., full user objects including password hashes).
- Use of GET for state-changing operations.

**What to Ignore**
- APIs with proper authentication, scoped permissions, and minimal data exposure.

**How to Test with Burp Suite**
1. Discover API endpoints (via JS analysis, spidering).
2. Attempt to access them without credentials.
3. Check if responses include sensitive fields.
4. Try to modify data using GET requests.

**Example**
```http
GET /api/users/123
```
Response includes `"password_hash": "..."`.

**Tools**
- Burp Repeater
- Postman
- API scanners

**Risk Rating**  
Critical

**Remediation**
- Enforce authentication and authorization for all API endpoints.
- Use proper HTTP methods (GET for read, POST for create, etc.).
- Limit returned fields (use field selection or separate endpoints).

---

## 20. INSECURE FILE UPLOAD DESIGN

**Description**  
Design that allows arbitrary file uploads without validation leads to remote code execution, malware distribution, and defacement.

**What to Look For**
- No file type validation (only client‑side).
- Uploaded files stored in web‑accessible locations.
- No restrictions on file size or content.

**What to Ignore**
- Whitelist of allowed file types, server‑side validation, storage outside webroot, and unique filenames.

**How to Test with Burp Suite**
1. Upload a malicious file (e.g., `shell.php`).
2. Attempt to access the uploaded file via its URL.
3. Try to bypass extension restrictions by renaming (e.g., `shell.php.jpg`).

**Example**
```http
POST /upload
Content-Type: multipart/form-data

file: shell.php
```
If the file can be accessed and executed, design is insecure.

**Tools**
- Burp Repeater
- Custom file upload scripts

**Risk Rating**  
Critical

**Remediation**
- Validate file type on server (whitelist extensions and MIME types).
- Store files outside webroot and serve through a script that enforces access controls.
- Use Content-Disposition: attachment to prevent execution.

---

## 21. INSECURE DESERIALIZATION DESIGN

**Description**  
Design that deserializes untrusted data without validation leads to remote code execution, denial of service, and privilege escalation.

**What to Look For**
- Use of `pickle`, `ObjectInputStream`, `JSON.parse` with untrusted data.
- No integrity checks (e.g., HMAC) on serialized objects.

**What to Ignore**
- Deserialization of trusted data only, or use of safe formats (e.g., JSON) with validation.

**How to Test with Burp Suite**
1. Identify endpoints that accept serialized data (e.g., base64‑encoded Java objects, PHP sessions).
2. Use tools like `ysoserial` to generate payloads.
3. Send payload and observe for errors, delays, or command execution.

**Example**
```http
POST /api/data
Cookie: session=O:4:"User":2:{s:4:"name";s:4:"admin";s:7:"isAdmin";b:1;}
```
If the server processes the object, deserialization may be vulnerable.

**Tools**
- ysoserial
- Burp Repeater
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Avoid deserializing untrusted data.
- Use integrity checks (HMAC) on serialized objects.
- Use safe data formats (JSON) with strict schema validation.

---

## 22. MISSING ANTI-CSRF TOKENS BY DESIGN

**Description**  
Design that does not include anti‑CSRF tokens for state‑changing requests leaves users vulnerable to cross‑site request forgery.

**What to Look For**
- Forms that do not contain a CSRF token.
- API endpoints that accept state‑changing requests without checking a token.

**What to Ignore**
- All state‑changing requests protected by a CSRF token (or same‑site cookies with proper context).

**How to Test with Burp Suite**
1. Identify a POST request that changes state (e.g., transfer, profile update).
2. Remove the CSRF token from the request (if present) or try to use a token from another user.
3. If the request still succeeds, CSRF protection is missing.

**Example**
```html
<form action="/transfer" method="POST">
  <input name="amount" value="1000">
  <input name="to" value="attacker">
</form>
```
No CSRF token.

**Tools**
- Burp Repeater
- Burp CSRF PoC generator

**Risk Rating**  
High

**Remediation**
- Include anti‑CSRF tokens in all state‑changing requests.
- Validate tokens server‑side.
- Use `SameSite=Lax` or `Strict` cookies as defense in depth.

---

## 23. LACK OF PROPER ACCESS CONTROL MODEL (RBAC NOT IMPLEMENTED)

**Description**  
Design that does not define or enforce roles and permissions leads to users being able to perform actions outside their privilege.

**What to Look For**
- No distinction between regular users and admins in code.
- All users have the same permissions.
- Hard‑coded checks based on usernames instead of roles.

**What to Ignore**
- Role‑based access control (RBAC) with clearly defined roles and permissions enforced server‑side.

**How to Test with Burp Suite**
1. Log in as a regular user.
2. Attempt to access administrative endpoints (e.g., `/admin`, `/api/admin`).
3. Try to perform actions that should be restricted (e.g., delete other users).
4. Observe if access is granted.

**Example**
```http
GET /admin/users HTTP/1.1
Cookie: session=user_session
```
If page loads with user list, RBAC is missing.

**Tools**
- Burp Repeater
- Autorize extension

**Risk Rating**  
Critical

**Remediation**
- Implement RBAC with centrally managed roles and permissions.
- Enforce checks on every sensitive function.

---

## 24. INSUFFICIENT DATA PROTECTION AT REST

**Description**  
Design that does not encrypt sensitive data at rest exposes it if the storage media is compromised.

**What to Look For**
- Database contains plaintext passwords, credit card numbers, or PII.
- Backups stored unencrypted.

**What to Ignore**
- Encryption of sensitive fields with strong algorithms, and encrypted backups.

**How to Test with Burp Suite**
1. If you have access to the database (via SQLi or other), inspect tables for sensitive data.
2. Check for backup files exposed (e.g., `.sql`, `.bak`).

**Example**
Database table `users` has a column `cc_number` storing plaintext credit card numbers.

**Tools**
- SQLMap
- Directory brute‑forcing for backup files

**Risk Rating**  
Critical

**Remediation**
- Encrypt sensitive data at rest using strong encryption (AES-256).
- Use database encryption or application‑level encryption.
- Encrypt backups and store them securely.

---

## 25. INSECURE THIRD-PARTY COMPONENT INTEGRATION

**Description**  
Design that integrates third‑party libraries, APIs, or services without proper security review exposes the application to vulnerabilities in those components.

**What to Look For**
- Outdated libraries with known vulnerabilities.
- Trusting third‑party inputs without validation.
- Insecure handling of third‑party callbacks (e.g., OAuth redirects).

**What to Ignore**
- Regularly updated components, with input validation and secure integration patterns.

**How to Test with Burp Suite**
1. Identify third‑party libraries via version headers, JavaScript files, or framework indicators.
2. Check known vulnerability databases (CVE, NVD) for those versions.
3. Test for issues like OAuth redirect_uri manipulation, insecure deserialization in libraries.

**Example**
- Application uses an old version of jQuery (1.x) with known XSS vulnerabilities.

**Tools**
- Wappalyzer
- OWASP Dependency-Check
- Burp Scanner

**Risk Rating**  
High

**Remediation**
- Maintain an inventory of third‑party components.
- Regularly update libraries.
- Review security of third‑party APIs before integration.

---

## 26. LACK OF SECURE DEFAULTS FOR NEW USERS

**Description**  
Design that creates new user accounts with weak defaults (e.g., guessable passwords, full permissions) increases risk.

**What to Look For**
- New users receive weak or no password.
- Default role is admin or highly privileged.
- No requirement to change initial password.

**What to Ignore**
- Strong randomly generated initial passwords forced to change on first login, and minimal default privileges.

**How to Test with Burp Suite**
1. Register a new account.
2. Check the assigned role (e.g., via profile API).
3. Attempt to use default password after registration.

**Example**
Registration completes with password `123456` and role `admin`.

**Tools**
- Burp Proxy
- Manual inspection

**Risk Rating**  
High

**Remediation**
- Generate strong random passwords or require user‑set passwords.
- Assign minimal privileges by default.
- Force password change on first login.

---

## 27. MISSING SECURITY REQUIREMENTS IN DESIGN PHASE

**Description**  
When security requirements are not defined early, the application is built without considering security controls.

**What to Look For**
- No evidence of threat modeling.
- Requirements documents lack security sections.
- Features implemented without considering security (e.g., no logging, no input validation).

**What to Ignore**
- Security requirements included in user stories, threat modeling performed, and security controls designed.

**How to Test with Burp Suite**
- This is a process review. However, you can infer missing requirements by the prevalence of vulnerabilities that would have been prevented by standard security controls.

**Example**
- Application lacks input validation, authentication controls, and logging – all signs of missing security requirements.

**Tools**
- Interviews with developers
- Document review

**Risk Rating**  
High

**Remediation**
- Include security requirements in the SDLC.
- Perform threat modeling at design stage.
- Use security checklists.

---

## 28. INADEQUATE BUSINESS LOGIC VALIDATION

**Description**  
Design that does not validate business logic (e.g., price changes, coupon abuse, stock limits) allows attackers to manipulate the application's intended behavior.

**What to Look For**
- Price or quantity parameters that can be changed client‑side.
- Coupons that can be applied multiple times.
- Missing validation of workflow steps (e.g., order after payment).

**What to Ignore**
- Business logic validated server‑side with checks against inventory, pricing, and state.

**How to Test with Burp Suite**
1. Identify business operations (purchase, transfer, voting).
2. Attempt to manipulate parameters (e.g., negative quantity, multiple coupons).
3. Check if the server accepts the manipulated request.

**Example**
```http
POST /cart/checkout
{"items":[{"id":1,"price":0.01}]}
```
If checkout processes with the modified price, business logic is flawed.

**Tools**
- Burp Repeater
- Manual business logic testing

**Risk Rating**  
High to Critical

**Remediation**
- Validate all business operations server‑side.
- Use server‑side state to enforce limits and rules.
- Never trust client‑side calculations.

---

## 29. LACK OF SECURE SESSION MANAGEMENT DESIGN

**Description**  
Design that uses predictable session identifiers, stores them insecurely, or does not rotate them after login leads to session hijacking.

**What to Look For**
- Session IDs in URLs or exposed in client‑side storage.
- No session rotation after authentication.
- Weak session ID generation.

**What to Ignore**
- Secure session cookies with `HttpOnly`, `Secure`, and regeneration on login.

**How to Test with Burp Suite**
1. Observe session cookies for flags (HttpOnly, Secure, SameSite).
2. Test if session ID changes after login.
3. Check if session ID is predictable (Burp Sequencer).

**Example**
```http
Set-Cookie: JSESSIONID=123456; Path=/
```
No HttpOnly, no Secure, and sequential ID.

**Tools**
- Burp Sequencer
- Burp Proxy

**Risk Rating**  
High

**Remediation**
- Generate cryptographically random session IDs.
- Set `HttpOnly`, `Secure`, `SameSite` flags.
- Regenerate session ID after login and privilege changes.

---

## 30. ABSENCE OF SECURITY ARCHITECTURE REVIEW

**Description**  
Not performing architecture reviews allows design flaws to persist undetected, leading to systemic vulnerabilities.

**What to Look For**
- No documented security architecture.
- Lack of threat modeling or design review meetings.
- Frequent security issues that are architectural in nature (e.g., trust boundaries crossed incorrectly).

**What to Ignore**
- Formal security architecture reviews conducted before implementation.

**How to Test with Burp Suite**
- This is a process review. Indicators include the presence of vulnerabilities that are architectural (e.g., IDOR everywhere, no authentication on APIs, all users have admin access).

**Example**
- Application uses the same API for both user and admin functions, relying on UI hiding.

**Tools**
- Interviews
- Documentation review

**Risk Rating**  
High

**Remediation**
- Include security architects in the design phase.
- Conduct threat modeling and architecture reviews.
- Document security controls and data flows.

---

## ✅ **SUMMARY**

Insecure design is about flaws in the application's architecture and business logic that cannot be fixed by simple code patches. These vulnerabilities require a redesign to address. This guide covers 30 design‑level flaws that should be identified during threat modeling, architecture review, and penetration testing.

### **Key Testing Areas Summary**

| Design Flaw | Key Indicators | Risk |
|-------------|----------------|------|
| Input Validation | No server‑side validation, injection possible | Critical |
| Workflow Authorization | Step skipping, direct access to final actions | High |
| Client‑Side Trust | Only JS validation | High |
| Default Configs | Default passwords, debug mode | High |
| Rate Limiting | No throttling | High |
| Security Headers | Missing CSP, HSTS, etc. | Medium-High |
| Logging | No logs of critical events | High |
| Error Handling | Stack traces exposed | Medium-High |
| CORS | Wildcard with credentials | High |
| IDOR | Predictable IDs, no ownership checks | Critical |
| Mass Assignment | Extra parameters accepted | Critical |
| Defense in Depth | Single security control | High |
| Crypto Storage | Weak hashing, plaintext | Critical |
| Session Expiry | No timeouts | Medium-High |
| Password Recovery | Predictable tokens | High |
| Account Lockout | No lockout | High |
| Input Sanitization | Direct use in queries/commands | Critical |
| SDLC Security | No testing phases | High |
| API Security | No auth, excessive data | Critical |
| File Upload | RCE via upload | Critical |
| Deserialization | Untrusted data deserialized | Critical |
| CSRF | No tokens | High |
| RBAC | No role enforcement | Critical |
| Data at Rest | Unencrypted sensitive data | Critical |
| Third‑Party Components | Outdated, insecure integration | High |
| Secure Defaults | Weak initial passwords | High |
| Security Requirements | None in design | High |
| Business Logic | Price/coupon manipulation | High-Critical |
| Session Management | Weak tokens, no flags | High |
| Architecture Review | No threat modeling | High |

### **Pro Tips for Testing Insecure Design**
1. **Think like an architect** – understand how components interact and where trust boundaries are.
2. **Map workflows** – document all business processes and test each step for authorization and logic flaws.
3. **Review requirements** – if possible, examine design documents for missing security controls.
4. **Combine techniques** – many design flaws are revealed by combining functional testing with security testing.
5. **Use threat modeling** – create threat models to identify where design decisions create risk.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
