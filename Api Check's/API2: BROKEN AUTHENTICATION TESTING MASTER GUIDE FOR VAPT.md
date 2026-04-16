# 🔑 **API2: BROKEN AUTHENTICATION TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Authentication Flaws in APIs*

---

## 📋 **TABLE OF CONTENTS**

1. [Missing Authentication on API Endpoints](#1-missing-authentication-on-api-endpoints)
2. [Weak API Key Generation (Predictable or Short Keys)](#2-weak-api-key-generation-predictable-or-short-keys)
3. [API Keys Exposed in URLs or Client‑Side Code](#3-api-keys-exposed-in-urls-or-client-side-code)
4. [JWT Weaknesses (None Algorithm, Weak Secret, Missing Expiry)](#4-jwt-weaknesses-none-algorithm-weak-secret-missing-expiry)
5. [JWT Algorithm Confusion (RS256 to HS256)](#5-jwt-algorithm-confusion-rs256-to-hs256)
6. [Missing or Weak Rate Limiting on Authentication Endpoints](#6-missing-or-weak-rate-limiting-on-authentication-endpoints)
7. [No Account Lockout or Progressive Delays](#7-no-account-lockout-or-progressive-delays)
8. [Username/Email Enumeration via API Responses](#8-usernameemail-enumeration-via-api-responses)
9. [Weak Password Policy Enforced Only Client‑Side](#9-weak-password-policy-enforced-only-client-side)
10. [Credentials Transmitted in Plaintext (HTTP not HTTPS)](#10-credentials-transmitted-in-plaintext-http-not-https)
11. [API Authentication via Session Cookies Missing Flags (HttpOnly, Secure)](#11-api-authentication-via-session-cookies-missing-flags-httponly-secure)
12. [Missing Multi‑Factor Authentication (MFA) for Privileged APIs](#12-missing-multi-factor-authentication-mfa-for-privileged-apis)
13. [MFA Bypass via Parameter Tampering or Step Skipping](#13-mfa-bypass-via-parameter-tampering-or-step-skipping)
14. [Weak Password Reset Tokens (Predictable, Short, No Expiry)](#14-weak-password-reset-tokens-predictable-short-no-expiry)
15. [Password Reset Token Leakage in API Responses](#15-password-reset-token-leakage-in-api-responses)
16. [Host Header Injection in Password Reset Flow](#16-host-header-injection-in-password-reset-flow)
17. [Insecure OAuth 2.0 / OpenID Connect Implementation](#17-insecure-oauth-20--openid-connect-implementation)
18. [Missing `state` Parameter in OAuth Flows (CSRF)](#18-missing-state-parameter-in-oauth-flows-csrf)
19. [OAuth `redirect_uri` Validation Bypass](#19-oauth-redirect_uri-validation-bypass)
20. [SAML Authentication Flaws (Signature Stripping, XML Wrapping)](#20-saml-authentication-flaws-signature-stripping-xml-wrapping)
21. [Basic Authentication Over HTTPS (Still Vulnerable to Credential Stuffing)](#21-basic-authentication-over-https-still-vulnerable-to-credential-stuffing)
22. [API Token Not Invalidated on Logout or Password Change](#22-api-token-not-invalidated-on-logout-or-password-change)
23. [Long‑Lived Tokens Without Refresh Mechanism](#23-long-lived-tokens-without-refresh-mechanism)
24. [Authentication Bypass via SQL Injection in Login API](#24-authentication-bypass-via-sql-injection-in-login-api)
25. [Authentication Bypass via NoSQL Injection in Login API](#25-authentication-bypass-via-nosql-injection-in-login-api)
26. [Authentication Bypass via Parameter Manipulation (e.g., `admin=true`)](#26-authentication-bypass-via-parameter-manipulation)
27. [Weak API Token Storage (Client‑Side localStorage, SessionStorage)](#27-weak-api-token-storage-client-side-localstorage-sessionstorage)
28. [Bearer Token in URL (Logging/Referer Leakage)](#28-bearer-token-in-url-loggingreferer-leakage)
29. [Missing Proper Authentication for Internal APIs or Microservices](#29-missing-proper-authentication-for-internal-apis-or-microservices)
30. [GraphQL Authentication Bypass via Introspection or Field Guessing](#30-graphql-authentication-bypass-via-introspection-or-field-guessing)

---

## 1. MISSING AUTHENTICATION ON API ENDPOINTS

**Description**  
API endpoints that perform sensitive operations (data retrieval, modification, deletion) without requiring authentication allow anyone to access or modify data.

**What to Look For**
- API endpoints accessible without any token, API key, or session cookie.
- Publicly documented endpoints that should be protected (e.g., `/api/admin/users`).
- No authentication headers required in requests.

**What to Ignore**
- Public endpoints that are intentionally open (e.g., login, registration, public data).

**How to Test with Burp Suite**
1. Identify all API endpoints (via spidering, JS analysis, Swagger docs).
2. Send a request to each endpoint without any authentication header or cookie.
3. If the endpoint returns sensitive data or performs an action, authentication is missing.

**Example**
```http
GET /api/users HTTP/1.1
Host: api.target.com
```
If the response returns a list of users, the endpoint is unprotected.

**Tools**
- Burp Proxy
- Burp Repeater
- API discovery tools (Postman, Swagger)

**Risk Rating**  
Critical

**Remediation**
- Enforce authentication on all sensitive API endpoints.
- Use token‑based authentication (JWT, OAuth, API keys) with proper validation.

---

## 2. WEAK API KEY GENERATION (PREDICTABLE OR SHORT KEYS)

**Description**  
API keys that are short, sequential, or based on predictable data (e.g., timestamps, user IDs) can be guessed or brute‑forced.

**What to Look For**
- API keys that are numeric or short alphanumeric strings (e.g., `123456`, `abc123`).
- Keys that are generated sequentially (e.g., `key1001`, `key1002`).
- Keys that contain user IDs or timestamps.

**What to Ignore**
- Cryptographically random API keys with sufficient length (≥32 characters).

**How to Test with Burp Suite**
1. Obtain a valid API key (e.g., from registration).
2. Analyze its pattern: length, character set, randomness.
3. Attempt to brute‑force other keys using Burp Intruder.
4. Use Burp Sequencer to evaluate randomness.

**Example**
```
API-Key: 1001
```
Next key may be `1002`.

**Tools**
- Burp Sequencer
- Burp Intruder
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Generate API keys using cryptographically secure random generators.
- Use at least 128 bits of entropy (e.g., 32 random hex characters).

---

## 3. API KEYS EXPOSED IN URLS OR CLIENT‑SIDE CODE

**Description**  
API keys exposed in URLs can be logged by servers, proxies, and browsers, or leaked via the `Referer` header. Keys in client‑side code (JavaScript) are publicly visible.

**What to Look For**
- API keys in query parameters: `?api_key=123456`.
- API keys in JavaScript files, HTML comments, or source maps.
- Keys in mobile app decompiled code.

**What to Ignore**
- Keys transmitted only in request headers (e.g., `Authorization: Bearer`).
- Keys stored securely on the server.

**How to Test with Burp Suite**
1. Intercept API requests and examine the URL for `api_key`, `key`, `token` parameters.
2. View page source and JavaScript files for hardcoded keys.
3. Use Burp’s search feature to look for common key patterns.

**Example**
```html
<script>
  const API_KEY = "sk_live_abc123";
</script>
```

**Tools**
- Burp Proxy
- Browser DevTools
- JS beautifier

**Risk Rating**  
Critical

**Remediation**
- Never expose API keys in URLs or client‑side code.
- Use server‑side proxies to forward requests with keys.

---

## 4. JWT WEAKNESSES (NONE ALGORITHM, WEAK SECRET, MISSING EXPIRY)

**Description**  
JSON Web Tokens (JWTs) are widely used for API authentication. Weaknesses include accepting the `none` algorithm, using weak HMAC secrets, or missing `exp` (expiration) claims.

**What to Look For**
- JWT header with `"alg": "none"` accepted.
- Weak secret (e.g., `secret`, `password`).
- No `exp` claim in the payload.

**What to Ignore**
- JWTs with strong algorithms (RS256, ES256) and proper expiration.

**How to Test with Burp Suite**
1. Capture a JWT from an API request.
2. Use Burp’s JWT Editor extension or jwt.io to decode.
3. Change the algorithm to `none` and remove the signature.
4. Send the modified token; if accepted, vulnerable.
5. For weak secret, use `jwt_tool` to brute force.

**Example**
```json
{
  "alg": "none",
  "typ": "JWT"
}
{
  "user": "admin",
  "exp": 9999999999
}
```

**Tools**
- Burp JWT Editor
- jwt_tool
- jwt.io

**Risk Rating**  
Critical

**Remediation**
- Reject `none` algorithm.
- Use strong secrets (≥256 bits) or asymmetric keys.
- Always include an `exp` claim with a short lifetime.

---

## 5. JWT ALGORITHM CONFUSION (RS256 TO HS256)

**Description**  
If the server supports both RS256 (asymmetric) and HS256 (symmetric) and the public key is known, attackers can forge tokens by using the public key as an HMAC secret.

**What to Look For**
- JWKS endpoint exposed (e.g., `/.well-known/jwks.json`).
- Server accepts both RS256 and HS256 tokens.

**What to Ignore**
- Single algorithm enforcement.

**How to Test with Burp Suite**
1. Obtain the public key from `/.well-known/jwks.json` or from the token header.
2. Use `jwt_tool` to convert an RS256 token to HS256 using the public key:  
   `python jwt_tool.py <token> -X a -p public.pem`
3. Send the modified token; if accepted, vulnerable.

**Example**
```bash
jwt_tool.py "eyJ..." -X a -p public.pem
```

**Tools**
- jwt_tool
- Burp JWT Editor

**Risk Rating**  
Critical

**Remediation**
- Enforce a single algorithm per application.
- Validate the algorithm in the token header.

---

## 6. MISSING OR WEAK RATE LIMITING ON AUTHENTICATION ENDPOINTS

**Description**  
Authentication endpoints (login, token refresh, password reset) without rate limiting allow brute force and credential stuffing attacks.

**What to Look For**
- No `X-RateLimit-*` headers in responses.
- Ability to send many requests without receiving a 429 (Too Many Requests).
- No CAPTCHA after multiple failures.

**What to Ignore**
- Rate limiting implemented (e.g., 5 attempts per minute).

**How to Test with Burp Suite**
1. Use Intruder to send 100 login requests with incorrect passwords.
2. If all requests return the same response (e.g., 401 Unauthorized) without delay or lockout, rate limiting is missing.

**Example**
```http
POST /api/login
{"username":"admin","password":"guess"}
```
Repeated 100 times.

**Tools**
- Burp Intruder / Turbo Intruder

**Risk Rating**  
High

**Remediation**
- Implement rate limiting (by IP, by user) on authentication endpoints.
- Use CAPTCHA after a threshold of failures.

---

## 7. NO ACCOUNT LOCKOUT OR PROGRESSIVE DELAYS

**Description**  
Without account lockout or progressive delays, attackers can brute force passwords indefinitely.

**What to Look For**
- No change in response time or error message after many failed attempts.
- No temporary lockout (e.g., 5 failures lock for 15 minutes).

**What to Ignore**
- Lockout or progressive delays (e.g., 1s, 5s, 30s after each failure).

**How to Test with Burp Suite**
1. Send 20 failed login attempts for the same user.
2. If the 20th attempt is processed without delay or lockout, vulnerable.

**Example**
- No lockout after 50 failed attempts.

**Tools**
- Burp Intruder
- Turbo Intruder (timing measurement)

**Risk Rating**  
High

**Remediation**
- Implement account lockout after a reasonable number of failures (e.g., 5).
- Use progressive delays (increase wait time after each failure).

---

## 8. USERNAME/EMAIL ENUMERATION VIA API RESPONSES

**Description**  
API responses that differ for valid vs invalid usernames allow attackers to enumerate valid accounts.

**What to Look For**
- Different error messages: `"User not found"` vs `"Invalid password"`.
- Different HTTP status codes (e.g., 404 vs 401).
- Different response times.

**What to Ignore**
- Generic error message: `"Invalid username or password"`.

**How to Test with Burp Suite**
1. Send a login request with a known valid username and an invalid password.
2. Send a request with an invalid username.
3. Compare responses. If they differ, enumeration is possible.

**Example**
```json
{"username":"valid@example.com","password":"wrong"}
Response: {"error": "Invalid password"}

{"username":"invalid@example.com","password":"wrong"}
Response: {"error": "User not found"}
```

**Tools**
- Burp Intruder (grep match)
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Use generic error messages for all authentication failures.
- Normalize response times.

---

## 9. WEAK PASSWORD POLICY ENFORCED ONLY CLIENT‑SIDE

**Description**  
Password complexity rules enforced only in the browser can be bypassed by directly calling the API.

**What to Look For**
- JavaScript validation for password strength but no server‑side check.
- Ability to set a weak password (e.g., `123`) via direct API call.

**What to Ignore**
- Server‑side password policy enforcement.

**How to Test with Burp Suite**
1. Intercept a registration or password change request.
2. Modify the password to a weak value (e.g., `"password": "123"`).
3. Send the request. If accepted, the policy is not enforced server‑side.

**Example**
```http
POST /api/register
{"username":"test","password":"123"}
```
If successful, weak policy.

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Enforce password policy on the server side.
- Validate password strength before storing.

---

## 10. CREDENTIALS TRANSMITTED IN PLAINTEXT (HTTP NOT HTTPS)

**Description**  
Sending credentials over HTTP allows attackers on the same network to intercept them.

**What to Look For**
- API endpoints accessible over HTTP (not redirected to HTTPS).
- Credentials in plaintext in requests.

**What to Ignore**
- Strict HTTPS with HSTS.

**How to Test with Burp Suite**
1. Change the protocol from HTTPS to HTTP and resend the login request.
2. If the server accepts the request, credentials are transmitted in plaintext.
3. Use Wireshark to confirm.

**Example**
```http
POST http://api.target.com/login
{"username":"admin","password":"secret"}
```

**Tools**
- Burp Repeater
- Wireshark

**Risk Rating**  
Critical

**Remediation**
- Enforce HTTPS site‑wide.
- Redirect all HTTP traffic to HTTPS.
- Implement HSTS.

---

## 11. API AUTHENTICATION VIA SESSION COOKIES MISSING FLAGS (HTTPONLY, SECURE)

**Description**  
Session cookies used for API authentication without `HttpOnly` are accessible to JavaScript (XSS risk). Without `Secure`, they may be sent over HTTP.

**What to Look For**
- `Set-Cookie` header missing `HttpOnly`, `Secure`, or `SameSite`.
- Cookies with `Domain` too broad.

**What to Ignore**
- Cookies with all flags properly set.

**How to Test with Burp Suite**
1. Intercept the response that sets the session cookie.
2. Check for `HttpOnly`, `Secure`, `SameSite`.
3. In browser console, try `document.cookie` to see if cookie appears.

**Example**
```http
Set-Cookie: session=abc123; Path=/
```
Missing `HttpOnly`, `Secure`.

**Tools**
- Burp Proxy
- Browser DevTools

**Risk Rating**  
High

**Remediation**
- Set `HttpOnly` to prevent JavaScript access.
- Set `Secure` to enforce HTTPS.
- Set `SameSite=Lax` or `Strict`.

---

## 12. MISSING MULTI‑FACTOR AUTHENTICATION (MFA) FOR PRIVILEGED APIS

**Description**  
APIs that perform privileged operations (admin functions, financial transactions) should require MFA. Missing MFA increases the risk of account takeover.

**What to Look For**
- Admin API endpoints that accept only a password or token.
- No MFA challenge for sensitive operations.

**What to Ignore**
- MFA enforced for all privileged APIs.

**How to Test with Burp Suite**
1. Log in with a privileged account.
2. Call a sensitive API endpoint (e.g., `/api/admin/deleteUser`).
3. If no MFA is required, vulnerable.

**Example**
```http
POST /api/admin/deleteUser HTTP/1.1
Authorization: Bearer PRIVILEGED_TOKEN
{"user_id":123}
```
No MFA step.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Enforce MFA for all privileged API operations.
- Use step‑up authentication.

---

## 13. MFA BYPASS VIA PARAMETER TAMPERING OR STEP SKIPPING

**Description**  
MFA implementations may allow bypass by skipping the verification step or by tampering with parameters.

**What to Look For**
- Ability to access authenticated API endpoints without providing MFA code.
- Parameters like `mfa_required=false`, `2fa_passed=true`.

**What to Ignore**
- MFA enforced server‑side with session flags.

**How to Test with Burp Suite**
1. Complete the first factor (login) but not MFA.
2. Try to call an authenticated API endpoint directly.
3. If the API returns data, MFA is bypassed.
4. Also try adding parameters like `&mfa_bypass=1`.

**Example**
```http
GET /api/dashboard HTTP/1.1
Cookie: session=AFTER_LOGIN_BUT_BEFORE_MFA
```
If dashboard loads, MFA step is missing.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Set a session flag indicating MFA completion.
- Validate that flag on every sensitive API call.

---

## 14. WEAK PASSWORD RESET TOKENS (PREDICTABLE, SHORT, NO EXPIRY)

**Description**  
Password reset tokens that are predictable (sequential, timestamp‑based) or short (4‑6 digits) allow attackers to guess tokens and take over accounts.

**What to Look For**
- Tokens in API responses (e.g., `{"reset_token":"1001"}`).
- Numeric tokens without rate limiting.
- No expiration time.

**What to Ignore**
- Cryptographically random tokens (≥128 bits) with short expiry.

**How to Test with Burp Suite**
1. Request a password reset for your account.
2. Capture the token (if visible) or the reset link.
3. Analyze token pattern (Burp Sequencer).
4. Attempt to brute force tokens for another user (if numeric, use Intruder).

**Example**
```http
POST /api/reset-password
{"email":"victim@example.com"}
Response: {"token": "123456"}
```
Token is sequential.

**Tools**
- Burp Sequencer
- Burp Intruder

**Risk Rating**  
High

**Remediation**
- Generate cryptographically random tokens.
- Set token expiry (e.g., 15 minutes).
- Rate limit token attempts.

---

## 15. PASSWORD RESET TOKEN LEAKAGE IN API RESPONSES

**Description**  
APIs that return the reset token in the response body expose it to anyone who can intercept the response (e.g., via MITM or logs).

**What to Look For**
- Token in JSON or XML response after requesting password reset.

**What to Ignore**
- Token sent only via email, not in API response.

**How to Test with Burp Suite**
1. Request a password reset.
2. Intercept the response and look for a token.
3. If found, token is leaked.

**Example**
```http
POST /api/reset-password
{"email":"user@example.com"}

Response: {"reset_token": "abc123", "message": "Check email"}
```

**Tools**
- Burp Proxy

**Risk Rating**  
High

**Remediation**
- Never return reset tokens in API responses.
- Send tokens only via secure out‑of‑band channels (email, SMS).

---

## 16. HOST HEADER INJECTION IN PASSWORD RESET FLOW

**Description**  
If the API uses the `Host` header to construct password reset links, attackers can manipulate it to send the reset link to their own domain.

**What to Look For**
- Reset links in emails that use the `Host` header value.
- No validation of `Host` header.

**What to Ignore**
- Absolute URLs based on server configuration, not `Host` header.

**How to Test with Burp Suite**
1. Intercept a password reset request.
2. Change the `Host` header to `evil.com`.
3. Forward the request.
4. Check if the reset email (if you control the victim’s email) contains a link to `evil.com`.

**Example**
```http
POST /api/reset-password
Host: evil.com
{"email":"victim@example.com"}
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Do not use the `Host` header to construct URLs.
- Validate `Host` against a whitelist.

---

## 17. INSECURE OAUTH 2.0 / OPENID CONNECT IMPLEMENTATION

**Description**  
Flaws in OAuth 2.0 implementation can lead to authorization code interception and account takeover.

**What to Look For**
- OAuth endpoints with missing or weak PKCE for public clients.
- Authorization code leakage in URLs or logs.
- Missing state parameter (see next).

**What to Ignore**
- Proper OAuth with PKCE, state parameter, and redirect_uri validation.

**How to Test with Burp Suite**
1. Intercept the OAuth authorization request.
2. Look for `response_type=code` and `redirect_uri`.
3. Test for missing `code_challenge` (PKCE) for public clients.
4. Try to reuse an authorization code.

**Example**
```http
GET /oauth/authorize?client_id=123&redirect_uri=https://client.com/callback&response_type=code
```

**Tools**
- Burp Repeater
- OAuth testing tools

**Risk Rating**  
Critical

**Remediation**
- Use PKCE for public clients.
- Validate `redirect_uri` against a whitelist.
- Use short‑lived authorization codes.

---

## 18. MISSING `STATE` PARAMETER IN OAUTH FLOWS (CSRF)

**Description**  
The OAuth 2.0 `state` parameter prevents CSRF attacks on the callback endpoint. Without it, an attacker can bind an authorization code to a victim’s session.

**What to Look For**
- OAuth authorization request missing the `state` parameter.
- Callback endpoint does not validate `state`.

**What to Ignore**
- `state` parameter present and validated.

**How to Test with Burp Suite**
1. Initiate an OAuth flow and capture the request.
2. Remove the `state` parameter (if present) or modify it.
3. Complete the flow; if the callback accepts the code, vulnerable.

**Example**
```http
GET /oauth/authorize?client_id=123&redirect_uri=https://client.com/callback&response_type=code
```
No `state` parameter.

**Tools**
- Burp Repeater
- Custom OAuth client

**Risk Rating**  
High

**Remediation**
- Always include a random `state` parameter.
- Validate `state` on the callback endpoint.

---

## 19. OAUTH `REDIRECT_URI` VALIDATION BYPASS

**Description**  
If the OAuth provider does not strictly validate the `redirect_uri`, attackers can change it to their own domain and intercept the authorization code.

**What to Look For**
- `redirect_uri` parameter that can be set to any domain.
- Open redirects on the client’s callback endpoint.

**What to Ignore**
- Whitelisted redirect URIs.

**How to Test with Burp Suite**
1. Intercept the OAuth authorization request.
2. Change `redirect_uri` to `https://evil.com/callback`.
3. If the provider redirects the code to `evil.com`, vulnerable.

**Example**
```http
GET /oauth/authorize?client_id=123&redirect_uri=https://evil.com/callback&response_type=code
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Validate `redirect_uri` against a strict whitelist.
- Use exact matching, not prefix.

---

## 20. SAML AUTHENTICATION FLAWS (SIGNATURE STRIPPING, XML WRAPPING)

**Description**  
SAML‑based API authentication can be compromised by removing signatures or wrapping assertions, allowing attackers to forge authentication assertions.

**What to Look For**
- SAML responses accepted without signature.
- XML parser vulnerable to wrapping attacks.

**What to Ignore**
- Strict signature validation and secure parsing.

**How to Test with Burp Suite**
1. Use SAML Raider extension.
2. Capture a SAML response.
3. Remove the `<ds:Signature>` element.
4. Forward; if accepted, signature stripping works.

**Example**
```xml
<saml:Assertion>
  <!-- signature removed -->
  <saml:Subject>admin</saml:Subject>
</saml:Assertion>
```

**Tools**
- Burp SAML Raider
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Validate signatures strictly.
- Use secure XML parsers.
- Disable external entity processing.

---

## 21. BASIC AUTHENTICATION OVER HTTPS (STILL VULNERABLE TO CREDENTIAL STUFFING)

**Description**  
Basic Authentication (Base64‑encoded username:password) is still vulnerable to credential stuffing and brute force, even over HTTPS.

**What to Look For**
- `Authorization: Basic <base64>` header.
- No rate limiting or lockout.

**What to Ignore**
- Strong rate limiting and MFA.

**How to Test with Burp Suite**
1. Capture a request with Basic Auth.
2. Decode the Base64 string to retrieve credentials.
3. Use Intruder to brute force other credentials.

**Example**
```http
GET /api/data HTTP/1.1
Authorization: Basic YWRtaW46c2VjcmV0
```
Decodes to `admin:secret`.

**Tools**
- Burp Intruder
- Base64 decoder

**Risk Rating**  
Medium

**Remediation**
- Use token‑based authentication instead of Basic Auth.
- Implement rate limiting and MFA.

---

## 22. API TOKEN NOT INVALIDATED ON LOGOUT OR PASSWORD CHANGE

**Description**  
API tokens that remain valid after logout or password change allow attackers with a stolen token to maintain access.

**What to Look For**
- Token works after logout.
- Token works after password change.

**What to Ignore**
- Tokens invalidated server‑side.

**How to Test with Burp Suite**
1. Log in and capture a valid token.
2. Log out (or change password).
3. Replay the token in a request to an authenticated endpoint.
4. If the request succeeds, token not invalidated.

**Example**
```http
GET /api/profile HTTP/1.1
Authorization: Bearer OLD_TOKEN_AFTER_LOGOUT
```
If profile returned, vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Invalidate tokens on logout and password change.
- Maintain a token blacklist or use short‑lived tokens.

---

## 23. LONG‑LIVED TOKENS WITHOUT REFRESH MECHANISM

**Description**  
Tokens that never expire or have extremely long lifetimes (e.g., years) increase the impact of token theft.

**What to Look For**
- JWT missing `exp` claim or with far‑future expiry.
- API keys that never rotate.

**What to Ignore**
- Short‑lived tokens (e.g., 15 minutes) with refresh tokens.

**How to Test with Burp Suite**
1. Obtain a token.
2. Wait for the expected expiration period (if documented).
3. Replay the token after that period.

**Example**
```json
{
  "user": "admin",
  "exp": 9999999999
}
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Use short‑lived access tokens (e.g., 15 minutes).
- Implement refresh token rotation.

---

## 24. AUTHENTICATION BYPASS VIA SQL INJECTION IN LOGIN API

**Description**  
SQL injection in the login API can allow attackers to bypass authentication by modifying the SQL query logic.

**What to Look For**
- Login API that concatenates user input into SQL queries.
- Error messages revealing SQL syntax.

**What to Ignore**
- Parameterized queries.

**How to Test with Burp Suite**
1. In the username field, inject `' OR '1'='1' --`.
2. Use any password.
3. If login succeeds, authentication bypass is possible.

**Example**
```http
POST /api/login
{"username":"admin' OR '1'='1' --", "password":"anything"}
```

**Tools**
- Burp Repeater
- SQLMap

**Risk Rating**  
Critical

**Remediation**
- Use parameterized queries or ORM.
- Never concatenate user input into SQL queries.

---

## 25. AUTHENTICATION BYPASS VIA NOSQL INJECTION IN LOGIN API

**Description**  
NoSQL injection (e.g., MongoDB) can bypass authentication using operators like `$ne`, `$gt`.

**What to Look For**
- Login API that passes JSON input directly to a NoSQL query.
- Ability to inject operators.

**What to Ignore**
- Input validation and type checking.

**How to Test with Burp Suite**
1. Send a login request with:
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
```
2. If login succeeds, vulnerable.

**Example**
```http
POST /api/login
Content-Type: application/json

{"username": {"$ne": null}, "password": {"$ne": null}}
```

**Tools**
- Burp Repeater
- NoSQLMap

**Risk Rating**  
Critical

**Remediation**
- Validate input types and sanitize.
- Use parameterized NoSQL queries (e.g., with `?` placeholders).

---

## 26. AUTHENTICATION BYPASS VIA PARAMETER MANIPULATION (E.G., `ADMIN=TRUE`)

**Description**  
Some APIs trust client‑supplied parameters to determine authentication or privilege.

**What to Look For**
- Parameters like `isAdmin=true`, `role=admin`, `authenticated=1`.
- Hidden fields in API requests.

**What to Ignore**
- Server‑side role determination.

**How to Test with Burp Suite**
1. Intercept a login or profile request.
2. Add parameters: `&isAdmin=true`, `&role=administrator`.
3. If you gain admin access, vulnerable.

**Example**
```http
POST /api/login
{"username":"user","password":"pass","isAdmin":true}
```

**Tools**
- Burp Repeater
- Param Miner

**Risk Rating**  
Critical

**Remediation**
- Never trust client‑side parameters for authentication.
- Derive roles from server‑side session.

---

## 27. WEAK API TOKEN STORAGE (CLIENT‑SIDE LOCALSTORAGE, SESSIONSTORAGE)

**Description**  
Storing API tokens in `localStorage` or `sessionStorage` makes them accessible to any JavaScript running on the page, including XSS attacks.

**What to Look For**
- Tokens stored in `localStorage` or `sessionStorage` (visible in DevTools).
- No use of `HttpOnly` cookies.

**What to Ignore**
- Tokens stored in `HttpOnly` cookies.

**How to Test with Burp Suite**
1. Log in and open browser DevTools.
2. Go to Application > Storage > Local Storage.
3. If you see the API token, it is vulnerable to XSS theft.

**Example**
```javascript
localStorage.setItem('access_token', 'eyJhbGciOiJIUzI1NiIs...');
```

**Tools**
- Browser DevTools
- Burp (search for `localStorage` in JS)

**Risk Rating**  
High

**Remediation**
- Store API tokens in `HttpOnly` cookies.
- If tokens must be in client‑side, use memory‑only storage (not persistent).

---

## 28. BEARER TOKEN IN URL (LOGGING/REFERER LEAKAGE)

**Description**  
Placing bearer tokens in URLs exposes them to server logs, browser history, and the `Referer` header.

**What to Look For**
- Token in URL query parameter: `?token=...` or `?access_token=...`.
- No use of `Authorization` header.

**What to Ignore**
- Tokens only in `Authorization` headers.

**How to Test with Burp Suite**
1. Look for tokens in request URLs.
2. Check if the token appears in the `Referer` header when navigating to another site.

**Example**
```http
GET /api/data?access_token=abc123 HTTP/1.1
```

**Tools**
- Burp Proxy

**Risk Rating**  
High

**Remediation**
- Always transmit tokens in the `Authorization` header.
- Never put tokens in URLs.

---

## 29. MISSING PROPER AUTHENTICATION FOR INTERNAL APIS OR MICROSERVICES

**Description**  
Internal APIs (microservices) may rely on network perimeter for security and lack proper authentication, leading to compromise if an attacker gains internal access.

**What to Look For**
- No authentication headers required for internal API calls.
- Services that accept requests from any source.

**What to Ignore**
- Mutual TLS (mTLS) or service‑level authentication.

**How to Test with Burp Suite**
1. If you have access to an internal network (e.g., via SSRF), call internal APIs.
2. Check if they respond without authentication.

**Example**
```http
GET http://internal-api.company.com/users
```
If returns data, authentication missing.

**Tools**
- Burp Repeater (via SSRF or internal access)

**Risk Rating**  
Critical

**Remediation**
- Implement service‑to‑service authentication (mTLS, JWT, API keys).
- Use zero‑trust principles.

---

## 30. GRAPHQL AUTHENTICATION BYPASS VIA INTROSPECTION OR FIELD GUESSING

**Description**  
GraphQL APIs may expose authentication‑bypass vectors through introspection (revealing mutation names) or by guessing unauthenticated queries.

**What to Look For**
- Introspection enabled (`__schema` query) revealing mutations like `login`, `register`.
- Queries that can be executed without a token.

**What to Ignore**
- Introspection disabled in production.
- Authentication required for all queries.

**How to Test with Burp Suite**
1. Send an introspection query:
```graphql
query { __schema { mutationType { fields { name } } } }
```
2. Look for authentication‑related mutations.
3. Try to call them without a token.

**Example**
```graphql
mutation { login(username: "admin", password: "guess") { token } }
```

**Tools**
- GraphQL Raider
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Disable introspection in production.
- Enforce authentication on all GraphQL endpoints.

---

## ✅ **SUMMARY**

Broken Authentication in APIs is a critical vulnerability that allows attackers to compromise user accounts, impersonate others, and gain unauthorized access. This guide covers 30 distinct authentication flaws and testing techniques.

### **Key Testing Areas Summary**

| Failure Type | Key Indicators | Risk |
|--------------|----------------|------|
| Missing Authentication | No token required | Critical |
| Weak API Keys | Short, sequential | High |
| Keys in URL/Client | Exposed in JS | Critical |
| JWT None/Weak | `alg:none`, weak secret | Critical |
| JWT Algorithm Confusion | RS256→HS256 | Critical |
| Rate Limiting Missing | No 429 responses | High |
| No Account Lockout | Unlimited attempts | High |
| Username Enumeration | Different error messages | Medium |
| Weak Password Policy | Client‑side only | Medium |
| Plaintext Credentials | HTTP not HTTPS | Critical |
| Missing Cookie Flags | No HttpOnly/Secure | High |
| Missing MFA | No 2FA for privileged | Critical |
| MFA Bypass | Step skipping | Critical |
| Weak Reset Tokens | Predictable, short | High |
| Token Leakage | Token in response | High |
| Host Header Injection | Reset link hijacking | High |
| Insecure OAuth | Missing PKCE, state | Critical |
| Missing OAuth State | CSRF on callback | High |
| redirect_uri Bypass | Open redirect | Critical |
| SAML Flaws | Signature stripping | Critical |
| Basic Auth | Credential stuffing | Medium |
| Token Not Invalidated | Works after logout | High |
| Long‑Lived Tokens | No expiry | High |
| SQLi Auth Bypass | `' OR '1'='1` | Critical |
| NoSQL Auth Bypass | `$ne` operators | Critical |
| Parameter Manipulation | `admin=true` | Critical |
| LocalStorage Token | XSS theft | High |
| Token in URL | Logging leakage | High |
| Internal API Auth | No authentication | Critical |
| GraphQL Introspection | Unauthenticated mutations | High |

### **Pro Tips for Testing Broken Authentication in APIs**
1. **Enumerate all authentication endpoints** – login, token refresh, password reset, MFA, logout.
2. **Test with and without tokens** – missing token, invalid token, expired token.
3. **Use Burp Intruder for brute force** – but respect rate limits (use low threads).
4. **Check OAuth flows** – `redirect_uri`, `state`, PKCE.
5. **Test token invalidation** – after logout, password change, and token expiry.
6. **Inspect token storage** – `localStorage`, sessionStorage, cookies (flags).
7. **Automate with Autorize/AuthMatrix** – test different user roles.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
