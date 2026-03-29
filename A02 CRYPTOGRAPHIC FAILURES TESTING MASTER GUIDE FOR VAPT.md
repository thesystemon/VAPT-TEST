# 🔐 **A02 CRYPTOGRAPHIC FAILURES TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Cryptographic Failures*

---

## 📋 **TABLE OF CONTENTS**

1. [Weak Transport Layer Security (TLS/SSL)](#1-weak-transport-layer-security-tlsssl)
2. [Mixed Content (HTTPS Page Loading HTTP Resources)](#2-mixed-content-https-page-loading-http-resources)
3. [Missing HTTP Strict Transport Security (HSTS)](#3-missing-http-strict-transport-security-hsts)
4. [Weak Cipher Suites and Protocols](#4-weak-cipher-suites-and-protocols)
5. [SSL/TLS Certificate Issues (Self-Signed, Expired, Weak)](#5-ssltls-certificate-issues-self-signed-expired-weak)
6. [Hardcoded Secrets in Source Code and Configuration](#6-hardcoded-secrets-in-source-code-and-configuration)
7. [Insecure Password Storage (Plaintext, Weak Hashing)](#7-insecure-password-storage-plaintext-weak-hashing)
8. [Sensitive Data Exposure in URLs (GET Parameters)](#8-sensitive-data-exposure-in-urls-get-parameters)
9. [Sensitive Data in Logs, Error Messages, and Debug Output](#9-sensitive-data-in-logs-error-messages-and-debug-output)
10. [Weak Encryption Algorithms (MD5, SHA1, DES, RC4)](#10-weak-encryption-algorithms-md5-sha1-des-rc4)
11. [Insufficient Key Length (RSA 1024, Symmetric Keys)](#11-insufficient-key-length-rsa-1024-symmetric-keys)
12. [Use of ECB Mode (Electronic Codebook)](#12-use-of-ecb-mode-electronic-codebook)
13. [Padding Oracle Attacks (CBC Mode)](#13-padding-oracle-attacks-cbc-mode)
14. [TLS Compression Vulnerabilities (CRIME, BREACH)](#14-tls-compression-vulnerabilities-crime-breach)
15. [SSL/TLS Downgrade Attacks (POODLE, DROWN)](#15-ssltls-downgrade-attacks-poodle-drown)
16. [Missing Secure Flag on Cookies](#16-missing-secure-flag-on-cookies)
17. [Exposure of Sensitive Data via Referer Header](#17-exposure-of-sensitive-data-via-referer-header)
18. [Insecure Storage of Secrets in Environment Variables](#18-insecure-storage-of-secrets-in-environment-variables)
19. [Weak Random Number Generation (Predictable Tokens)](#19-weak-random-number-generation-predictable-tokens)
20. [Sensitive Data in Client-Side Storage (localStorage, sessionStorage)](#20-sensitive-data-in-client-side-storage-localstorage-sessionstorage)
21. [Insecure Data at Rest (Unencrypted Databases, Backups)](#21-insecure-data-at-rest-unencrypted-databases-backups)
22. [Hardcoded Encryption Keys in Source Code](#22-hardcoded-encryption-keys-in-source-code)
23. [Use of Deprecated Cryptographic APIs](#23-use-of-deprecated-cryptographic-apis)
24. [Insecure Handling of Secrets in CI/CD Pipelines](#24-insecure-handling-of-secrets-in-ci-cd-pipelines)
25. [Sensitive Data in HTTP Headers (Basic Auth, API Keys)](#25-sensitive-data-in-http-headers-basic-auth-api-keys)
26. [Insecure Storage of Sensitive Data in Mobile App Backups](#26-insecure-storage-of-sensitive-data-in-mobile-app-backups)
27. [Weak Encryption in Database Columns (Deterministic Encryption)](#27-weak-encryption-in-database-columns-deterministic-encryption)
28. [Lack of Encryption for Data in Transit (Internal Networks)](#28-lack-of-encryption-for-data-in-transit-internal-networks)
29. [Exposure of Sensitive Data in Error Messages (Stack Traces)](#29-exposure-of-sensitive-data-in-error-messages-stack-traces)
30. [Use of Custom or Weak Cryptographic Algorithms](#30-use-of-custom-or-weak-cryptographic-algorithms)

---

## 1. WEAK TRANSPORT LAYER SECURITY (TLS/SSL)

**Description**  
Transport Layer Security (TLS) protects data in transit between the client and server. Weak or outdated TLS versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1) or misconfigurations can allow attackers to intercept, decrypt, or modify sensitive data.

**What to Look For**
- Support for SSLv2, SSLv3, TLS 1.0, TLS 1.1
- Missing TLS 1.2 or TLS 1.3 support
- Vulnerable to known attacks like POODLE, BEAST, DROWN
- Weak cipher suites (RC4, DES, 3DES, export ciphers)

**What to Ignore**
- Proper TLS 1.2 or TLS 1.3 with strong ciphers and no deprecated versions

**How to Test with Burp Suite & Tools**

1. **Use Burp Scanner:**
   - Configure Burp as a proxy and run an active scan
   - Burp will detect weak SSL/TLS configurations

2. **Use SSL/TLS Scanner:**
   ```
   sslyze --regular target.com
   testssl.sh target.com
   nmap --script ssl-enum-ciphers -p 443 target.com
   ```

3. **Manual Test:**
   - Use openssl to check supported protocols:
   ```
   openssl s_client -connect target.com:443 -tls1_0
   openssl s_client -connect target.com:443 -tls1_1
   openssl s_client -connect target.com:443 -tls1_2
   openssl s_client -connect target.com:443 -tls1_3
   ```

**Example**
```bash
$ openssl s_client -connect target.com:443 -tls1_0
CONNECTED(00000003)
```
If connection succeeds, TLS 1.0 is supported (should be disabled).

**Tools**
- Burp Suite Scanner
- sslyze
- testssl.sh
- Nmap
- OpenSSL

**Risk Rating**  
High

**Remediation**
- Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1
- Enable TLS 1.2 and TLS 1.3 only
- Use strong cipher suites (e.g., ECDHE+AES-GCM)
- Configure HSTS to enforce secure connections

---

## 2. MIXED CONTENT (HTTPS PAGE LOADING HTTP RESOURCES)

**Description**  
When an HTTPS page loads resources (images, scripts, stylesheets) over HTTP, it breaks the security of the page. Attackers can intercept and modify these resources, potentially injecting malicious code.

**What to Look For**
- HTTPS pages containing `<img src="http://...">`, `<script src="http://...">`, etc.
- CSS or AJAX requests over HTTP
- Frames or iframes loaded over HTTP

**What to Ignore**
- Pages with all resources loaded over HTTPS

**How to Test with Burp Suite**

1. **Browse the site with Burp proxy enabled**
2. **In Proxy History, look for requests to HTTP resources from an HTTPS origin**
3. **Use Burp Scanner:**
   - Active scan can detect mixed content issues

4. **Browser DevTools:**
   - Open Console; mixed content warnings are displayed
   - Look for "Mixed Content" errors

**Example**
```html
<img src="http://example.com/image.jpg">
```
When page is served over HTTPS, the browser will warn and may block the resource.

**Tools**
- Burp Suite
- Browser DevTools (Console)
- Mixed Content Scanner extensions

**Risk Rating**  
Medium to High

**Remediation**
- Serve all resources over HTTPS (use relative URLs or `https://`)
- Implement Content Security Policy (CSP) to enforce HTTPS
- Use upgrade-insecure-requests CSP directive

---

## 3. MISSING HTTP STRICT TRANSPORT SECURITY (HSTS)

**Description**  
HSTS forces browsers to communicate with the site only over HTTPS, preventing SSL stripping attacks and cookie leakage over HTTP.

**What to Look For**
- No `Strict-Transport-Security` header in responses
- Short or improper `max-age` value
- No `includeSubDomains` directive when appropriate

**What to Ignore**
- Proper HSTS header with `max-age` >= 1 year and `includeSubDomains`

**How to Test with Burp Suite**

1. **Intercept a response from the site**
2. **Look for `Strict-Transport-Security` header**
   - Example of secure header:
   ```
   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
   ```
3. **If missing, the site is vulnerable to SSL stripping**

**Tools**
- Burp Repeater
- Browser DevTools (Network tab)
- Security Headers scanning tools (securityheaders.com)

**Risk Rating**  
Medium

**Remediation**
- Add HSTS header with `max-age` at least 1 year
- Include `includeSubDomains` if applicable
- Consider `preload` directive to be included in browser preload lists

---

## 4. WEAK CIPHER SUITES AND PROTOCOLS

**Description**  
Weak cipher suites (e.g., RC4, DES, 3DES, NULL, anonymous) allow attackers to decrypt or manipulate traffic.

**What to Look For**
- Support for RC4, DES, 3DES, EXPORT ciphers
- Anonymous ciphers (ADH, AECDH)
- Ciphers using CBC mode without secure handling (may be vulnerable to BEAST/Lucky13)
- Ciphers with weak key exchange (RSA without forward secrecy)

**What to Ignore**
- Strong ciphers: ECDHE+AES-GCM, ECDHE+CHACHA20, DHE+AES-GCM

**How to Test with Tools**

1. **Use testssl.sh:**
   ```
   testssl.sh --cipher-per-proto target.com
   ```

2. **Use nmap:**
   ```
   nmap --script ssl-enum-ciphers -p 443 target.com
   ```

3. **Burp Scanner:**
   - Active scan includes cipher strength checks

**Example**
```
SSLv3: ECDHE-RSA-RC4-SHA (weak)
TLSv1.2: ECDHE-RSA-AES256-GCM-SHA384 (strong)
```

**Tools**
- testssl.sh
- sslyze
- nmap
- Burp Suite

**Risk Rating**  
High

**Remediation**
- Disable all weak cipher suites
- Use only modern ciphers: TLS_AES_256_GCM_SHA384, ECDHE-RSA-AES256-GCM-SHA384, etc.
- Prioritize ciphers with forward secrecy

---

## 5. SSL/TLS CERTIFICATE ISSUES (SELF-SIGNED, EXPIRED, WEAK)

**Description**  
Invalid or weak certificates break trust and can allow man-in-the-middle attacks.

**What to Look For**
- Self-signed certificates
- Expired certificates
- Certificates with weak signature algorithms (MD5, SHA1)
- Mismatched hostnames
- Certificates with short key length (RSA < 2048 bits)
- Certificates issued by untrusted CAs

**What to Ignore**
- Valid, trusted certificates with strong signature and sufficient key length

**How to Test with Tools**

1. **Use openssl:**
   ```
   openssl s_client -connect target.com:443 -showcerts
   ```
2. **Check expiration, issuer, signature algorithm, key length**

3. **Use sslyze:**
   ```
   sslyze --certinfo target.com
   ```

4. **Burp Scanner** will flag certificate issues.

**Example**
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: ...
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C = US, O = FakeCA, CN = FakeCA
        Validity
            Not Before: Jan 1 00:00:00 2020 GMT
            Not After : Jan 1 00:00:00 2021 GMT (expired)
```

**Tools**
- openssl
- sslyze
- Burp Suite
- SSL Labs (online)

**Risk Rating**  
High

**Remediation**
- Obtain certificates from trusted CAs
- Ensure certificates are valid and not expired
- Use RSA 2048-bit minimum or ECDSA
- Use SHA-256 or better for signature

---

## 6. HARDCODED SECRETS IN SOURCE CODE AND CONFIGURATION

**Description**  
Hardcoding API keys, passwords, tokens, or encryption keys in source code, configuration files, or client-side code exposes them to attackers.

**What to Look For**
- API keys in JavaScript files, HTML comments
- Database passwords in configuration files (e.g., `.env`, `config.php`)
- Hardcoded credentials in source code repositories
- Client-side tokens stored in plaintext

**What to Ignore**
- Secrets stored securely in environment variables or secret management services

**How to Test with Burp Suite & Tools**

1. **Use Burp's passive scanner to look for common patterns in responses**
2. **Manual inspection of JavaScript files, source code**
3. **Use automated secret scanning tools:**
   ```
   trufflehog --regex --entropy=False https://github.com/user/repo.git
   git-secrets --scan
   ```

4. **Check `.git` directory exposure** (can leak entire repository)

**Example**
```javascript
// In main.js
const API_KEY = "AIzaSyD1234567890abcdefghijklmnopqrst";
```

**Tools**
- Burp Suite (manual inspection)
- TruffleHog
- GitLeaks
- Git-secrets
- Nmap for .git exposure

**Risk Rating**  
Critical

**Remediation**
- Remove secrets from source code
- Use environment variables or secret management (e.g., HashiCorp Vault, AWS Secrets Manager)
- Rotate leaked secrets immediately
- Implement pre-commit hooks to prevent committing secrets

---

## 7. INSECURE PASSWORD STORAGE (PLAINTEXT, WEAK HASHING)

**Description**  
Passwords stored in plaintext or with weak hashing algorithms (MD5, SHA1) allow attackers to easily recover them after a breach.

**What to Look For**
- Passwords transmitted in plaintext (HTTP, response bodies)
- Passwords stored with MD5, SHA1, SHA256 without salt
- No salt or weak salt (reused across users)
- Use of fast hashing algorithms (allow fast cracking)

**What to Ignore**
- Strong password hashing with bcrypt, Argon2, PBKDF2 with high iteration count and per-user salt

**How to Test with Burp Suite**

1. **Look for passwords in requests and responses**
2. **If you have access to database via SQL injection or other means, inspect hash format**
   - Example: `5f4dcc3b5aa765d61d8327deb882cf99` is MD5 of "password"
3. **Attempt to crack with hashcat or John the Ripper to verify weakness**

**Example**
Database entry:
```
username: admin
password: password123  # plaintext
```

**Tools**
- Burp Suite
- Hashcat
- John the Ripper
- SQLMap (for extracting hashes)

**Risk Rating**  
Critical

**Remediation**
- Never store passwords in plaintext
- Use strong adaptive hashing: bcrypt (cost ≥10), Argon2, PBKDF2 (≥100,000 iterations)
- Always use a unique, cryptographically random salt per user

---

## 8. SENSITIVE DATA EXPOSURE IN URLS (GET PARAMETERS)

**Description**  
Sensitive data (passwords, tokens, PII) in URLs can be logged by servers, proxies, and browsers, and may be leaked via Referer headers or bookmarks.

**What to Look For**
- Authentication tokens in URL query strings
- Passwords, credit card numbers in GET requests
- Session IDs in URL (should be in cookies)

**What to Ignore**
- Sensitive data sent only via POST bodies or cookies

**How to Test with Burp Suite**

1. **Browse the application and observe requests**
2. **Look for sensitive parameters like `password`, `token`, `ssn`, `creditcard` in URL query strings**

**Example**
```
https://target.com/reset-password?token=abc123&email=user@example.com
```
Token and email exposed in URL.

**Tools**
- Burp Proxy
- Manual observation

**Risk Rating**  
Medium to High

**Remediation**
- Never send sensitive data in GET parameters
- Use POST for sensitive operations
- Use cookies with `Secure` and `HttpOnly` for session tokens

---

## 9. SENSITIVE DATA IN LOGS, ERROR MESSAGES, AND DEBUG OUTPUT

**Description**  
Applications often log sensitive data (passwords, tokens, PII) inadvertently, which can be accessed by attackers if log files are exposed.

**What to Look For**
- Passwords or tokens in error responses
- Stack traces containing sensitive data
- Debug endpoints (`/debug`, `/phpinfo`) revealing configuration
- Log files accessible via directory listing or file inclusion

**What to Ignore**
- Sanitized logs and error messages

**How to Test with Burp Suite**

1. **Trigger errors by sending malformed input**
2. **Observe response for stack traces or sensitive information**
3. **Check for exposed log files: `/logs/`, `/var/log/`, `/error_log`**

**Example**
```
Error: SQLSTATE[42S02]: Base table or view not found: 1146 Table 'app.users' doesn't exist
```
May leak database table names.

**Tools**
- Burp Suite
- Dirb/Gobuster for log directories

**Risk Rating**  
Medium

**Remediation**
- Sanitize error messages in production
- Disable detailed error reporting
- Do not log sensitive data
- Store logs securely with proper access controls

---

## 10. WEAK ENCRYPTION ALGORITHMS (MD5, SHA1, DES, RC4)

**Description**  
Use of weak algorithms for cryptographic operations (hashing, encryption) allows attackers to reverse or break the protection.

**What to Look For**
- Passwords hashed with MD5 or SHA1 (even with salt)
- Encryption using DES, 3DES, RC4
- Use of ECB mode for encryption (reveals patterns)

**What to Ignore**
- Strong algorithms: AES-256-GCM, ChaCha20-Poly1305 for encryption; Argon2, bcrypt for hashing

**How to Test**

1. **If you can extract hashes, identify algorithm by length and format**
   - MD5 = 32 hex chars
   - SHA1 = 40 hex chars
2. **Check for use of weak ciphers in TLS (see earlier)**
3. **Inspect source code or configuration for algorithm names**

**Example**
```python
# Insecure
hashlib.md5(password + salt).hexdigest()
```

**Tools**
- Hashcat (identify hash type)
- John the Ripper

**Risk Rating**  
High

**Remediation**
- Replace weak algorithms with strong ones
- For passwords: bcrypt, Argon2, PBKDF2
- For encryption: AES-256-GCM, ChaCha20

---

## 11. INSUFFICIENT KEY LENGTH (RSA 1024, SYMMETRIC KEYS)

**Description**  
Short key lengths can be broken with sufficient computational power, making encryption ineffective.

**What to Look For**
- RSA keys < 2048 bits
- Symmetric keys < 128 bits (AES-128 is acceptable, but 256 is better)
- DSA keys < 2048 bits
- EC keys < 256 bits

**What to Ignore**
- RSA ≥ 2048 bits, AES-256, ECDH with curve P-256 or better

**How to Test with Tools**

1. **Check TLS certificates:**
   ```
   openssl x509 -in cert.pem -text -noout | grep "Public-Key"
   ```
2. **Look for key lengths in configuration files**

**Example**
```
Public-Key: (1024 bit)
```
RSA 1024 is considered weak and can be factored by state-level actors.

**Tools**
- openssl
- sslyze

**Risk Rating**  
High

**Remediation**
- Use RSA 2048-bit minimum (3072 or 4096 preferred)
- Use AES-256 or ChaCha20 for symmetric encryption
- Use ECDH with curve P-384 or higher

---

## 12. USE OF ECB MODE (ELECTRONIC CODEBOOK)

**Description**  
ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, revealing patterns in data. This can leak information about the plaintext.

**What to Look For**
- Encrypted data showing repeating patterns (e.g., in cookies, tokens)
- Use of AES-ECB in code or configuration

**What to Ignore**
- Use of secure modes like GCM, CBC (with proper IV), CTR

**How to Test**

1. **Capture an encrypted value (e.g., cookie, token)**
2. **Look for repeating 16-byte blocks (for AES)**
   - Example: `aGVsbG8gd29ybGQ=...` if repeated, indicates ECB

3. **Use tools to detect ECB patterns**

**Example**
Encrypted cookie: `4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c` (repeating pattern every 32 hex chars may indicate ECB)

**Tools**
- Custom scripts to detect block repetition
- Manual inspection

**Risk Rating**  
Medium

**Remediation**
- Use authenticated encryption modes: GCM, CCM
- If CBC must be used, ensure random IV per message
- Never use ECB

---

## 13. PADDING ORACLE ATTACKS (CBC MODE)

**Description**  
When CBC mode encryption is used without proper authentication, an attacker can manipulate ciphertext and observe padding errors to decrypt data.

**What to Look For**
- Use of CBC mode without MAC (encrypt-then-MAC)
- Different error messages for invalid padding vs. invalid MAC
- Ability to trigger padding errors

**What to Ignore**
- Use of authenticated encryption (GCM) or encrypt-then-MAC

**How to Test with Burp Suite**

1. **Find an encrypted parameter (e.g., in cookie, POST body)**
2. **Modify a byte in the ciphertext and observe response**
   - If different error messages appear (e.g., "padding error" vs "invalid request"), it may be vulnerable
3. **Use tools like PadBuster to automate**

**Example**
```http
GET /profile?token=... HTTP/1.1
```
Modify one byte of token; if server returns `500` vs `200`, padding oracle exists.

**Tools**
- PadBuster
- Burp Intruder with custom payloads
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Use authenticated encryption (GCM, CCM)
- If using CBC, combine with HMAC (encrypt-then-MAC) and verify MAC before decrypting
- Ensure uniform error messages

---

## 14. TLS COMPRESSION VULNERABILITIES (CRIME, BREACH)

**Description**  
TLS compression (CRIME) and HTTP compression (BREACH) can be exploited to steal sensitive information by observing compression ratios.

**What to Look For**
- TLS compression enabled (CRIME)
- HTTP compression enabled on responses containing secrets (BREACH)
- Application returns compressed responses containing secrets (e.g., CSRF tokens)

**What to Ignore**
- TLS compression disabled
- HTTP compression disabled for sensitive endpoints

**How to Test with Tools**

1. **Check for TLS compression:**
   ```
   testssl.sh --crime target.com
   ```

2. **Check for HTTP compression:**
   - Look for `Content-Encoding: gzip` in responses
   - If a response contains a secret (e.g., CSRF token), an attacker could inject data and observe compression ratio to recover the secret (BREACH).

**Example**
Response containing CSRF token compressed: attacker can inject characters and measure size changes.

**Tools**
- testssl.sh
- Custom BREACH PoC scripts

**Risk Rating**  
Medium to High

**Remediation**
- Disable TLS compression (it's already disabled by default in modern servers)
- Disable HTTP compression for sensitive endpoints (use separate domain for static assets)
- Use random CSRF tokens that are not compressed

---

## 15. SSL/TLS DOWNGRADE ATTACKS (POODLE, DROWN)

**Description**  
Attackers can force the client to downgrade to weaker protocols or cipher suites, enabling exploitation of known vulnerabilities.

**What to Look For**
- Support for SSLv3 (POODLE)
- Support for SSLv2 (DROWN)
- Support for export-grade ciphers (FREAK, Logjam)
- Missing TLS_FALLBACK_SCSV

**What to Ignore**
- All weak protocols disabled, TLS_FALLBACK_SCSV present

**How to Test with Tools**

1. **Use testssl.sh:**
   ```
   testssl.sh --poodle target.com
   testssl.sh --drown target.com
   testssl.sh --fallback target.com
   ```

2. **Use nmap:**
   ```
   nmap --script ssl-poodle,ssl-drown -p 443 target.com
   ```

**Example**
```
SSLv3 supported (POODLE)
```

**Tools**
- testssl.sh
- sslyze
- nmap

**Risk Rating**  
High

**Remediation**
- Disable SSLv2, SSLv3, TLS 1.0
- Enable TLS_FALLBACK_SCSV
- Disable export-grade ciphers

---

## 16. MISSING SECURE FLAG ON COOKIES

**Description**  
Cookies without the `Secure` flag can be transmitted over unencrypted HTTP, making them vulnerable to interception.

**What to Look For**
- Session cookies, authentication tokens without `Secure` flag
- Any sensitive cookie sent over HTTP (even if site uses HTTPS, the cookie may still be sent if not flagged)

**What to Ignore**
- Cookies with `Secure` flag set

**How to Test with Burp Suite**

1. **Intercept responses that set cookies**
2. **Look for `Set-Cookie` header missing `Secure`**

**Example**
```
Set-Cookie: sessionid=abc123; Path=/
```
Missing `Secure`.

**Tools**
- Burp Proxy
- Browser DevTools

**Risk Rating**  
Medium

**Remediation**
- Set `Secure` flag on all cookies that contain sensitive data
- Also set `HttpOnly` and `SameSite`

---

## 17. EXPOSURE OF SENSITIVE DATA VIA REFERER HEADER

**Description**  
When a secure page (HTTPS) links to an insecure page (HTTP) or includes external resources, the full URL (including query parameters) may be leaked in the `Referer` header.

**What to Look For**
- HTTPS pages containing links to HTTP sites
- HTTPS pages loading HTTP resources (mixed content)
- Sensitive data in URL parameters (e.g., tokens) that can be leaked via Referer

**What to Ignore**
- No HTTP links/resources on HTTPS pages
- Use of `Referrer-Policy: no-referrer`

**How to Test with Burp Suite**

1. **Browse HTTPS pages and watch for requests to HTTP domains**
2. **Check if those requests include Referer headers containing sensitive data**

**Example**
HTTPS page with link: `<a href="http://example.com">`
When clicked, `Referer: https://target.com/page?token=abc123` is sent to `http://example.com` (in plaintext).

**Tools**
- Burp Proxy
- Browser DevTools (Network tab)

**Risk Rating**  
Medium

**Remediation**
- Avoid linking to HTTP sites from HTTPS pages
- Use `Referrer-Policy: no-referrer` or `same-origin`
- Avoid sensitive data in URL parameters

---

## 18. INSECURE STORAGE OF SECRETS IN ENVIRONMENT VARIABLES

**Description**  
Environment variables may be exposed through misconfigured servers, debugging interfaces, or container orchestration tools.

**What to Look For**
- Exposed `.env` files (via directory listing or path traversal)
- Debug endpoints (`/phpinfo`, `/env`) that display environment variables
- Secrets in environment variables of containers visible via API

**What to Ignore**
- Secrets stored in secret management services, not in plaintext env vars

**How to Test**

1. **Check for common env file paths:**
   ```
   /.env
   /.env.local
   /.env.production
   /env
   ```

2. **Check for phpinfo, /env, /config endpoints**

3. **If you have access to server, inspect environment (rare in testing)**

**Example**
```
/.env file contains:
DB_PASSWORD=secret123
API_KEY=abc123
```

**Tools**
- Dirb, Gobuster
- Burp Suite

**Risk Rating**  
High

**Remediation**
- Never store secrets in `.env` files in production exposed to web
- Use secret management solutions (Vault, AWS Secrets Manager, Kubernetes secrets)
- Restrict access to environment variables

---

## 19. WEAK RANDOM NUMBER GENERATION (PREDICTABLE TOKENS)

**Description**  
Using weak random number generators (e.g., `rand()`, `mt_rand()`, predictable seeds) can lead to predictable tokens, session IDs, CSRF tokens, or password reset tokens.

**What to Look For**
- Tokens with patterns (sequential, timestamp-based)
- Short tokens (e.g., 4-digit numbers)
- Tokens generated using predictable algorithms

**What to Ignore**
- Cryptographically secure random tokens (e.g., `random_bytes()`, `SecureRandom` in Java, `secrets` in Python)

**How to Test with Burp Suite**

1. **Collect a series of tokens (e.g., 50-100)**
2. **Send to Burp Sequencer**
3. **Analyze randomness: look for biases, patterns**

**Example**
Reset tokens: `123456`, `123457`, `123458` → sequential.

**Tools**
- Burp Sequencer
- Custom statistical analysis

**Risk Rating**  
High

**Remediation**
- Use cryptographically secure random number generators
- Ensure sufficient length (≥128 bits)
- Do not rely on time or predictable inputs as seeds

---

## 20. SENSITIVE DATA IN CLIENT-SIDE STORAGE (localStorage, sessionStorage)

**Description**  
Storing sensitive data (tokens, PII) in `localStorage` or `sessionStorage` makes it accessible to any JavaScript running on the page, including malicious scripts via XSS.

**What to Look For**
- Authentication tokens stored in `localStorage` (instead of `HttpOnly` cookies)
- Personal information, credit card details stored in client-side storage

**What to Ignore**
- Using `HttpOnly` cookies for session tokens
- Storing non-sensitive, transient data

**How to Test with Browser DevTools**

1. **Open DevTools → Application → Storage**
2. **Examine `localStorage` and `sessionStorage` for sensitive data**

**Example**
```javascript
localStorage.setItem('token', 'eyJhbGciOiJIUzI1NiIs...');
```
Any XSS can steal this token.

**Tools**
- Browser DevTools
- Burp (search responses for `localStorage` usage)

**Risk Rating**  
High

**Remediation**
- Use `HttpOnly` cookies for session tokens
- If tokens must be in client-side, use sessionStorage with short lifetime and ensure XSS protection
- Avoid storing PII in client-side storage

---

## 21. INSECURE DATA AT REST (UNENCRYPTED DATABASES, BACKUPS)

**Description**  
Sensitive data stored in databases, file systems, or backups without encryption can be exposed if storage media is compromised.

**What to Look For**
- Databases storing plaintext passwords, credit cards
- Backups stored in unencrypted format
- Database files accessible via path traversal or file disclosure

**What to Ignore**
- Data encrypted at rest (e.g., database encryption, encrypted backups)

**How to Test**

1. **If you can access the database (via SQLi or other), check if sensitive fields are encrypted**
2. **Look for backup files exposed via web:**
   ```
   /backup.sql
   /dump.sql
   /db_backup.zip
   ```

**Example**
Accessing `/backup.sql` reveals:
```sql
INSERT INTO users VALUES (1,'admin','plaintext_password',...);
```

**Tools**
- Dirb/Gobuster for backup files
- SQL injection to retrieve data

**Risk Rating**  
Critical

**Remediation**
- Encrypt sensitive data at rest (database encryption, column-level encryption)
- Ensure backups are encrypted and stored securely
- Use proper access controls for backup files

---

## 22. HARDCODED ENCRYPTION KEYS IN SOURCE CODE

**Description**  
Encryption keys hardcoded in source code can be extracted by attackers, allowing them to decrypt sensitive data.

**What to Look For**
- Strings that look like encryption keys (AES keys, RSA private keys) in code
- Keys in JavaScript, HTML comments, or configuration files

**What to Ignore**
- Keys stored in secure key management services

**How to Test with Burp Suite & Tools**

1. **Search JavaScript files for patterns:**
   - `key: "`, `secret: "`, `AES`, `RSA`
2. **Use TruffleHog on source code**

**Example**
```javascript
const encryptionKey = "0123456789abcdef0123456789abcdef";
```

**Tools**
- TruffleHog
- GitLeaks
- Manual inspection

**Risk Rating**  
Critical

**Remediation**
- Never hardcode encryption keys
- Use environment variables or key management services
- Rotate keys regularly

---

## 23. USE OF DEPRECATED CRYPTOGRAPHIC APIS

**Description**  
Using outdated cryptographic APIs (e.g., `javax.crypto` without proper modes, `mcrypt` in PHP) can lead to insecure implementations.

**What to Look For**
- In source code: `MD5`, `SHA1`, `mcrypt`, `openssl_encrypt` with ECB mode
- Use of deprecated libraries

**What to Ignore**
- Use of modern, well-audited cryptographic libraries

**How to Test**

1. **Review source code (if available) or decompile**
2. **Look for function calls to known weak APIs**

**Example**
```php
$hashed = md5($password);
```

**Tools**
- Manual code review
- Static analysis tools (SonarQube, Checkmarx)

**Risk Rating**  
High

**Remediation**
- Update to modern, well-supported cryptographic libraries
- Follow industry best practices (e.g., using libsodium, cryptography.io)

---

## 24. INSECURE HANDLING OF SECRETS IN CI/CD PIPELINES

**Description**  
Secrets exposed in CI/CD logs, build artifacts, or configuration files can be accessed by unauthorized parties.

**What to Look For**
- Secrets printed in build logs (e.g., `echo $API_KEY`)
- Secrets stored in plaintext in CI configuration files (`.gitlab-ci.yml`, `Jenkinsfile`)
- Artifacts containing secrets published

**What to Ignore**
- Secrets stored as masked variables, not printed in logs

**How to Test**

1. **Check CI/CD configuration files in repositories**
2. **Look for exposed secrets in public logs (if accessible)**

**Example**
```yaml
# .gitlab-ci.yml
script:
  - echo "Deploying with API_KEY=$API_KEY"
```
API key appears in logs.

**Tools**
- Manual inspection
- Secret scanning tools

**Risk Rating**  
High

**Remediation**
- Use CI/CD secret masking features
- Never echo secrets in logs
- Use secret management services integrated with CI/CD

---

## 25. SENSITIVE DATA IN HTTP HEADERS (BASIC AUTH, API KEYS)

**Description**  
Sensitive data sent in HTTP headers (e.g., Basic Authentication, API keys) may be exposed in logs, referrers, or intercepted.

**What to Look For**
- `Authorization: Basic base64(username:password)` – base64 can be decoded instantly
- API keys in `X-API-Key` or custom headers
- Tokens in `Authorization: Bearer` exposed over HTTP

**What to Ignore**
- Using HTTPS, but still headers are visible in logs

**How to Test with Burp Suite**

1. **Observe requests for sensitive headers**
2. **Check if they are sent over HTTP (not HTTPS)**
3. **Check if they appear in logs (by triggering errors that log headers)**

**Example**
```
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
```
Decoded: admin:password

**Tools**
- Burp Proxy
- Manual inspection

**Risk Rating**  
Medium

**Remediation**
- Use HTTPS only for authentication
- Avoid Basic Auth; use token-based auth
- Ensure sensitive headers are not logged

---

## 26. INSECURE STORAGE OF SENSITIVE DATA IN MOBILE APP BACKUPS

**Description**  
Mobile applications may store sensitive data in unencrypted backups (iTunes, iCloud, Android backups), allowing extraction by attackers.

**What to Look For**
- iOS apps with `NSFileProtectionNone` for files containing sensitive data
- Android apps with `allowBackup=true` and storing sensitive data in shared preferences or databases without encryption

**What to Ignore**
- Apps that disable backups and encrypt sensitive data

**How to Test**

1. **For Android:**
   - Check `AndroidManifest.xml` for `android:allowBackup="true"`
   - Extract backup via `adb backup` and inspect data

2. **For iOS:**
   - Use `iTunes` to create backup and inspect files

**Example**
Android backup contains `shared_prefs/auth.xml` with token in plaintext.

**Tools**
- adb
- iTunes
- backup extraction tools

**Risk Rating**  
Medium to High

**Remediation**
- Set `android:allowBackup="false"` in manifest
- Use `NSFileProtectionComplete` for sensitive files on iOS
- Encrypt sensitive data before storing

---

## 27. WEAK ENCRYPTION IN DATABASE COLUMNS (DETERMINISTIC ENCRYPTION)

**Description**  
Deterministic encryption (same plaintext yields same ciphertext) allows attackers to infer patterns and potentially decrypt data via frequency analysis.

**What to Look For**
- Database columns with encrypted data that shows repeated patterns (e.g., same ciphertext for same plaintext)
- Use of deterministic encryption (e.g., AES in ECB mode or without IV)

**What to Ignore**
- Randomized encryption (e.g., AES-GCM with unique IV per row)

**How to Test**

1. **If you have access to database, look for repeated ciphertext values**
2. **Check application code for encryption method (if available)**

**Example**
Ciphertexts in column `ssn`:
```
Row1: 3d4f5a6b7c8d9e0f...
Row2: 3d4f5a6b7c8d9e0f... (same ciphertext as row1)
```
Indicates deterministic encryption.

**Tools**
- Manual inspection
- Code review

**Risk Rating**  
Medium

**Remediation**
- Use randomized encryption (IV per record)
- If deterministic encryption is required (e.g., for indexing), use a secure algorithm with a unique IV stored alongside ciphertext

---

## 28. LACK OF ENCRYPTION FOR DATA IN TRANSIT (INTERNAL NETWORKS)

**Description**  
Internal traffic between microservices, databases, and caches often goes unencrypted, allowing attackers who compromise the internal network to intercept sensitive data.

**What to Look For**
- Database connections without TLS (e.g., MySQL without SSL)
- Inter-service communication over HTTP
- Redis, Memcached, Elasticsearch without encryption

**What to Ignore**
- All internal communication encrypted (e.g., mTLS, HTTPS)

**How to Test**

1. **If you have internal network access (e.g., via SSRF or compromised host), sniff traffic**
2. **Check configuration files for database SSL settings**

**Example**
MySQL connection string: `mysql://user:pass@db:3306/mydb` (no SSL)

**Tools**
- Wireshark (on internal network)
- Configuration inspection

**Risk Rating**  
High

**Remediation**
- Enable TLS for all internal services
- Use mTLS for service-to-service authentication
- Encrypt database connections

---

## 29. EXPOSURE OF SENSITIVE DATA IN ERROR MESSAGES (STACK TRACES)

**Description**  
Verbose error messages (stack traces) can leak sensitive information such as database structure, file paths, or even secrets.

**What to Look For**
- Full stack traces in production responses
- Error pages displaying database errors, file paths, or code snippets

**What to Ignore**
- Custom error pages with no technical details

**How to Test with Burp Suite**

1. **Trigger errors by sending malformed input**
2. **Observe response for stack traces, SQL errors, file paths**

**Example**
```
Error: PDOException: SQLSTATE[42S02]: Base table or view not found: 1146 Table 'prod.users' doesn't exist
```

**Tools**
- Burp Repeater
- Manual fuzzing

**Risk Rating**  
Medium

**Remediation**
- Disable detailed error reporting in production
- Use custom error pages
- Log errors securely without exposing to users

---

## 30. USE OF CUSTOM OR WEAK CRYPTOGRAPHIC ALGORITHMS

**Description**  
Rolling your own cryptography or using proprietary, unvetted algorithms often leads to vulnerabilities that can be exploited.

**What to Look For**
- Custom encryption functions in code (e.g., XOR, substitution ciphers)
- Use of non-standard algorithms (e.g., home-grown hashes)
- Lack of use of well-known cryptographic libraries

**What to Ignore**
- Use of standard, well-audited libraries (OpenSSL, libsodium, Bouncy Castle)

**How to Test**

1. **Review source code for custom encryption implementations**
2. **Look for usage of weak custom algorithms (XOR, bit-shifting, etc.)**

**Example**
```php
function encrypt($data) {
    $key = 'secretkey';
    $result = '';
    for ($i=0; $i<strlen($data); $i++) {
        $result .= chr(ord($data[$i]) ^ ord($key[$i % strlen($key)]));
    }
    return base64_encode($result);
}
```

**Tools**
- Code review
- Static analysis

**Risk Rating**  
Critical

**Remediation**
- Use established cryptographic libraries
- Never implement your own encryption
- Follow NIST recommendations

---

## ✅ **SUMMARY**

Cryptographic failures encompass a wide range of issues from transport security to storage, key management, and algorithm selection. Properly implemented cryptography is essential for protecting sensitive data.

### **Key Areas to Test**

| Area | Critical Checks |
|------|-----------------|
| Transport Security | TLS versions, ciphers, certificates, HSTS |
| Data at Rest | Encryption of databases, backups, files |
| Secrets Management | Hardcoded secrets, key storage, environment variables |
| Hashing | Password storage, salt, algorithm strength |
| Client-Side Storage | localStorage, sessionStorage, mobile backups |
| Error Handling | Information leakage via errors |
| Randomness | Token generation, entropy |
| API & Headers | Exposure of credentials in URLs/headers |

### **Testing Tools Summary**

| Tool | Purpose |
|------|---------|
| Burp Suite | Proxy, scanner, intruder for many tests |
| testssl.sh | TLS/SSL configuration testing |
| sslyze | Detailed TLS analysis |
| nmap | Port scanning, ssl-enum-ciphers |
| openssl | Manual certificate and protocol checks |
| TruffleHog | Secret scanning in code |
| Hashcat | Password hash cracking (for testing) |
| Dirb/Gobuster | Finding exposed files (logs, backups, .env) |
| Browser DevTools | Client-side storage inspection |

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
