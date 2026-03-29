# ⚙️ **A05: SECURITY MISCONFIGURATION TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Configuration-Based Vulnerabilities*

---

## 📋 **TABLE OF CONTENTS**

1. [Default Credentials Left Unchanged](#1-default-credentials-left-unchanged)
2. [Debug Mode / Development Features Enabled in Production](#2-debug-mode--development-features-enabled-in-production)
3. [Directory Listing Enabled](#3-directory-listing-enabled)
4. [Unnecessary HTTP Methods Enabled (TRACE, OPTIONS, etc.)](#4-unnecessary-http-methods-enabled-trace-options-etc)
5. [Verbose Error Messages Exposing Stack Traces](#5-verbose-error-messages-exposing-stack-traces)
6. [Missing Security Headers (CSP, HSTS, X-Frame-Options)](#6-missing-security-headers-csp-hsts-x-frame-options)
7. [Outdated Software Versions (Unpatched Vulnerabilities)](#7-outdated-software-versions-unpatched-vulnerabilities)
8. [Insecure Cloud Storage Permissions (e.g., Public S3 Buckets)](#8-insecure-cloud-storage-permissions-eg-public-s3-buckets)
9. [Exposed Administrative Interfaces](#9-exposed-administrative-interfaces)
10. [Unnecessary Services or Ports Open](#10-unnecessary-services-or-ports-open)
11. [Weak SSL/TLS Configuration (Old Protocols, Weak Ciphers)](#11-weak-ssltls-configuration-old-protocols-weak-ciphers)
12. [Missing Security Patches (Unpatched Vulnerabilities)](#12-missing-security-patches-unpatched-vulnerabilities)
13. [Improper Cross-Origin Resource Sharing (CORS) Configuration](#13-improper-cross-origin-resource-sharing-cors-configuration)
14. [Insecure HTTP Headers (Server Version Disclosure)](#14-insecure-http-headers-server-version-disclosure)
15. [Default Installation Files or Sample Scripts Left Accessible](#15-default-installation-files-or-sample-scripts-left-accessible)
16. [Unprotected Backup Files or Database Dumps](#16-unprotected-backup-files-or-database-dumps)
17. [Missing or Weak Password Policies](#17-missing-or-weak-password-policies)
18. [Session Cookie Misconfiguration (Missing HttpOnly, Secure)](#18-session-cookie-misconfiguration-missing-httponly-secure)
19. [Improper File Permissions (World-Readable/Writable)](#19-improper-file-permissions-world-readablewritable)
20. [Open Redirects via Misconfigured URL Handling](#20-open-redirects-via-misconfigured-url-handling)
21. [Insecure WebSocket Configuration](#21-insecure-websocket-configuration)
22. [Server-Side Includes (SSI) Enabled](#22-server-side-includes-ssi-enabled)
23. [Unrestricted File Upload Configuration](#23-unrestricted-file-upload-configuration)
24. [Missing Rate Limiting Configuration](#24-missing-rate-limiting-configuration)
25. [Incorrect HTTP Cache Headers for Sensitive Content](#25-incorrect-http-cache-headers-for-sensitive-content)
26. [Improperly Configured Cross-Domain Policy Files (crossdomain.xml, clientaccesspolicy.xml)](#26-improperly-configured-cross-domain-policy-files-crossdomainxml-clientaccesspolicyxml)
27. [Information Disclosure via Version Headers](#27-information-disclosure-via-version-headers)
28. [Weak Cryptography Configuration (e.g., allow weak ciphers)](#28-weak-cryptography-configuration-eg-allow-weak-ciphers)
29. [Exposed Git or Version Control Directories](#29-exposed-git-or-version-control-directories)
30. [Improperly Configured Firewall Rules (e.g., open ports)](#30-improperly-configured-firewall-rules-eg-open-ports)

---

## 1. DEFAULT CREDENTIALS LEFT UNCHANGED

**Description**  
Default credentials are common in many applications, devices, and frameworks. If left unchanged, attackers can easily gain administrative access.

**What to Look For**
- Admin panels or services with well‑known default credentials (admin/admin, root/root, etc.).
- Applications that do not force a password change on first login.

**What to Ignore**
- Systems that enforce password change on first use and disable default accounts.

**How to Test with Burp Suite**
1. Identify admin endpoints (e.g., `/admin`, `/manager`, `/phpmyadmin`).
2. Attempt login with common default credentials.
3. Use Burp Intruder with a wordlist of default credential pairs.

**Example**
```http
GET /admin/ HTTP/1.1
Authorization: Basic YWRtaW46YWRtaW4=
```
If access is granted, default credentials are in use.

**Tools**
- Burp Intruder (with default credential wordlists)
- Hydra
- Nmap with `http-default-accounts` script

**Risk Rating**  
Critical

**Remediation**
- Change default credentials during deployment.
- Remove or disable default accounts.
- Implement strong password policies.

---

## 2. DEBUG MODE / DEVELOPMENT FEATURES ENABLED IN PRODUCTION

**Description**  
Debug mode often exposes sensitive information (stack traces, configuration, internal paths) and may enable dangerous features like interactive error consoles.

**What to Look For**
- Error pages with stack traces, debug information, or `X-Debug` headers.
- Endpoints like `/debug`, `/phpinfo.php`, `/_profiler`, `/dev`.

**What to Ignore**
- Production systems with debug disabled and custom error pages.

**How to Test with Burp Suite**
1. Trigger errors (e.g., malformed input, 404) and examine responses for stack traces.
2. Check for common debug endpoints: `/debug`, `/phpinfo`, `/env`, `/health`.
3. Look for headers like `X-Powered-By` with debugging info.

**Example**
```http
GET /phpinfo.php HTTP/1.1
```
If phpinfo is accessible, the server exposes sensitive configuration.

**Tools**
- Dirb/Gobuster (to discover debug endpoints)
- Burp Scanner

**Risk Rating**  
High to Critical

**Remediation**
- Disable debug mode in production.
- Remove debug endpoints and files.
- Use generic error pages.

---

## 3. DIRECTORY LISTING ENABLED

**Description**  
When directory listing is enabled, attackers can browse directories and discover files that were not intended for public access.

**What to Look For**
- Accessing a directory (e.g., `/uploads/`) shows a list of files.
- No `index.html` or default page in the directory.

**What to Ignore**
- Directories that return a 403 Forbidden or 404 Not Found.

**How to Test with Burp Suite**
1. Attempt to access directories that may contain uploads, configs, or logs.
2. Use tools like Dirb or Burp Intruder to test common directory names.
3. Observe if the response lists files.

**Example**
```http
GET /uploads/ HTTP/1.1
```
Response may contain HTML with file listing.

**Tools**
- Burp Repeater
- Dirb/Gobuster
- Manual browsing

**Risk Rating**  
Medium to High

**Remediation**
- Disable directory listing in web server configuration.
- Place `index.html` or deny access via `.htaccess` / web.config.

---

## 4. UNNECESSARY HTTP METHODS ENABLED (TRACE, OPTIONS, ETC.)

**Description**  
Unnecessary HTTP methods like `TRACE` can be abused for cross‑site tracing (XST) attacks. Others like `PUT`, `DELETE` may be used to modify resources.

**What to Look For**
- `TRACE` method allowed (returns request body).
- `PUT`, `DELETE`, `PATCH` enabled without proper authentication/authorization.
- `OPTIONS` revealing allowed methods.

**What to Ignore**
- Only `GET`, `POST`, and necessary methods allowed, with proper access controls.

**How to Test with Burp Suite**
1. Use `OPTIONS` to discover allowed methods.
2. Send a `TRACE` request and see if it echoes the request.
3. Attempt to `PUT` or `DELETE` files.

**Example**
```http
TRACE / HTTP/1.1
Host: target.com
```
If response echoes the request, `TRACE` is enabled.

**Tools**
- Burp Repeater
- Nmap (`http-methods` script)

**Risk Rating**  
Medium

**Remediation**
- Disable `TRACE` method.
- Disable unnecessary methods like `PUT`, `DELETE` unless required.
- Implement proper authentication for allowed methods.

---

## 5. VERBOSE ERROR MESSAGES EXPOSING STACK TRACES

**Description**  
Error messages that reveal internal details (file paths, database structure, framework version) aid attackers in reconnaissance and exploitation.

**What to Look For**
- Stack traces in HTTP responses.
- SQL error messages with table names.
- File path disclosures.

**What to Ignore**
- Generic error pages without technical details.

**How to Test with Burp Suite**
1. Trigger errors by sending invalid input, long strings, or malformed parameters.
2. Observe responses for stack traces, SQL errors, or file paths.

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
- Burp Intruder (fuzzing)

**Risk Rating**  
Medium to High

**Remediation**
- Use custom error pages.
- Disable detailed error output in production.
- Log errors internally without exposing them.

---

## 6. MISSING SECURITY HEADERS (CSP, HSTS, X-FRAME-OPTIONS)

**Description**  
Security headers help protect against common attacks like clickjacking, XSS, and protocol downgrades. Their absence indicates a misconfiguration.

**What to Look For**
- Missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`.
- Missing `Referrer-Policy`, `Permissions-Policy`.

**What to Ignore**
- Properly configured headers that mitigate client‑side risks.

**How to Test with Burp Suite**
1. Intercept responses and examine headers.
2. Use Burp Scanner passive scan to report missing headers.
3. Use online tools like securityheaders.com.

**Example**
```http
HTTP/1.1 200 OK
Server: nginx
Date: ...
```
No security headers present.

**Tools**
- Burp Scanner
- Browser DevTools
- securityheaders.com

**Risk Rating**  
Medium to High

**Remediation**
- Add `Strict-Transport-Security` for HTTPS sites.
- Add `X-Frame-Options: DENY` to prevent clickjacking.
- Implement a strict `Content-Security-Policy`.

---

## 7. OUTDATED SOFTWARE VERSIONS (UNPATCHED VULNERABILITIES)

**Description**  
Running outdated software (web servers, frameworks, libraries) exposes known vulnerabilities that can be exploited.

**What to Look For**
- Old versions of Apache, Nginx, PHP, Tomcat, etc., disclosed in headers or error pages.
- Framework version in cookies or URLs (e.g., `JSESSIONID` for Tomcat).

**What to Ignore**
- Up‑to‑date software with patches applied.

**How to Test with Burp Suite**
1. Inspect `Server` header, `X-Powered-By`, and other version‑revealing headers.
2. Look for version strings in static files (e.g., `/css/style.css?ver=1.2.3`).
3. Use fingerprinting tools like Wappalyzer.

**Example**
```http
Server: Apache/2.2.22 (Ubuntu)
```
Version 2.2.22 is old and vulnerable.

**Tools**
- Wappalyzer
- Nmap
- Burp Scanner

**Risk Rating**  
High to Critical

**Remediation**
- Keep all software updated to the latest stable versions.
- Use a patch management process.

---

## 8. INSECURE CLOUD STORAGE PERMISSIONS (E.G., PUBLIC S3 BUCKETS)

**Description**  
Misconfigured cloud storage (e.g., AWS S3, Azure Blob) can expose sensitive data to the public.

**What to Look For**
- Publicly readable buckets containing sensitive files (backups, credentials, user data).
- Bucket listing enabled.

**What to Ignore**
- Private buckets with proper IAM policies.

**How to Test with Burp Suite**
1. Try to access bucket URLs (e.g., `https://bucket-name.s3.amazonaws.com`).
2. Check if bucket listing returns files.
3. Attempt to download files from the bucket.

**Example**
```http
GET https://company-backups.s3.amazonaws.com/ HTTP/1.1
```
If response lists files, bucket is public.

**Tools**
- AWS CLI
- S3Scanner
- Manual browsing

**Risk Rating**  
Critical

**Remediation**
- Restrict bucket permissions to private.
- Use IAM roles and policies to control access.
- Enable bucket logging and monitor for unusual access.

---

## 9. EXPOSED ADMINISTRATIVE INTERFACES

**Description**  
Admin interfaces that are publicly accessible increase the attack surface. They should be restricted to internal networks or require strong authentication.

**What to Look For**
- Publicly accessible `/admin`, `/manager`, `/phpmyadmin`, `/wp-admin` without IP restrictions.
- No additional authentication layer.

**What to Ignore**
- Admin panels protected by IP whitelisting, VPN, or strong multi‑factor authentication.

**How to Test with Burp Suite**
1. Use Dirb/Gobuster to find common admin paths.
2. Attempt to access them without credentials.
3. Check if they are accessible from the internet.

**Example**
```http
GET /phpmyadmin/ HTTP/1.1
```
If phpMyAdmin is accessible, it may be a target for brute force.

**Tools**
- Dirb/Gobuster
- Burp Intruder

**Risk Rating**  
High

**Remediation**
- Restrict admin interfaces to trusted IP ranges.
- Use strong authentication (MFA) and limit access.
- Place admin panels behind a VPN.

---

## 10. UNNECESSARY SERVICES OR PORTS OPEN

**Description**  
Open ports and running services that are not required increase the attack surface. Attackers can scan and exploit them.

**What to Look For**
- Ports open that are not needed (e.g., FTP, Telnet, unused database ports).
- Services running on default ports without firewall restrictions.

**What to Ignore**
- Only necessary ports open, with firewall rules.

**How to Test with Burp Suite**
1. Use Nmap to scan for open ports.
2. Identify services on those ports.
3. Check if they are necessary for the application.

**Example**
```
nmap -p- target.com
```
Open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL). MySQL should not be exposed to the internet.

**Tools**
- Nmap
- Masscan
- Shodan

**Risk Rating**  
High

**Remediation**
- Close unnecessary ports.
- Use firewalls to restrict access to needed services.
- Place database and internal services behind a firewall or VPN.

---

## 11. WEAK SSL/TLS CONFIGURATION (OLD PROTOCOLS, WEAK CIPHERS)

**Description**  
Weak TLS configurations allow attackers to downgrade connections or decrypt traffic.

**What to Look For**
- Support for SSLv2, SSLv3, TLS 1.0, TLS 1.1.
- Weak cipher suites (RC4, DES, 3DES, export ciphers).
- Missing forward secrecy.

**What to Ignore**
- TLS 1.2 and 1.3 only, with strong ciphers.

**How to Test with Burp Suite**
1. Use `sslyze` or `testssl.sh` to scan.
2. Burp Scanner can detect weak SSL configurations.
3. Test manually with openssl.

**Example**
```bash
testssl.sh --cipher-per-proto target.com
```
If SSLv3 is supported, configuration is weak.

**Tools**
- testssl.sh
- sslyze
- Nmap (`ssl-enum-ciphers`)

**Risk Rating**  
High

**Remediation**
- Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1.
- Use TLS 1.2 and 1.3 only.
- Configure strong cipher suites (ECDHE+AES-GCM, CHACHA20).

---

## 12. MISSING SECURITY PATCHES (UNPATCHED VULNERABILITIES)

**Description**  
Failure to apply security patches leaves the system vulnerable to known exploits.

**What to Look For**
- Version numbers that are outdated and have known CVEs.
- No evidence of patch management.

**What to Ignore**
- Systems that are regularly patched and updated.

**How to Test with Burp Suite**
1. Identify software versions from banners, error messages, or file names.
2. Check CVE databases (NVD, CVE Details) for vulnerabilities.
3. Use vulnerability scanners like Nessus.

**Example**
- Apache version 2.2.22 (released 2012) has many vulnerabilities.

**Tools**
- Nessus
- OpenVAS
- Nmap scripts (`http-apache-negotiation`)

**Risk Rating**  
Critical

**Remediation**
- Implement a patch management process.
- Regularly update operating system, web server, application, and libraries.

---

## 13. IMPROPER CROSS-ORIGIN RESOURCE SHARING (CORS) CONFIGURATION

**Description**  
CORS misconfigurations can allow malicious websites to read sensitive data from your application.

**What to Look For**
- `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`.
- Dynamic origin reflection (echoing any `Origin` header).
- Overly permissive `Access-Control-Allow-Methods` or `Access-Control-Allow-Headers`.

**What to Ignore**
- Strict allowlist of origins, no credentials with wildcard.

**How to Test with Burp Suite**
1. Send requests with custom `Origin` header.
2. Observe if the response reflects that origin with credentials allowed.
3. Check for `Access-Control-Allow-Credentials: true`.

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
- Define a whitelist of allowed origins.
- Do not use wildcard with credentials.
- Use `SameSite` cookie attributes.

---

## 14. INSECURE HTTP HEADERS (SERVER VERSION DISCLOSURE)

**Description**  
Headers like `Server`, `X-Powered-By` reveal software versions and can be used to target known vulnerabilities.

**What to Look For**
- Headers disclosing exact versions (e.g., `Server: Apache/2.4.18 (Ubuntu)`).
- Headers revealing technology stack (`X-Powered-By: PHP/5.6.40`).

**What to Ignore**
- Headers stripped or generic values (e.g., `Server: nginx`).

**How to Test with Burp Suite**
1. Intercept responses and examine headers.
2. Look for `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, etc.

**Example**
```http
Server: Microsoft-IIS/8.5
X-Powered-By: ASP.NET
```
Reveals IIS and ASP.NET versions.

**Tools**
- Burp Proxy
- Browser DevTools

**Risk Rating**  
Low to Medium

**Remediation**
- Remove or mask version details from headers.
- Use generic headers or remove unnecessary headers.

---

## 15. DEFAULT INSTALLATION FILES OR SAMPLE SCRIPTS LEFT ACCESSIBLE

**Description**  
Sample scripts (e.g., `examples/`, `demo/`) often contain vulnerabilities or can be used to fingerprint the application.

**What to Look For**
- Paths like `/examples/`, `/samples/`, `/demo/`, `/test/`, `/docs/`.
- Default configuration files or install scripts.

**What to Ignore**
- No such files present in production.

**How to Test with Burp Suite**
1. Use Dirb/Gobuster to find common installation directories.
2. Access them and see if they are present.

**Example**
```http
GET /examples/jsp/ HTTP/1.1
```
If accessible, may expose vulnerable samples.

**Tools**
- Dirb/Gobuster
- Burp Intruder

**Risk Rating**  
Medium to High

**Remediation**
- Remove sample files and default installation scripts.
- Do not deploy development files to production.

---

## 16. UNPROTECTED BACKUP FILES OR DATABASE DUMPS

**Description**  
Backup files (e.g., `.sql`, `.bak`, `.tar.gz`) left in web‑accessible locations can be downloaded by attackers, exposing sensitive data.

**What to Look For**
- Files like `backup.sql`, `db_dump.tar.gz`, `old.zip`.
- Paths like `/backup/`, `/old/`, `/temp/`.

**What to Ignore**
- No backup files accessible via web.

**How to Test with Burp Suite**
1. Use Dirb/Gobuster with extensions like `.sql`, `.bak`, `.gz`, `.zip`.
2. Try common filenames: `backup.sql`, `db.sql`, `dump.sql`.
3. Access found files and inspect content.

**Example**
```http
GET /backup.sql HTTP/1.1
```
If file is served, may contain database credentials.

**Tools**
- Dirb/Gobuster with extension lists
- Burp Intruder

**Risk Rating**  
Critical

**Remediation**
- Store backups outside the webroot.
- Encrypt backups and restrict access.
- Remove old backups from production servers.

---

## 17. MISSING OR WEAK PASSWORD POLICIES

**Description**  
Weak password policies (no complexity, short length) allow brute force and credential stuffing attacks.

**What to Look For**
- Password length less than 8 characters allowed.
- No requirement for mixed case, numbers, symbols.
- Common passwords accepted (e.g., "password123").

**What to Ignore**
- Strong password policies enforced on registration and change.

**How to Test with Burp Suite**
1. Register a new account with weak password.
2. Try to change password to weak value.
3. Observe if policy is enforced.

**Example**
```http
POST /register HTTP/1.1
{"username":"test","password":"123"}
```
If successful, weak policy.

**Tools**
- Burp Repeater
- Manual testing

**Risk Rating**  
Medium

**Remediation**
- Enforce minimum length (≥8) and complexity (upper, lower, digit, special).
- Reject common passwords (use breached password lists).
- Implement password strength meter.

---

## 18. SESSION COOKIE MISCONFIGURATION (MISSING HTTPONLY, SECURE)

**Description**  
Cookies without `HttpOnly` are accessible to JavaScript (XSS risk). Without `Secure`, they may be transmitted over HTTP. Without `SameSite`, they are more vulnerable to CSRF.

**What to Look For**
- `Set-Cookie` headers missing `HttpOnly`, `Secure`, or `SameSite`.
- Cookies with `Domain` too broad.

**What to Ignore**
- Cookies with all flags properly set.

**How to Test with Burp Suite**
1. Intercept responses that set cookies.
2. Examine flags: `HttpOnly`, `Secure`, `SameSite`.
3. In browser console, try `document.cookie` to see if HttpOnly cookies are hidden.

**Example**
```http
Set-Cookie: sessionid=abc123; Path=/
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

## 19. IMPROPER FILE PERMISSIONS (WORLD-READABLE/WRITABLE)

**Description**  
Files and directories with overly permissive permissions (e.g., 777) can allow attackers to read or modify sensitive files.

**What to Look For**
- Configuration files readable by anyone.
- Upload directories writable by the web server.

**What to Ignore**
- Proper permissions (e.g., 644 for files, 755 for directories) with least privilege.

**How to Test with Burp Suite**
1. Attempt to access configuration files like `/config.php`, `/.env`, `/wp-config.php`.
2. If file is returned, permissions are too permissive.
3. If you can upload files, check if you can overwrite existing files.

**Example**
```http
GET /wp-config.php HTTP/1.1
```
If file is served, permissions are insecure.

**Tools**
- Dirb/Gobuster for common config files
- Manual access

**Risk Rating**  
High

**Remediation**
- Set strict file permissions: 644 for files, 755 for directories.
- Store configuration files outside webroot.
- Use `.htaccess` or `web.config` to deny access.

---

## 20. OPEN REDIRECTS VIA MISCONFIGURED URL HANDLING

**Description**  
Open redirects occur when the application accepts a URL parameter and redirects to it without validation. Attackers can use this for phishing.

**What to Look For**
- Parameters like `redirect`, `returnTo`, `next`, `url` that accept external URLs.
- Redirects that do not validate the target domain.

**What to Ignore**
- Redirects that validate the target against a whitelist or use relative paths.

**How to Test with Burp Suite**
1. Identify redirect parameters.
2. Set the parameter to an external domain, e.g., `https://evil.com`.
3. Observe if the browser redirects to that domain.

**Example**
```http
GET /login?redirect=https://evil.com HTTP/1.1
```
If the user is redirected to `https://evil.com`, it's an open redirect.

**Tools**
- Burp Repeater
- Manual testing

**Risk Rating**  
Medium

**Remediation**
- Validate redirect targets against a whitelist.
- Use relative paths instead of full URLs.
- Do not allow arbitrary external redirects.

---

## 21. INSECURE WEBSOCKET CONFIGURATION

**Description**  
WebSocket connections that do not enforce authentication or use weak origins can be abused to hijack sessions.

**What to Look For**
- WebSocket endpoints (ws:// or wss://) that accept connections without authentication.
- No origin validation.

**What to Ignore**
- Secure WebSockets with authentication and origin checks.

**How to Test with Burp Suite**
1. Intercept WebSocket traffic.
2. Try to connect from a different origin.
3. Attempt to send messages without authentication.

**Example**
```http
GET /ws HTTP/1.1
Upgrade: websocket
Origin: https://evil.com
```
If connection is allowed, origin validation is missing.

**Tools**
- Burp Suite (WebSocket support)
- Custom WebSocket clients

**Risk Rating**  
High

**Remediation**
- Require authentication for WebSocket connections.
- Validate the `Origin` header against a whitelist.
- Use wss:// (TLS) to encrypt traffic.

---

## 22. SERVER-SIDE INCLUDES (SSI) ENABLED

**Description**  
SSI directives can be used to execute commands or include files if user input is allowed in SSI contexts.

**What to Look For**
- Files with `.shtml` extension.
- Ability to inject `<!--#exec cmd="id" -->` and see output.

**What to Ignore**
- SSI disabled or not used.

**How to Test with Burp Suite**
1. Look for `.shtml` files or pages that might process SSI.
2. Attempt to inject SSI directives in parameters.
3. Observe if command output appears.

**Example**
```http
GET /page.shtml?name=<!--#exec cmd="id" -->
```
If command output appears, SSI is enabled and dangerous.

**Tools**
- Burp Repeater
- Manual fuzzing

**Risk Rating**  
High

**Remediation**
- Disable Server‑Side Includes unless absolutely necessary.
- If needed, sanitize user input and restrict directives.

---

## 23. UNRESTRICTED FILE UPLOAD CONFIGURATION

**Description**  
Allowing file uploads without proper restrictions can lead to code execution, malware hosting, or denial of service.

**What to Look For**
- No file type validation (only client‑side).
- Uploads stored in web‑accessible location.
- No size limits.

**What to Ignore**
- Server‑side validation of type, size, and safe storage outside webroot.

**How to Test with Burp Suite**
1. Upload a file with a dangerous extension (e.g., `.php`).
2. Attempt to access the uploaded file.
3. Try to upload very large files.

**Example**
```http
POST /upload
Content-Type: multipart/form-data

file: shell.php
```
If shell.php can be executed, configuration is insecure.

**Tools**
- Burp Repeater
- Custom file upload scripts

**Risk Rating**  
Critical

**Remediation**
- Validate file type (whitelist extensions, MIME types).
- Store uploaded files outside webroot.
- Set size limits and scan for malware.

---

## 24. MISSING RATE LIMITING CONFIGURATION

**Description**  
Absence of rate limiting allows attackers to brute force credentials, enumerate users, or perform denial of service.

**What to Look For**
- No throttling on login, password reset, or API endpoints.
- Ability to send thousands of requests without interruption.

**What to Ignore**
- Endpoints protected by rate limiting (by IP, user, or token).

**How to Test with Burp Suite**
1. Use Intruder or Turbo Intruder to send many requests.
2. Observe if any requests are rejected or delayed.

**Example**
```http
POST /login
username=admin&password=§word§
```
Send 100 attempts; if all succeed, no rate limiting.

**Tools**
- Burp Intruder
- Turbo Intruder

**Risk Rating**  
High

**Remediation**
- Implement rate limiting on all sensitive endpoints.
- Use progressive delays or CAPTCHA after failures.

---

## 25. INCORRECT HTTP CACHE HEADERS FOR SENSITIVE CONTENT

**Description**  
Sensitive responses (e.g., user data) cached by browsers or intermediate caches can be accessed by other users.

**What to Look For**
- Responses containing private data with `Cache-Control: public` or `max-age` set.
- Missing `Cache-Control: no-store, private`.

**What to Ignore**
- Proper cache headers: `Cache-Control: no-store, must-revalidate, private`.

**How to Test with Burp Suite**
1. Access a sensitive endpoint and check cache headers.
2. Try to access the same URL in a private/incognito window after the original user logged out.

**Example**
```http
Cache-Control: public, max-age=3600
```
Sensitive data may be cached.

**Tools**
- Burp Repeater
- Browser DevTools

**Risk Rating**  
Medium

**Remediation**
- Set `Cache-Control: no-store, private` for sensitive data.
- Use `Pragma: no-cache` for older browsers.

---

## 26. IMPROPERLY CONFIGURED CROSS-DOMAIN POLICY FILES (crossdomain.xml, clientaccesspolicy.xml)

**Description**  
These files control Flash and Silverlight access to resources. Overly permissive policies can allow cross‑domain data theft.

**What to Look For**
- `crossdomain.xml` with `<allow-access-from domain="*" />`.
- `clientaccesspolicy.xml` with `<allow-from http-request-headers="*">`.

**What to Ignore**
- Restrictive policies with specific allowed domains.

**How to Test with Burp Suite**
1. Request `/crossdomain.xml` and `/clientaccesspolicy.xml`.
2. Examine content for wildcard or overly broad permissions.

**Example**
```xml
<cross-domain-policy>
  <allow-access-from domain="*" />
</cross-domain-policy>
```
Any Flash movie can access resources.

**Tools**
- Burp Proxy
- Manual inspection

**Risk Rating**  
Medium

**Remediation**
- Restrict allowed domains to a whitelist.
- Remove the files if not needed.

---

## 27. INFORMATION DISCLOSURE VIA VERSION HEADERS

**Description**  
Headers like `X-Powered-By`, `X-AspNet-Version`, or `X-Generator` reveal technology stack details.

**What to Look For**
- Headers that include version numbers.
- Frameworks or libraries disclosed.

**What to Ignore**
- Headers stripped or generic.

**How to Test with Burp Suite**
1. Examine response headers.
2. Note any version information.

**Example**
```http
X-Powered-By: PHP/7.4.33
```
Reveals PHP version.

**Tools**
- Burp Proxy

**Risk Rating**  
Low

**Remediation**
- Remove or mask version details.
- Use `ServerTokens Prod` in Apache, or custom headers.

---

## 28. WEAK CRYPTOGRAPHY CONFIGURATION (E.G., ALLOW WEAK CIPHERS)

**Description**  
Allowing weak ciphers for TLS (RC4, DES, etc.) or using weak key exchange parameters (e.g., 1024‑bit RSA) can compromise encryption.

**What to Look For**
- Cipher suites with RC4, DES, 3DES.
- SSL/TLS protocols older than TLS 1.2.
- Short key lengths.

**What to Ignore**
- Strong ciphers with forward secrecy.

**How to Test with Burp Suite**
1. Use `testssl.sh` or `sslyze` to enumerate ciphers.
2. Check for weak ciphers.

**Example**
```
RC4-SHA: supported
```

**Tools**
- testssl.sh
- sslyze
- nmap `ssl-enum-ciphers`

**Risk Rating**  
High

**Remediation**
- Disable weak ciphers.
- Use only TLS 1.2 and 1.3 with strong cipher suites.

---

## 29. EXPOSED GIT OR VERSION CONTROL DIRECTORIES

**Description**  
Directories like `.git` that are publicly accessible can allow attackers to download the entire source code repository.

**What to Look For**
- Access to `/.git/config`, `/.git/HEAD`, `/.git/index`.
- Ability to download repository objects.

**What to Ignore**
- `.git` directory not exposed.

**How to Test with Burp Suite**
1. Request `/.git/config` and see if it returns file contents.
2. Use tools like `git-dumper` to clone repository.

**Example**
```http
GET /.git/config HTTP/1.1
```
If response contains `[core]` section, repository is exposed.

**Tools**
- GitTools
- git-dumper
- Dirb/Gobuster

**Risk Rating**  
Critical

**Remediation**
- Remove `.git` directory from production.
- Do not deploy source code to web‑accessible locations.

---

## 30. IMPROPERLY CONFIGURED FIREWALL RULES (E.G., OPEN PORTS)

**Description**  
Firewall rules that allow unnecessary inbound connections expose services to the internet.

**What to Look For**
- Ports open that should be internal-only (database, admin interfaces).
- No rate limiting or geo‑blocking.

**What to Ignore**
- Firewall rules that allow only necessary services.

**How to Test with Burp Suite**
1. Use Nmap to scan for open ports.
2. Identify services and determine if they should be accessible.

**Example**
```
nmap -p 22,80,443,3306 target.com
```
If 3306 (MySQL) is open, firewall rule is too permissive.

**Tools**
- Nmap
- Masscan
- Shodan

**Risk Rating**  
High

**Remediation**
- Implement firewall rules to allow only necessary ports.
- Restrict access to internal services via IP whitelisting or VPN.

---

## ✅ **SUMMARY**

Security misconfigurations are among the most common and preventable vulnerabilities. They occur when security settings are not defined, implemented, or maintained properly. This guide covers 30 configuration flaws that should be checked during assessments.

### **Key Testing Areas Summary**

| Misconfiguration | Key Indicators | Risk |
|------------------|----------------|------|
| Default Credentials | Admin panels with default passwords | Critical |
| Debug Mode | Stack traces, phpinfo | High-Critical |
| Directory Listing | Browsable directories | Medium-High |
| HTTP Methods | TRACE, PUT enabled | Medium |
| Error Messages | Stack traces, SQL errors | Medium-High |
| Security Headers | Missing CSP, HSTS, etc. | Medium-High |
| Outdated Software | Old version numbers | High-Critical |
| Cloud Storage | Public S3 buckets | Critical |
| Admin Interfaces | Public admin panels | High |
| Open Ports | Unnecessary services exposed | High |
| Weak TLS | Old protocols, weak ciphers | High |
| Unpatched Systems | Known CVEs | Critical |
| CORS | Wildcard with credentials | High |
| Version Headers | Disclosure of versions | Low-Medium |
| Sample Files | `/examples/`, `/demo/` | Medium-High |
| Backup Files | `.sql`, `.bak` accessible | Critical |
| Password Policies | Weak passwords allowed | Medium |
| Cookie Flags | Missing HttpOnly, Secure | Medium-High |
| File Permissions | Config files readable | High |
| Open Redirects | Unvalidated redirects | Medium |
| WebSockets | No origin validation | High |
| SSI | `.shtml` with command injection | High |
| File Upload | RCE via upload | Critical |
| Rate Limiting | No throttling | High |
| Cache Headers | Caching sensitive data | Medium |
| Cross‑Domain Policy | Wildcard permissions | Medium |
| Git Exposure | `.git` accessible | Critical |
| Firewall Rules | Unnecessary open ports | High |

### **Pro Tips for Testing Security Misconfiguration**
1. **Automate scanning** – Use tools like Nessus, OpenVAS, and Burp Scanner to detect common misconfigurations.
2. **Check default paths** – Always test for default installation files and admin panels.
3. **Review headers** – Examine HTTP headers for missing security flags and version leaks.
4. **Use fingerprinting** – Identify software versions to find known vulnerabilities.
5. **Test for exposed files** – Look for `.git`, `.env`, backup files, and configs.
6. **Audit cloud configurations** – Check S3 bucket permissions, IAM roles, and cloud storage.
7. **Verify firewall rules** – Ensure unnecessary ports are closed.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
