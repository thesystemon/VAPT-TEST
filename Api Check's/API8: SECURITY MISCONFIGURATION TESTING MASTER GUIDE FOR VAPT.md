# ⚙️ **API8: SECURITY MISCONFIGURATION TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into API Configuration Weaknesses*

---

## 📋 **TABLE OF CONTENTS**

1. [Missing HTTP Security Headers (CSP, HSTS, X‑Frame‑Options)](#1-missing-http-security-headers)
2. [Debug Mode Enabled in Production (Verbose Errors, Stack Traces)](#2-debug-mode-enabled-in-production)
3. [Default or Weak CORS Policy (`Access-Control-Allow-Origin: *`)](#3-default-or-weak-cors-policy)
4. [Unnecessary HTTP Methods Enabled (TRACE, OPTIONS, PUT, DELETE)](#4-unnecessary-http-methods-enabled)
5. [API Version Disclosure in Responses or Headers](#5-api-version-disclosure-in-responses-or-headers)
6. [Missing Rate Limiting on API Endpoints](#6-missing-rate-limiting-on-api-endpoints)
7. [Directory Listing Enabled on API Endpoints or Static Directories](#7-directory-listing-enabled-on-api-endpoints-or-static-directories)
8. [Default Credentials for API Documentation or Admin Panels](#8-default-credentials-for-api-documentation-or-admin-panels)
9. [Exposed API Documentation (Swagger, OpenAPI) Without Authentication](#9-exposed-api-documentation-swagger-openapi-without-authentication)
10. [Information Disclosure via Server Headers (`Server`, `X-Powered-By`)](#10-information-disclosure-via-server-headers)
11. [Missing `HttpOnly` and `Secure` Flags on Session Cookies](#11-missing-httponly-and-secure-flags-on-session-cookies)
12. [TLS/SSL Misconfiguration (Weak Ciphers, Old Protocols)](#12-tlsssl-misconfiguration-weak-ciphers-old-protocols)
13. [Caching of Sensitive API Responses (Missing `Cache-Control`)](#13-caching-of-sensitive-api-responses-missing-cache-control)
14. [Unprotected API Endpoints Behind Reverse Proxy (No Authentication)](#14-unprotected-api-endpoints-behind-reverse-proxy)
15. [Error Messages Exposing Internal Paths, SQL Queries, or Stack Traces](#15-error-messages-exposing-internal-paths-sql-queries-or-stack-traces)
16. [Cross‑Origin Resource Sharing (CORS) with `Access-Control-Allow-Credentials: true` and Wildcard Origin](#16-cors-with-wildcard-origin-and-credentials)
17. [Missing `SameSite` Attribute on Cookies](#17-missing-samesite-attribute-on-cookies)
18. [Exposed Environment or Configuration Files (`.env`, `.git`, `config.json`)](#18-exposed-environment-or-configuration-files)
19. [Verbose Error Messages in API Responses (e.g., `trace_id`, `exception`)](#19-verbose-error-messages-in-api-responses)
20. [Insecure API Key Transmission (Key in URL or Client‑Side Code)](#20-insecure-api-key-transmission)
21. [Missing `Content-Security-Policy` for API Responses (if HTML is returned)](#21-missing-content-security-policy-for-api-responses)
22. [Unprotected Admin or Internal API Endpoints Accessible from Internet](#22-unprotected-admin-or-internal-api-endpoints)
23. [Information Disclosure via Verbose HTTP Status Codes (e.g., 404 vs 403)](#23-information-disclosure-via-verbose-http-status-codes)
24. [Missing Security Patching (Outdated API Frameworks, Libraries)](#24-missing-security-patching)
25. [Improperly Configured Logging (Sensitive Data in Logs)](#25-improperly-configured-logging-sensitive-data-in-logs)
26. [Unnecessary Ports or Services Exposed on API Host](#26-unnecessary-ports-or-services-exposed-on-api-host)
27. [Insecure Deserialization Configuration (e.g., Java `ObjectInputStream` allowed)](#27-insecure-deserialization-configuration)
28. [Missing `X-Content-Type-Options: nosniff` Header](#28-missing-x-content-type-options-nosniff-header)
29. [Default or Weak API Rate Limit Configuration (e.g., Unlimited Requests)](#29-default-or-weak-api-rate-limit-configuration)
30. [No Security Scanning or Hardening in CI/CD Pipeline](#30-no-security-scanning-or-hardening-in-cicd-pipeline)

---

## 1. MISSING HTTP SECURITY HEADERS

**Description**  
Security headers (e.g., `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`) are often omitted in API responses, leaving the application vulnerable to clickjacking, MIME type sniffing, and protocol downgrade attacks.

**What to Look For**
- API responses missing `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`.
- Missing `Content-Security-Policy` (especially if the API returns HTML).

**What to Ignore**
- Properly configured headers for all responses.

**How to Test with Burp Suite**
1. Intercept any API response.
2. Check for presence of security headers.
3. Use Burp Scanner passive scan to report missing headers.

**Example**
```http
HTTP/1.1 200 OK
Content-Type: application/json
```
No security headers present.

**Tools**
- Burp Proxy
- Burp Scanner
- Securityheaders.com

**Risk Rating**  
Medium

**Remediation**
- Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
- Add `X-Frame-Options: DENY`.
- Add `X-Content-Type-Options: nosniff`.
- Add `Content-Security-Policy: default-src 'none'` for APIs.

---

## 2. DEBUG MODE ENABLED IN PRODUCTION (VERBOSE ERRORS, STACK TRACES)

**Description**  
Leaving debug mode enabled in production exposes stack traces, database queries, environment variables, and internal paths in error responses, aiding attackers.

**What to Look For**
- Error responses containing stack traces, SQL queries, or file paths.
- Headers like `X-Debug-Info`, `X-Debug-Token`, or `X-Powered-By` with versions.
- Endpoints like `/debug`, `/phpinfo`, `/health` that expose configuration.

**What to Ignore**
- Generic error messages (e.g., `{"error":"Internal Server Error"}`).

**How to Test with Burp Suite**
1. Trigger errors by sending malformed requests (e.g., invalid JSON, missing parameters).
2. Observe response for stack traces or verbose information.

**Example**
```json
{
  "error": "SQLSTATE[42S02]: Base table or view not found: 1146 Table 'prod.users' doesn't exist"
}
```

**Tools**
- Burp Repeater
- Burp Intruder (fuzzing)

**Risk Rating**  
High

**Remediation**
- Disable debug mode in production.
- Use generic error messages for clients.
- Log detailed errors server‑side only.

---

## 3. DEFAULT OR WEAK CORS POLICY (`ACCESS-CONTROL-ALLOW-ORIGIN: *`)

**Description**  
APIs with `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` allow any website to read sensitive data from authenticated API responses.

**What to Look For**
- Response headers: `Access-Control-Allow-Origin: *` or dynamic origin reflection.
- `Access-Control-Allow-Credentials: true`.

**What to Ignore**
- Strict allowlist of origins, no credentials with wildcard.

**How to Test with Burp Suite**
1. Send a request with a custom `Origin` header.
2. Check if the response reflects that origin and includes `Access-Control-Allow-Credentials: true`.

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

**Tools**
- Burp Repeater
- CORS scanner extensions

**Risk Rating**  
High

**Remediation**
- Configure a whitelist of allowed origins.
- Never use `*` with `Access-Control-Allow-Credentials: true`.
- Use `SameSite` cookie attributes.

---

## 4. UNNECESSARY HTTP METHODS ENABLED (TRACE, OPTIONS, PUT, DELETE)

**Description**  
Unnecessary HTTP methods (e.g., `TRACE`, `PUT`, `DELETE`) may be enabled without proper authentication, leading to information disclosure or resource manipulation.

**What to Look For**
- `TRACE` method returns the request body (XST attack).
- `PUT` or `DELETE` allowed without authentication.

**What to Ignore**
- Only `GET`, `POST`, and necessary methods with proper access controls.

**How to Test with Burp Suite**
1. Send `OPTIONS /api/endpoint` to see allowed methods.
2. Send `TRACE /api/endpoint` and observe if request is echoed.
3. Attempt `PUT` and `DELETE` without authentication.

**Example**
```http
OPTIONS /api/users HTTP/1.1
```
Response: `Allow: GET, POST, PUT, DELETE, TRACE`

**Tools**
- Burp Repeater
- Nmap `http-methods` script

**Risk Rating**  
Medium

**Remediation**
- Disable `TRACE` method.
- Disable unnecessary methods (`PUT`, `DELETE`) unless required and protected.

---

## 5. API VERSION DISCLOSURE IN RESPONSES OR HEADERS

**Description**  
API version information in headers (e.g., `X-API-Version`, `X-Powered-By`) or responses helps attackers target known vulnerabilities in specific versions.

**What to Look For**
- Headers like `X-API-Version: 1.2.3`, `X-Powered-By: Express`, `Server: nginx/1.18.0`.
- Version strings in JSON responses.

**What to Ignore**
- Version disclosure removed or generic.

**How to Test with Burp Suite**
1. Intercept API responses and examine headers.
2. Look for version strings in response bodies (e.g., `"version": "1.0"`).

**Example**
```http
Server: nginx/1.18.0
X-Powered-By: PHP/7.4.33
```

**Tools**
- Burp Proxy
- Wappalyzer

**Risk Rating**  
Low to Medium

**Remediation**
- Remove version headers or use generic values (e.g., `Server: nginx`).
- Do not expose version numbers in responses.

---

## 6. MISSING RATE LIMITING ON API ENDPOINTS

**Description**  
APIs without rate limiting allow brute force attacks, credential stuffing, and denial of service.

**What to Look For**
- No `X-RateLimit-*` headers in responses.
- Ability to send many requests without `429` status.

**What to Ignore**
- Rate limiting implemented (e.g., 100 req/min).

**How to Test with Burp Suite**
1. Use Intruder to send 100 requests to the endpoint.
2. If all return `200 OK`, rate limiting is missing.

**Example**
```http
POST /api/login HTTP/1.1
```
100 requests, no `429` responses.

**Tools**
- Burp Intruder
- Turbo Intruder

**Risk Rating**  
High

**Remediation**
- Implement rate limiting per IP, per API key, or per user.
- Return `429 Too Many Requests` with `Retry-After`.

---

## 7. DIRECTORY LISTING ENABLED ON API ENDPOINTS OR STATIC DIRECTORIES

**Description**  
Directory listing on API static directories (e.g., `/static`, `/uploads`) can expose sensitive files or API documentation.

**What to Look For**
- Accessing a directory returns an HTML listing of files.
- No `index.html` or default page.

**What to Ignore**
- Directories returning `403 Forbidden` or `404 Not Found`.

**How to Test with Burp Suite**
1. Request `/api/static/`, `/uploads/`, `/docs/`.
2. Check if file listing is returned.

**Example**
```http
GET /api/docs/ HTTP/1.1
```
Response contains list of JSON files.

**Tools**
- Dirb/Gobuster
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Disable directory listing in web server configuration.
- Place `index.html` or deny access.

---

## 8. DEFAULT CREDENTIALS FOR API DOCUMENTATION OR ADMIN PANELS

**Description**  
API documentation (Swagger, Redoc) or admin panels left with default credentials allow attackers to access sensitive API information.

**What to Look For**
- Accessible `/swagger`, `/api-docs`, `/admin` without authentication.
- Default username/password (e.g., `admin/admin`) still active.

**What to Ignore**
- Protected documentation and admin panels.

**How to Test with Burp Suite**
1. Access common documentation paths: `/swagger`, `/api-docs`, `/redoc`.
2. Try default credentials: `admin/admin`, `admin/password`.

**Example**
```http
GET /swagger/index.html HTTP/1.1
```
If Swagger UI loads without login, vulnerable.

**Tools**
- Dirb/Gobuster
- Burp Intruder (default credentials)

**Risk Rating**  
Critical

**Remediation**
- Secure API documentation with authentication.
- Change default credentials.

---

## 9. EXPOSED API DOCUMENTATION (SWAGGER, OPENAPI) WITHOUT AUTHENTICATION

**Description**  
Unprotected OpenAPI/Swagger documentation reveals all API endpoints, parameters, and sometimes example values, aiding attackers.

**What to Look For**
- Accessible `/swagger.json`, `/openapi.json`, `/swagger-ui/`.
- No authentication or IP whitelisting.

**What to Ignore**
- Documentation protected by API keys or login.

**How to Test with Burp Suite**
1. Request common OpenAPI paths: `/swagger/v1/swagger.json`, `/api-docs`, `/v3/api-docs`.
2. If JSON is returned, documentation is exposed.

**Example**
```http
GET /swagger/v1/swagger.json HTTP/1.1
```
Returns full API specification.

**Tools**
- Burp Repeater
- Dirb/Gobuster

**Risk Rating**  
High

**Remediation**
- Protect API documentation with authentication.
- Restrict access to internal networks or via VPN.

---

## 10. INFORMATION DISCLOSURE VIA SERVER HEADERS (`SERVER`, `X-POWERED-BY`)

**Description**  
Headers like `Server`, `X-Powered-By`, `X-AspNet-Version` reveal software versions that may have known vulnerabilities.

**What to Look For**
- Headers disclosing exact versions (e.g., `Server: Apache/2.4.18`).

**What to Ignore**
- Headers stripped or generic.

**How to Test with Burp Suite**
1. Inspect response headers.
2. Note any version information.

**Example**
```http
Server: Apache/2.4.49 (Ubuntu)
X-Powered-By: PHP/7.4.33
```

**Tools**
- Burp Proxy

**Risk Rating**  
Low

**Remediation**
- Remove or mask version details (e.g., `Server: nginx`).
- Use `ServerTokens Prod` in Apache, or custom headers.

---

## 11. MISSING `HTTPONLY` AND `SECURE` FLAGS ON SESSION COOKIES

**Description**  
Session cookies without `HttpOnly` are accessible to JavaScript (XSS risk). Without `Secure`, they may be sent over HTTP.

**What to Look For**
- `Set-Cookie` header missing `HttpOnly`, `Secure`, or `SameSite`.

**What to Ignore**
- Cookies with all flags properly set.

**How to Test with Burp Suite**
1. Intercept responses that set session cookies.
2. Check for `HttpOnly`, `Secure`, `SameSite`.

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

## 12. TLS/SSL MISCONFIGURATION (WEAK CIPHERS, OLD PROTOCOLS)

**Description**  
Weak TLS configurations allow attackers to downgrade connections or decrypt traffic.

**What to Look For**
- Support for SSLv2, SSLv3, TLS 1.0, TLS 1.1.
- Weak cipher suites (RC4, DES, 3DES).

**What to Ignore**
- TLS 1.2 and 1.3 only, with strong ciphers.

**How to Test with Burp Suite**
1. Use `testssl.sh` or `sslyze` to scan.
2. Burp Scanner can detect weak SSL configurations.

**Example**
```bash
testssl.sh --cipher-per-proto api.target.com
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
- Configure strong cipher suites (ECDHE+AES-GCM).

---

## 13. CACHING OF SENSITIVE API RESPONSES (MISSING `CACHE-CONTROL`)

**Description**  
Sensitive API responses (e.g., user data, tokens) cached by browsers or CDNs can be exposed to other users.

**What to Look For**
- Responses containing sensitive data with `Cache-Control: public` or `max-age`.
- Missing `Cache-Control: no-store, private`.

**What to Ignore**
- Proper cache headers for sensitive data.

**How to Test with Burp Suite**
1. Access a sensitive endpoint and check cache headers.
2. Try to access the same URL from another session after logout.

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

## 14. UNPROTECTED API ENDPOINTS BEHIND REVERSE PROXY (NO AUTHENTICATION)

**Description**  
API endpoints intended for internal use may be exposed to the internet without authentication due to misconfigured reverse proxy.

**What to Look For**
- Endpoints like `/internal/`, `/admin/`, `/metrics` accessible without authentication.
- No IP whitelisting or API key.

**What to Ignore**
- Properly protected internal endpoints.

**How to Test with Burp Suite**
1. Use forced browsing to discover internal paths.
2. Attempt to access them without any token.

**Example**
```http
GET /internal/health HTTP/1.1
```
If health data is returned, vulnerable.

**Tools**
- Dirb/Gobuster
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Require authentication for all endpoints.
- Use network segmentation and IP whitelisting.

---

## 15. ERROR MESSAGES EXPOSING INTERNAL PATHS, SQL QUERIES, OR STACK TRACES

**Description**  
Verbose error messages reveal internal paths, database queries, or stack traces, aiding attackers.

**What to Look For**
- Stack traces in JSON responses.
- SQL errors with table names.
- File paths (e.g., `/var/www/html/...`).

**What to Ignore**
- Generic error messages.

**How to Test with Burp Suite**
1. Send malformed requests to trigger errors.
2. Examine responses for sensitive information.

**Example**
```json
{"error": "SQLSTATE[42S02]: Table 'prod.user_passwords' doesn't exist"}
```

**Tools**
- Burp Repeater
- Burp Intruder (fuzzing)

**Risk Rating**  
High

**Remediation**
- Use generic error messages for clients.
- Log detailed errors server‑side.

---

## 16. CORS WITH WILDCARD ORIGIN AND CREDENTIALS

**Description**  
CORS misconfiguration that allows any origin with credentials leads to cross‑origin data theft.

**What to Look For**
- `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.
- Dynamic origin reflection without validation.

**What to Ignore**
- Strict allowlist and no credentials with wildcard.

**How to Test with Burp Suite**
1. Send request with `Origin: https://evil.com`.
2. Check if response reflects origin and includes credentials flag.

**Example**
```http
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Whitelist allowed origins.
- Never use `*` with credentials.

---

## 17. MISSING `SAMESITE` ATTRIBUTE ON COOKIES

**Description**  
Cookies without `SameSite` attribute are more vulnerable to CSRF attacks.

**What to Look For**
- `Set-Cookie` header missing `SameSite`.
- Cookies that are sent with cross‑site requests.

**What to Ignore**
- `SameSite=Lax` or `Strict` set.

**How to Test with Burp Suite**
1. Intercept responses setting cookies.
2. Check for `SameSite` attribute.

**Example**
```http
Set-Cookie: session=abc123; Path=/
```
Missing `SameSite`.

**Tools**
- Burp Proxy

**Risk Rating**  
Medium

**Remediation**
- Set `SameSite=Lax` for session cookies.
- Use `SameSite=Strict` for sensitive cookies.

---

## 18. EXPOSED ENVIRONMENT OR CONFIGURATION FILES (`.ENV`, `.GIT`, `CONFIG.JSON`)

**Description**  
Sensitive files like `.env`, `.git`, `config.json` exposed via web server misconfiguration can leak secrets.

**What to Look For**
- Accessible `.env` file with database passwords.
- Exposed `.git` directory allowing source code download.

**What to Ignore**
- Files not accessible.

**How to Test with Burp Suite**
1. Request `/`, `.env`, `/config.json`, `/production.yml`.
2. Check if files are served.

**Example**
```http
GET /.env HTTP/1.1
```
Returns `DB_PASSWORD=secret`.

**Tools**
- Dirb/Gobuster
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Store configuration files outside webroot.
- Use environment variables or secret management.

---

## 19. VERBOSE ERROR MESSAGES IN API RESPONSES (E.G., `TRACE_ID`, `EXCEPTION`)

**Description**  
Error responses containing `trace_id`, `exception` class names, or internal request IDs can aid attackers.

**What to Look For**
- JSON responses with `"trace_id"`, `"exception": "SQLException"`.
- Internal correlation IDs that can be used for enumeration.

**What to Ignore**
- Generic error messages.

**How to Test with Burp Suite**
1. Send invalid input to cause errors.
2. Look for internal identifiers in responses.

**Example**
```json
{"error": "Internal Server Error", "trace_id": "e8f2a1b3"}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Low to Medium

**Remediation**
- Do not expose internal identifiers to clients.
- Use generic error messages.

---

## 20. INSECURE API KEY TRANSMISSION (KEY IN URL OR CLIENT‑SIDE CODE)

**Description**  
API keys transmitted in URLs can be logged, leaked via Referer header, or stored in browser history. Keys in client‑side code are publicly visible.

**What to Look For**
- API keys in query parameters: `?api_key=123456`.
- Keys in JavaScript files, HTML comments, or source maps.

**What to Ignore**
- Keys in `Authorization` headers only.

**How to Test with Burp Suite**
1. Search for `api_key`, `key`, `token` in URLs.
2. View page source and JS files for hardcoded keys.

**Example**
```html
<script>const API_KEY = "sk_live_abc123";</script>
```

**Tools**
- Burp Proxy
- Browser DevTools

**Risk Rating**  
Critical

**Remediation**
- Never expose API keys in URLs or client‑side code.
- Use `Authorization` headers.

---

## 21. MISSING `CONTENT-SECURITY-POLICY` FOR API RESPONSES (IF HTML IS RETURNED)

**Description**  
If the API returns HTML (e.g., error pages), missing CSP allows XSS attacks.

**What to Look For**
- API endpoints that return HTML content (e.g., error pages, documentation).
- No `Content-Security-Policy` header.

**What to Ignore**
- APIs that return only JSON/XML with CSP.

**How to Test with Burp Suite**
1. Check content type of responses.
2. If HTML, verify CSP header presence.

**Example**
```html
HTTP/1.1 404 Not Found
Content-Type: text/html
```
No CSP.

**Tools**
- Burp Proxy

**Risk Rating**  
Medium

**Remediation**
- Set `Content-Security-Policy: default-src 'none'` for API HTML responses.

---

## 22. UNPROTECTED ADMIN OR INTERNAL API ENDPOINTS ACCESSIBLE FROM INTERNET

**Description**  
Admin APIs or internal endpoints exposed to the internet without authentication allow attackers to perform privileged actions.

**What to Look For**
- Endpoints like `/api/admin`, `/v1/internal`, `/system/config` accessible without token.
- No IP whitelisting or authentication.

**What to Ignore**
- Properly protected admin APIs.

**How to Test with Burp Suite**
1. Discover admin paths via forced browsing or documentation.
2. Access them with a regular user token or no token.

**Example**
```http
GET /api/admin/users HTTP/1.1
```
Returns user list.

**Tools**
- Dirb/Gobuster
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Require authentication for all admin endpoints.
- Use network segmentation (VPN, IP whitelist).

---

## 23. INFORMATION DISCLOSURE VIA VERBOSE HTTP STATUS CODES (E.G., 404 VS 403)

**Description**  
Different status codes for missing resources (404) vs forbidden resources (403) can leak information.

**What to Look For**
- 404 for non‑existent resources, 403 for existing but forbidden resources.
- Attackers can enumerate valid resources.

**What to Ignore**
- Uniform error responses (e.g., always 404 or 403).

**How to Test with Burp Suite**
1. Request a non‑existent resource (e.g., `/api/user/99999`).
2. Request an existing resource you cannot access.
3. If status codes differ, enumeration is possible.

**Example**
- `/api/user/99999` → 404
- `/api/user/123` → 403 (existing user)

**Tools**
- Burp Intruder

**Risk Rating**  
Medium

**Remediation**
- Return generic status codes (e.g., always 404 for both missing and forbidden).

---

## 24. MISSING SECURITY PATCHING (OUTDATED API FRAMEWORKS, LIBRARIES)

**Description**  
Using outdated API frameworks or libraries with known vulnerabilities exposes the API to exploits.

**What to Look For**
- Framework versions in headers (`X-Powered-By: Express/4.17.1`).
- Old library versions in `package-lock.json` or similar exposed files.

**What to Ignore**
- Up‑to‑date software.

**How to Test with Burp Suite**
1. Identify framework from headers or error messages.
2. Check CVE databases for known vulnerabilities.

**Example**
```http
X-Powered-By: Express/4.17.1
```
Express 4.17.1 has known vulnerabilities.

**Tools**
- Wappalyzer
- Burp Scanner
- Nuclei

**Risk Rating**  
Critical

**Remediation**
- Keep all software and libraries updated.
- Use automated dependency scanning.

---

## 25. IMPROPERLY CONFIGURED LOGGING (SENSITIVE DATA IN LOGS)

**Description**  
Logging sensitive data (passwords, tokens, PII) violates compliance and exposes data if logs are compromised.

**What to Look For**
- Logs containing plaintext passwords, session tokens, or credit card numbers.
- Accessible log files.

**What to Ignore**
- Logs sanitised of sensitive data.

**How to Test with Burp Suite**
1. If logs are accessible (e.g., `/logs/`), search for `password`, `token`, `Authorization`.
2. Trigger a request and ask for log access (if possible).

**Example**
```
2024-01-01 12:00:00 POST /api/login - password=secret123
```

**Tools**
- Burp Proxy (if logs exposed)
- Log review

**Risk Rating**  
High

**Remediation**
- Never log passwords, tokens, or PII.
- Use log redaction or masking.

---

## 26. UNNECESSARY PORTS OR SERVICES EXPOSED ON API HOST

**Description**  
Open ports and services (e.g., SSH, Redis, MySQL) on the API host increase the attack surface.

**What to Look For**
- Ports open that are not needed (e.g., 22, 3306, 6379).
- Services running on default ports without firewall restrictions.

**What to Ignore**
- Only necessary ports open.

**How to Test with Burp Suite**
1. Use Nmap to scan for open ports.
2. Identify services on those ports.

**Example**
```
nmap -p- api.target.com
```
Open ports: 22 (SSH), 80, 443, 3306 (MySQL).

**Tools**
- Nmap
- Masscan

**Risk Rating**  
High

**Remediation**
- Close unnecessary ports.
- Use firewalls to restrict access.

---

## 27. INSECURE DESERIALIZATION CONFIGURATION (E.G., JAVA `OBJECTINPUTSTREAM` ALLOWED)

**Description**  
APIs that accept serialized Java objects (or other languages) without validation are vulnerable to deserialisation attacks.

**What to Look For**
- Content-Type `application/x-java-serialized-object`.
- Base64‑encoded binary blobs in requests.

**What to Ignore**
- JSON or XML only with schema validation.

**How to Test with Burp Suite**
1. Identify serialised data patterns (e.g., `ACED0005` for Java).
2. Use `ysoserial` to generate payloads and test.

**Example**
```http
POST /api/deserialize HTTP/1.1
Content-Type: application/x-java-serialized-object
```
Payload: `rO0ABXNy...`

**Tools**
- Burp Repeater
- ysoserial

**Risk Rating**  
Critical

**Remediation**
- Avoid deserialising untrusted data.
- Use safe formats (JSON) with validation.

---

## 28. MISSING `X-CONTENT-TYPE-OPTIONS: NOSNIFF` HEADER

**Description**  
Missing `X-Content-Type-Options: nosniff` allows browsers to “sniff” MIME types, potentially leading to XSS if an API returns HTML content.

**What to Look For**
- Responses missing `X-Content-Type-Options: nosniff`.
- API endpoints that return user‑controlled content.

**What to Ignore**
- Header present.

**How to Test with Burp Suite**
1. Intercept any response and check for the header.

**Example**
```http
HTTP/1.1 200 OK
Content-Type: application/json
```
Missing `X-Content-Type-Options`.

**Tools**
- Burp Proxy

**Risk Rating**  
Low

**Remediation**
- Add `X-Content-Type-Options: nosniff` to all responses.

---

## 29. DEFAULT OR WEAK API RATE LIMIT CONFIGURATION (E.G., UNLIMITED REQUESTS)

**Description**  
APIs with no rate limiting or very high limits are vulnerable to brute force and DoS.

**What to Look For**
- No `429` responses after many requests.
- Rate limit headers missing or set to very high values.

**What to Ignore**
- Reasonable rate limits (e.g., 100 req/min).

**How to Test with Burp Suite**
1. Send 200 requests quickly using Turbo Intruder.
2. Observe if any are blocked.

**Example**
- 200 requests all return `200 OK`.

**Tools**
- Turbo Intruder

**Risk Rating**  
High

**Remediation**
- Configure rate limits appropriate for each endpoint.
- Return `429 Too Many Requests`.

---

## 30. NO SECURITY SCANNING OR HARDENING IN CI/CD PIPELINE

**Description**  
Lack of automated security testing in the CI/CD pipeline allows misconfigurations to reach production.

**What to Look For**
- No SAST, DAST, or dependency scanning in the build process.
- Manual deployment without security checks.

**What to Ignore**
- Security scanning integrated.

**How to Test with Burp Suite**
- This is a process review. Indicators include the presence of multiple misconfigurations that should have been caught by automated scanning.

**Example**
- Production API has debug mode enabled, missing security headers, exposed .env file.

**Tools**
- Process review
- CI/CD configuration inspection

**Risk Rating**  
High

**Remediation**
- Integrate SAST, DAST, and dependency scanning into CI/CD.
- Use infrastructure‑as‑code security scanners.

---

## ✅ **SUMMARY**

Security Misconfiguration (API8) is one of the most common API vulnerabilities, often caused by default settings, verbose errors, missing security headers, and exposed configuration files. This guide covers 30 misconfiguration issues.

### **Key Testing Areas Summary**

| Misconfiguration | Key Indicators | Risk |
|------------------|----------------|------|
| Missing Security Headers | No CSP, HSTS, XFO | Medium |
| Debug Mode | Stack traces, SQL errors | High |
| Weak CORS | `*` with credentials | High |
| Unnecessary HTTP Methods | `TRACE`, `PUT`, `DELETE` | Medium |
| Version Disclosure | `Server`, `X-Powered-By` | Low-Medium |
| Missing Rate Limiting | No `429` responses | High |
| Directory Listing | Browsable directories | Medium |
| Default Credentials | Admin/admin still works | Critical |
| Exposed API Docs | Swagger without auth | High |
| Verbose Error Messages | Paths, SQL, stack traces | High |
| Insecure Cookie Flags | No `HttpOnly`, `Secure` | High |
| Weak TLS | Old protocols, weak ciphers | High |
| Sensitive Caching | `Cache-Control: public` | Medium |
| Unprotected Internal Endpoints | `/internal`, `/admin` | Critical |
| Exposed Config Files | `.env`, `.git` | Critical |
| CORS with Credentials | `*` + `credentials: true` | High |
| Missing `SameSite` | No SameSite attribute | Medium |
| Insecure API Key Transmission | Key in URL/client | Critical |
| Missing CSP | HTML responses without CSP | Medium |
| Verbose Status Codes | 404 vs 403 | Medium |
| Outdated Software | Old framework versions | Critical |
| Sensitive Data in Logs | Passwords logged | High |
| Unnecessary Ports | MySQL, Redis exposed | High |
| Insecure Deserialisation | Java serialised objects | Critical |
| Missing `nosniff` | No X‑Content‑Type‑Options | Low |
| Weak Rate Limit | Unlimited requests | High |
| No CI/CD Security Scanning | Misconfigs reach production | High |

### **Pro Tips for Testing Security Misconfiguration**
1. **Use Burp Scanner** – passive and active scans detect many misconfigurations.
2. **Check all headers** – look for missing security headers, version disclosure.
3. **Enumerate directories** – find exposed admin panels, documentation, config files.
4. **Test rate limiting** – send bursts of requests to see if `429` is returned.
5. **Review error messages** – trigger errors and look for stack traces or SQL queries.
6. **Test CORS** – use custom `Origin` headers to check for reflection.
7. **Automate with Nuclei** – many misconfiguration templates are available.

---

*This guide is for professional security testing purposes only. Unauthorised testing is illegal.*
