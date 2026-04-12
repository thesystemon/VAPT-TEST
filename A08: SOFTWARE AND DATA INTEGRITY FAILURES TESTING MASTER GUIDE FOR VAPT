# 🛡️ **A08: SOFTWARE AND DATA INTEGRITY FAILURES TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Integrity Compromises*

---

## 📋 **TABLE OF CONTENTS**

1. [Insecure Deserialization (Java, .NET, PHP, Python, Ruby)](#1-insecure-deserialization-java-net-php-python-ruby)
2. [Deserialization of Untrusted Data (Pickle, Yaml, JSON)](#2-deserialization-of-untrusted-data-pickle-yaml-json)
3. [Insufficient Integrity Checks on Software Updates](#3-insufficient-integrity-checks-on-software-updates)
4. [Missing Code Signing or Signature Validation](#4-missing-code-signing-or-signature-validation)
5. [Insecure CI/CD Pipelines (Unverified Artifacts)](#5-insecure-cicd-pipelines-unverified-artifacts)
6. [Dependency Confusion / Supply Chain Attacks](#6-dependency-confusion--supply-chain-attacks)
7. [Typosquatting in Package Dependencies](#7-typosquatting-in-package-dependencies)
8. [Insecure Third-Party CDN Resources (SRI Missing)](#8-insecure-third-party-cdn-resources-sri-missing)
9. [Unverified Integrity of Configuration Files](#9-unverified-integrity-of-configuration-files)
10. [Lack of Subresource Integrity (SRI) for JavaScript/CSS](#10-lack-of-subresource-integrity-sri-for-javascriptcss)
11. [Insecure File Upload (No Integrity Verification)](#11-insecure-file-upload-no-integrity-verification)
12. [Unprotected Integrity of Critical Data in Transit (e.g., Financial Transactions)](#12-unprotected-integrity-of-critical-data-in-transit)
13. [Missing Checksums or Hash Verification for Downloads](#13-missing-checksums-or-hash-verification-for-downloads)
14. [Insecure Use of JavaScript `eval()` or `innerHTML`](#14-insecure-use-of-javascript-eval-or-innerhtml)
15. [Prototype Pollution in JavaScript Applications](#15-prototype-pollution-in-javascript-applications)
16. [Insecure Deserialization in Mobile Apps (Android, iOS)](#16-insecure-deserialization-in-mobile-apps-android-ios)
17. [Lack of Integrity Protection for Database Records (e.g., No Audit Trails)](#17-lack-of-integrity-protection-for-database-records)
18. [Unverified API Responses (No Signature Validation)](#18-unverified-api-responses-no-signature-validation)
19. [Insecure Handling of JWT Signatures (Algorithm Confusion)](#19-insecure-handling-of-jwt-signatures-algorithm-confusion)
20. [Dependency Verification Failure (No `package-lock.json`, `composer.lock`)](#20-dependency-verification-failure-no-package-lockjson-composerlock)
21. [Insecure Code Integrity Checks (Bypassable Integrity Mechanisms)](#21-insecure-code-integrity-checks-bypassable-integrity-mechanisms)
22. [Unverified Sideloaded Updates (Mobile, Desktop Apps)](#22-unverified-sideloaded-updates-mobile-desktop-apps)
23. [Missing Integrity Checks for Serverless Functions](#23-missing-integrity-checks-for-serverless-functions)
24. [Insecure Container Image Signing (Docker Content Trust)](#24-insecure-container-image-signing-docker-content-trust)
25. [Unverified Integrity of Logs (Log Forging/Tampering)](#25-unverified-integrity-of-logs-log-forgingtampering)
26. [Lack of Cryptographic Signatures for Configuration Files](#26-lack-of-cryptographic-signatures-for-configuration-files)
27. [Insecure Deserialization in WebSocket Messages](#27-insecure-deserialization-in-websocket-messages)
28. [Unverified Integrity of Third-Party Libraries (SRI for CSS/JS)](#28-unverified-integrity-of-third-party-libraries-sri-for-cssjs)
29. [Insecure Data Integrity Validation (e.g., No HMAC on Cookies)](#29-insecure-data-integrity-validation-no-hmac-on-cookies)
30. [Missing Software Bill of Materials (SBOM) and Provenance Verification](#30-missing-software-bill-of-materials-sbom-and-provenance-verification)

---

## 1. INSECURE DESERIALIZATION (JAVA, .NET, PHP, PYTHON, RUBY)

**Description**  
Deserialization of untrusted data can lead to remote code execution, privilege escalation, and denial of service. Attackers craft malicious serialized objects that, when deserialized, execute arbitrary code.

**What to Look For**
- Serialized data formats (Java `ObjectInputStream`, PHP `unserialize`, Python `pickle`, .NET `BinaryFormatter`, Ruby `Marshal`).
- Base64-encoded or binary payloads in cookies, POST bodies, or hidden fields.
- Use of dangerous deserialization methods.

**What to Ignore**
- Deserialization of trusted data only, or use of safe formats (JSON) with schema validation.

**How to Test with Burp Suite**
1. Identify serialized data patterns (e.g., `O:4:"User":2:{...}` for PHP, `ACED0005` for Java, `80|` for Python pickle).
2. Use tools like `ysoserial` to generate payloads.
3. Inject payload into parameters and observe for errors, delays, or command execution.
4. Use Burp extensions like **Java Deserializer Scanner**.

**Example**
```http
Cookie: user=O:4:"User":1:{s:8:"username";s:5:"admin";}
```
Modify to inject gadget chain.

**Tools**
- ysoserial (Java, .NET)
- PHP Generic Gadget Chains (PHPGGC)
- Burp extensions (Java Deserializer, PHP Object Injection Checker)

**Risk Rating**  
Critical

**Remediation**
- Avoid deserializing untrusted data.
- Use safe data formats (JSON, XML) with strict schema validation.
- Implement integrity checks (HMAC) on serialized objects.

---

## 2. DESERIALIZATION OF UNTRUSTED DATA (PICKLE, YAML, JSON)

**Description**  
Many languages have unsafe deserialization libraries (Python `pickle`, Ruby `YAML.load`, JavaScript `eval` on JSON). Attackers can execute code via crafted payloads.

**What to Look For**
- Use of `pickle.loads()` on user input.
- Use of `YAML.load()` (Ruby) or `yaml.load()` (Python) without safe loader.
- `eval()` used to parse JSON or configuration.

**What to Ignore**
- Safe alternatives: `json.loads()`, `yaml.safe_load()`, `pickle` only on trusted data.

**How to Test with Burp Suite**
1. Send a Python pickle payload: `cbuiltins\neval\np0\n(S'print(1)'\np1\ntp2\nRp3\n.`
2. Send a YAML payload: `!!ruby/object:Gem::Installer { "i": "touch /tmp/foo" }`
3. Observe if command executes or errors differ.

**Example**
```yaml
!!python/object/new:os.system ["id"]
```

**Tools**
- ysoserial (for Python pickle)
- Ruby YAML deserialization tools
- Burp Repeater with custom payloads

**Risk Rating**  
Critical

**Remediation**
- Use safe deserialization methods (e.g., `yaml.safe_load`, `json.loads`).
- Never deserialize untrusted data with `pickle`, `eval`, or `YAML.load`.

---

## 3. INSUFFICIENT INTEGRITY CHECKS ON SOFTWARE UPDATES

**Description**  
Software update mechanisms that do not verify the integrity and authenticity of updates allow attackers to distribute malicious updates.

**What to Look For**
- Updates downloaded over HTTP without signature validation.
- No code signing or hash verification.
- Updates from unauthenticated sources.

**What to Ignore**
- Updates signed with strong keys, validated over HTTPS, and hash-checked.

**How to Test with Burp Suite**
1. Intercept an update request.
2. Replace the update file with a malicious file (same name).
3. If the client installs it, integrity check is missing.

**Example**
```http
GET /update/latest.exe HTTP/1.1
```
If response is served without signature, vulnerable.

**Tools**
- Burp Proxy (intercept and modify)
- Custom update server simulator

**Risk Rating**  
Critical

**Remediation**
- Use code signing and verify signatures before installation.
- Serve updates over HTTPS with hash verification.

---

## 4. MISSING CODE SIGNING OR SIGNATURE VALIDATION

**Description**  
Code signing ensures that software comes from a trusted source and has not been tampered with. Without it, attackers can replace binaries.

**What to Look For**
- No digital signature on executables, libraries, or updates.
- Signature not validated by the application.

**What to Ignore**
- Signed binaries with verified certificate chain.

**How to Test with Burp Suite**
1. Download an executable or update file.
2. Check for digital signature (Windows: right-click → Properties → Digital Signatures).
3. Use `sigcheck` or `osslsigncode` to verify.

**Example**
```bash
sigcheck -a target.exe
```
If no signature, vulnerable.

**Tools**
- sigcheck (Sysinternals)
- osslsigncode

**Risk Rating**  
High to Critical

**Remediation**
- Sign all binaries with a trusted certificate.
- Validate signatures at runtime before executing.

---

## 5. INSECURE CI/CD PIPELINES (UNVERIFIED ARTIFACTS)

**Description**  
CI/CD pipelines that pull dependencies or build artifacts from untrusted sources without verification can introduce malicious code.

**What to Look For**
- Use of third-party actions (GitHub Actions) without hash pinning.
- No verification of artifact integrity.
- Unauthenticated artifact repositories.

**What to Ignore**
- Pinned hashes, signed artifacts, and verified sources.

**How to Test with Burp Suite**
1. Review CI/CD configuration files (`.github/workflows/*.yml`, `.gitlab-ci.yml`).
2. Look for `curl | bash` patterns or `wget` without checksum.
3. Check if third-party actions are pinned by commit hash.

**Example**
```yaml
- uses: third-party/action@v1  # not pinned to commit hash
```

**Tools**
- Manual code review
- CI/CD security scanners (e.g., Trivy, Checkov)

**Risk Rating**  
High

**Remediation**
- Pin actions and dependencies to specific hashes.
- Verify artifact signatures.
- Use private, authenticated artifact repositories.

---

## 6. DEPENDENCY CONFUSION / SUPPLY CHAIN ATTACKS

**Description**  
Dependency confusion occurs when a private package name is also available in a public repository, and the build system pulls the public (malicious) version instead.

**What to Look For**
- Internal packages with names that exist in public registries (npm, PyPI, Maven Central).
- No scoping or private registry configuration.

**What to Ignore**
- Scoped packages or private registry with explicit priority.

**How to Test with Burp Suite**
1. Identify internal package names from `package.json`, `requirements.txt`, etc.
2. Check if the same name exists in the public registry.
3. Attempt to publish a malicious package with the same name (requires permission, not for real testing). Instead, verify configuration.

**Example**
```json
"dependencies": {
  "internal-lib": "1.0.0"
}
```
If `internal-lib` exists on npm, confusion possible.

**Tools**
- npm, pip, mvn CLI
- Dependency confusion scanners

**Risk Rating**  
Critical

**Remediation**
- Use scoped packages (`@company/package`) or private registries.
- Configure package managers to prefer private registries.

---

## 7. TYPOSQUATTING IN PACKAGE DEPENDENCIES

**Description**  
Attackers publish packages with names similar to popular libraries (e.g., `request` vs `requeset`). Developers may accidentally install the wrong package.

**What to Look For**
- Dependencies with unusual spellings or typos.
- Dependencies from unfamiliar authors.

**What to Ignore**
- Well-known, widely used packages with high download counts.

**How to Test with Burp Suite**
1. Review `package.json`, `requirements.txt`, etc., for suspicious package names.
2. Cross-check with official package names.

**Example**
```json
"dependencies": {
  "expressjs": "1.0.0"
}
```
Correct name is `express`.

**Tools**
- Manual inspection
- Package vulnerability scanners (Snyk, OWASP Dependency-Check)

**Risk Rating**  
High

**Remediation**
- Double-check package names before installing.
- Use lockfiles (`package-lock.json`) and verify integrity.

---

## 8. INSECURE THIRD-PARTY CDN RESOURCES (SRI MISSING)

**Description**  
Third-party resources (CDN) without Subresource Integrity (SRI) can be compromised; the attacker modifies the script and all sites using it are affected.

**What to Look For**
- External scripts or stylesheets without `integrity` attribute.
- CDN resources loaded over HTTP.

**What to Ignore**
- Resources with `integrity` attribute and `crossorigin` set.

**How to Test with Burp Suite**
1. Inspect HTML for `<script src="https://cdn.example.com/...">`.
2. Check if `integrity` attribute is present.
3. Use Burp to modify the resource and see if the browser rejects it.

**Example**
```html
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
```
Missing `integrity` attribute.

**Tools**
- Browser DevTools
- SRI hash generator

**Risk Rating**  
High

**Remediation**
- Generate SRI hashes and add `integrity` and `crossorigin` attributes.
- Self-host critical libraries.

---

## 9. UNVERIFIED INTEGRITY OF CONFIGURATION FILES

**Description**  
Configuration files (e.g., `web.config`, `.env`, `appsettings.json`) that are not integrity-protected can be tampered with to alter application behavior.

**What to Look For**
- Configuration files writable by the web server.
- No checksum or signature validation.
- Config loaded from remote source without verification.

**What to Ignore**
- Read-only configs with checksum validation.

**How to Test with Burp Suite**
1. Access configuration files via path traversal (if possible).
2. Modify a config value (if writable) and observe if the application behaves differently.
3. Check if the application validates config integrity.

**Example**
```http
GET /../.env HTTP/1.1
```
If exposed, config integrity may be compromised.

**Tools**
- Dirb/Gobuster for config files
- Manual testing

**Risk Rating**  
High

**Remediation**
- Store configuration files outside webroot.
- Use read-only permissions.
- Implement integrity checks (e.g., sign configs).

---

## 10. LACK OF SUBRESOURCE INTEGRITY (SRI) FOR JAVASCRIPT/CSS

**Description**  
SRI ensures that resources fetched from CDN match a cryptographic hash. Without it, a compromised CDN can serve malicious code.

**What to Look For**
- External scripts/styles without `integrity` hash.
- CDN resources loaded without `crossorigin` attribute.

**What to Ignore**
- Resources with valid `integrity` and `crossorigin="anonymous"`.

**How to Test with Burp Suite**
1. Identify external resources.
2. Check for `integrity` attribute.
3. Use browser console to see if SRI is enforced.

**Example**
```html
<link rel="stylesheet" href="https://cdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
```
Missing `integrity`.

**Tools**
- Browser DevTools
- SRI Hash Generator (srihash.org)

**Risk Rating**  
High

**Remediation**
- Add `integrity` attribute with SHA-384 or SHA-512 hash.
- Set `crossorigin="anonymous"`.

---

## 11. INSECURE FILE UPLOAD (NO INTEGRITY VERIFICATION)

**Description**  
File upload endpoints that do not verify the integrity of uploaded files can allow attackers to replace legitimate files with malicious ones.

**What to Look For**
- No checksum validation for uploaded files.
- Files stored without verifying they haven't been tampered with.

**What to Ignore**
- Integrity checks (hash) and digital signatures.

**How to Test with Burp Suite**
1. Upload a legitimate file, capture the request.
2. Modify the file content (e.g., add a payload) and resend.
3. If the modified file is accepted, integrity check is missing.

**Example**
```http
POST /upload
Content-Type: multipart/form-data

file: legit.pdf (modified with embedded script)
```

**Tools**
- Burp Repeater
- Custom file modification

**Risk Rating**  
High

**Remediation**
- Compute and store file hash after upload.
- Validate hash on download or use.
- Use digital signatures for critical files.

---

## 12. UNPROTECTED INTEGRITY OF CRITICAL DATA IN TRANSIT (E.G., FINANCIAL TRANSACTIONS)

**Description**  
Critical data (e.g., financial transactions, medical records) transmitted without integrity protection (e.g., no MAC or signature) can be modified in transit.

**What to Look For**
- API requests for sensitive actions without request signing.
- No HMAC or digital signature on payloads.

**What to Ignore**
- HTTPS alone (does not prevent modification by client or attacker with access). Need application-level integrity for critical data.

**How to Test with Burp Suite**
1. Intercept a critical API request (e.g., money transfer).
2. Modify a parameter (e.g., amount) and forward.
3. If the server accepts the modified request, integrity is not enforced.

**Example**
```http
POST /api/transfer
{"amount":1000,"to":"attacker"}
```
Modify amount to 10000; if accepted, vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Use request signing (HMAC) or digital signatures for critical operations.
- Validate signature on the server side.

---

## 13. MISSING CHECKSUMS OR HASH VERIFICATION FOR DOWNLOADS

**Description**  
When the application allows file downloads, it should provide and verify checksums to ensure the file has not been tampered with.

**What to Look For**
- No hash provided for downloadable files.
- No validation of downloaded file integrity.

**What to Ignore**
- Checksums provided and validated.

**How to Test with Burp Suite**
1. Download a file from the application.
2. Modify the file using a hex editor.
3. If the application does not detect tampering (e.g., during later processing), vulnerable.

**Example**
- A software update download without hash verification.

**Tools**
- Hex editor
- Manual testing

**Risk Rating**  
Medium to High

**Remediation**
- Provide SHA-256 or SHA-512 hashes for all downloadable files.
- Validate the hash on the client side (if possible).

---

## 14. INSECURE USE OF JAVASCRIPT `EVAL()` OR `INNERHTML`

**Description**  
Using `eval()` or `innerHTML` with untrusted data allows attackers to inject malicious code, compromising client-side integrity.

**What to Look For**
- `eval(userInput)` in JavaScript.
- `element.innerHTML = userInput` without sanitization.

**What to Ignore**
- Use of `textContent` or `innerText`, or proper sanitization with DOMPurify.

**How to Test with Burp Suite**
1. Inject payloads like `<img src=x onerror=alert(1)>` into parameters that are used in `innerHTML`.
2. Observe if alert triggers.

**Example**
```javascript
eval(document.location.hash.substring(1));
```

**Tools**
- Burp Repeater
- Browser DevTools

**Risk Rating**  
High

**Remediation**
- Avoid `eval()` and `innerHTML` with user input.
- Use `textContent` or `innerText`.
- Sanitize with DOMPurify if HTML is necessary.

---

## 15. PROTOTYPE POLLUTION IN JAVASCRIPT APPLICATIONS

**Description**  
Prototype pollution occurs when attackers modify `Object.prototype` by injecting properties, leading to unexpected behavior, XSS, or RCE.

**What to Look For**
- Merging user input into objects without proper key validation (e.g., `merge` function).
- Use of `Object.assign` or `lodash.merge` with unsanitized keys.

**What to Ignore**
- Using `Object.create(null)` for maps, or validating keys.

**How to Test with Burp Suite**
1. Send payload: `{"__proto__":{"polluted":"true"}}` to an API that merges objects.
2. Check if `({}).polluted` becomes `true` (requires client-side test).
3. Look for `constructor.prototype` injection.

**Example**
```javascript
merge({}, JSON.parse('{"__proto__":{"x":1}}'));
```
Now `({}).x` returns 1.

**Tools**
- Burp Repeater
- Client-side testing in browser console

**Risk Rating**  
High to Critical

**Remediation**
- Avoid recursive merging of user-controlled objects.
- Use `Map` instead of plain objects.
- Validate keys and reject `__proto__`, `constructor`, `prototype`.

---

## 16. INSECURE DESERIALIZATION IN MOBILE APPS (ANDROID, IOS)

**Description**  
Mobile apps often use serialization for data persistence or IPC. Insecure deserialization can lead to code execution or data tampering.

**What to Look For**
- Use of `ObjectInputStream` in Android (Java).
- Use of `NSKeyedUnarchiver` in iOS with untrusted data.
- Custom binary protocols.

**What to Ignore**
- Using safe formats (JSON, Protocol Buffers) with validation.

**How to Test with Burp Suite**
1. Intercept mobile app traffic and look for binary blobs.
2. Extract and analyze serialized data.
3. Use tools like `Frida` to hook deserialization methods.

**Example**
- Android app uses `readObject()` on user-supplied file.

**Tools**
- Frida
- MobSF
- Jadx (decompile)

**Risk Rating**  
High

**Remediation**
- Avoid deserializing untrusted data.
- Use JSON with schema validation.

---

## 17. LACK OF INTEGRITY PROTECTION FOR DATABASE RECORDS (E.G., NO AUDIT TRAILS)

**Description**  
Database records without integrity checks (e.g., no row-level hash or audit trail) can be tampered with undetectably.

**What to Look For**
- No hash column for record integrity.
- No audit table tracking changes.

**What to Ignore**
- Use of blockchain or hash chaining, or comprehensive audit logging.

**How to Test with Burp Suite**
1. If you have SQL injection, modify a record (e.g., change balance).
2. Check if the application detects tampering.
3. If not, integrity protection missing.

**Example**
```sql
UPDATE accounts SET balance=999999 WHERE id=1;
```
No integrity check.

**Tools**
- SQLMap
- Manual database modification

**Risk Rating**  
High

**Remediation**
- Add a hash column (HMAC) for each row.
- Implement audit tables with immutable records.

---

## 18. UNVERIFIED API RESPONSES (NO SIGNATURE VALIDATION)

**Description**  
API clients that trust server responses without verifying signatures are vulnerable to response tampering.

**What to Look For**
- API responses without a signature header.
- Client does not verify the signature.

**What to Ignore**
- Signed responses (e.g., with JWT or custom HMAC) verified on client.

**How to Test with Burp Suite**
1. Intercept an API response.
2. Modify a field (e.g., `"status":"approved"` to `"status":"pending"`).
3. Forward to client; if client acts on modified data, no verification.

**Example**
```json
{"balance": 1000}
```
Modify to `{"balance": 999999}`.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Sign API responses with HMAC or digital signatures.
- Verify signatures on the client side.

---

## 19. INSECURE HANDLING OF JWT SIGNATURES (ALGORITHM CONFUSION)

**Description**  
JWT algorithm confusion attacks occur when a server accepts tokens signed with an asymmetric algorithm (RS256) but verifies them using a symmetric algorithm (HS256) with a public key.

**What to Look For**
- Server supports both RS256 and HS256.
- Public key exposed (e.g., in JWKS endpoint).

**What to Ignore**
- Whitelisting only strong algorithms, and validating algorithm properly.

**How to Test with Burp Suite**
1. Obtain the public key from `/.well-known/jwks.json` or via other means.
2. Use `jwt_tool` to convert RS256 to HS256: `python jwt_tool.py -X a -p public.pem token`.
3. Send modified token; if accepted, vulnerable.

**Example**
```python
jwt_tool.py "eyJ..." -X a -p public.pem
```

**Tools**
- jwt_tool
- Burp JWT Editor

**Risk Rating**  
Critical

**Remediation**
- Only allow a single algorithm per application.
- Validate algorithm in the token header.

---

## 20. DEPENDENCY VERIFICATION FAILURE (NO `PACKAGE-LOCK.JSON`, `COMPOSER.LOCK`)

**Description**  
Without lockfiles, the exact versions of dependencies are not pinned, allowing unintended updates that could introduce vulnerabilities or malicious code.

**What to Look For**
- `package.json` without `package-lock.json` or `yarn.lock`.
- `composer.json` without `composer.lock`.
- No integrity verification of dependencies.

**What to Ignore**
- Lockfiles present and committed to repository.

**How to Test with Burp Suite**
1. Check the application's source or repository for lockfiles.
2. If missing, the build may pull untested versions.

**Example**
- Project has `package.json` but no `package-lock.json`.

**Tools**
- Manual inspection
- Dependency scanners

**Risk Rating**  
Medium

**Remediation**
- Commit lockfiles to version control.
- Use integrity verification (e.g., npm’s `package-lock.json` includes integrity hashes).

---

## 21. INSECURE CODE INTEGRITY CHECKS (BYPASSABLE INTEGRITY MECHANISMS)

**Description**  
Custom integrity checks that are easily bypassed (e.g., client-side checks, weak hashes) provide a false sense of security.

**What to Look For**
- Integrity check performed only on client side.
- Simple checksums (e.g., CRC32) without cryptographic strength.
- Hardcoded hash values that can be replaced.

**What to Ignore**
- Server-side cryptographic integrity checks (HMAC, digital signatures).

**How to Test with Burp Suite**
1. Identify integrity check mechanism.
2. Attempt to bypass by modifying the checked file and updating the hash (if client-side).
3. For server-side, attempt to replace hash in request.

**Example**
```html
<script integrity="sha256-abc...">
```
If you can replace both script and integrity value, bypass.

**Tools**
- Burp Repeater
- Browser DevTools

**Risk Rating**  
Medium to High

**Remediation**
- Perform integrity checks server-side.
- Use strong cryptographic hashes (SHA-256 or higher).

---

## 22. UNVERIFIED SIDELOADED UPDATES (MOBILE, DESKTOP APPS)

**Description**  
Mobile or desktop apps that allow sideloading of updates (e.g., via external SD card or user-provided file) without integrity checks can be compromised.

**What to Look For**
- Update from external storage without signature validation.
- No hash verification before installation.

**What to Ignore**
- Updates only from official app stores with signature verification.

**How to Test with Burp Suite**
1. Intercept an update request or locate update file.
2. Replace with a modified APK, EXE, or IPA.
3. If the app installs the modified update, vulnerable.

**Example**
- Android app installs APK from `/sdcard/update.apk` without verification.

**Tools**
- Burp Proxy
- File modification tools

**Risk Rating**  
High

**Remediation**
- Verify digital signature of sideloaded updates.
- Use official app stores for distribution.

---

## 23. MISSING INTEGRITY CHECKS FOR SERVERLESS FUNCTIONS

**Description**  
Serverless functions (AWS Lambda, Azure Functions) that pull code from unverified sources or allow unsigned deployment packages can be compromised.

**What to Look For**
- Deployment packages without checksum or signature.
- Insecure CI/CD that pushes unverified code.

**What to Ignore**
- Signed deployment packages and verified code provenance.

**How to Test with Burp Suite**
1. Review CI/CD configuration for serverless deployment.
2. Check if code is pulled from public repositories without hash pinning.
3. Attempt to modify a deployment package (requires access; test in lab).

**Example**
- Lambda function pulls code from a public S3 bucket without integrity check.

**Tools**
- Manual review
- Serverless security scanners

**Risk Rating**  
High

**Remediation**
- Use code signing for serverless deployments.
- Enforce integrity checks (e.g., Lambda layers with pinned versions).

---

## 24. INSECURE CONTAINER IMAGE SIGNING (DOCKER CONTENT TRUST)

**Description**  
Docker images pulled without signature verification may be tampered with, leading to container compromise.

**What to Look For**
- Docker daemon without `DOCKER_CONTENT_TRUST` enabled.
- Images pulled from untrusted registries.
- No signature verification in CI/CD.

**What to Ignore**
- Docker Content Trust enabled, images signed and verified.

**How to Test with Burp Suite**
1. Check if the environment uses `DOCKER_CONTENT_TRUST=1`.
2. Attempt to pull an unsigned image; if allowed, vulnerable.

**Example**
```bash
docker pull company/app:latest
```
If no signature check, could be malicious.

**Tools**
- Docker CLI
- Docker Content Trust inspection

**Risk Rating**  
High

**Remediation**
- Enable Docker Content Trust.
- Use signed images from trusted registries.

---

## 25. UNVERIFIED INTEGRITY OF LOGS (LOG FORGING/TAMPERING)

**Description**  
If logs can be tampered without detection, attackers can cover their tracks or inject false entries.

**What to Look For**
- No integrity protection (e.g., hash chain) on logs.
- Logs stored in plaintext, writable by application user.

**What to Ignore**
- Logs with HMAC or hash chaining, and read-only access.

**How to Test with Burp Suite**
1. If you have access, modify a log file.
2. Check if the application detects tampering (e.g., during log review).
3. Attempt to inject log entries using CRLF injection.

**Example**
```http
User-Agent: User-Agent: legit\r\n2024-01-01 Admin logged in
```

**Tools**
- Manual log modification
- CRLF injection testing

**Risk Rating**  
Medium

**Remediation**
- Use HMAC or hash chaining for log integrity.
- Store logs in append-only, write-once storage.

---

## 26. LACK OF CRYPTOGRAPHIC SIGNATURES FOR CONFIGURATION FILES

**Description**  
Configuration files that are not signed can be modified by attackers to change application behavior (e.g., redirect URLs, security settings).

**What to Look For**
- Configuration files stored in plaintext.
- No signature verification when loading config.

**What to Ignore**
- Signed configuration with verified signature.

**How to Test with Burp Suite**
1. Access a configuration file (if exposed).
2. Modify a parameter (e.g., `debug=true`).
3. If the application loads the modified config, vulnerable.

**Example**
```json
{
  "auth_url": "https://evil.com/login"
}
```

**Tools**
- Burp Repeater
- Manual file modification

**Risk Rating**  
High

**Remediation**
- Sign configuration files with a private key.
- Verify signature before loading.

---

## 27. INSECURE DESERIALIZATION IN WEBSOCKET MESSAGES

**Description**  
WebSocket messages may contain serialized objects. Insecure deserialization can lead to RCE or data tampering.

**What to Look For**
- Binary or custom serialization formats over WebSocket.
- No integrity check on messages.

**What to Ignore**
- JSON messages with validation.

**How to Test with Burp Suite**
1. Intercept WebSocket messages.
2. If binary, attempt to modify using a hex editor.
3. Send malformed or malicious serialized data.

**Example**
- WebSocket message: `ACED0005...` (Java serialized).

**Tools**
- Burp WebSocket support
- Custom deserialization payloads

**Risk Rating**  
High

**Remediation**
- Use JSON with schema validation.
- Avoid deserializing untrusted data.

---

## 28. UNVERIFIED INTEGRITY OF THIRD-PARTY LIBRARIES (SRI FOR CSS/JS)

**Description**  
Third-party libraries loaded without SRI (Subresource Integrity) can be replaced by a compromised CDN, affecting all users.

**What to Look For**
- External CSS/JS files without `integrity` attribute.
- Use of CDN without fallback.

**What to Ignore**
- SRI implemented with `integrity` and `crossorigin`.

**How to Test with Burp Suite**
1. Identify external resources.
2. Check for `integrity` attribute.
3. Use Burp to modify the resource and see if the browser rejects.

**Example**
```html
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
```
Missing `integrity`.

**Tools**
- Browser DevTools
- SRI hash generator

**Risk Rating**  
High

**Remediation**
- Generate SRI hash and add `integrity` and `crossorigin="anonymous"`.

---

## 29. INSECURE DATA INTEGRITY VALIDATION (E.G., NO HMAC ON COOKIES)

**Description**  
Cookies or client-side data that are not integrity-protected (e.g., no HMAC) can be tampered with by users to escalate privileges.

**What to Look For**
- Cookies containing user data (e.g., `user_id=123`) without signature.
- Client-side data modified in browser and accepted by server.

**What to Ignore**
- Signed cookies (e.g., with HMAC) or server-side session storage.

**How to Test with Burp Suite**
1. Capture a cookie that contains user identifier.
2. Modify the value (e.g., change user ID).
3. Send request; if server accepts the change, vulnerable.

**Example**
```http
Cookie: user_id=123; role=user
```
Change to `user_id=1; role=admin`.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Use server-side session storage.
- Sign cookies with HMAC (e.g., Flask’s `session` with secret key).

---

## 30. MISSING SOFTWARE BILL OF MATERIALS (SBOM) AND PROVENANCE VERIFICATION

**Description**  
Without an SBOM, organizations cannot easily identify vulnerable or malicious components. Lack of provenance verification means they may unknowingly use tampered software.

**What to Look For**
- No documented list of all components and dependencies.
- No process to verify software provenance (e.g., signatures, hashes).

**What to Ignore**
- SBOM generated and stored, with provenance verification in CI/CD.

**How to Test with Burp Suite**
1. Ask developers or check repositories for SBOM.
2. If none exists, integrity verification is missing.
3. Try to identify components manually (e.g., from headers, file paths).

**Example**
- No `cyclonedx.json` or `spdx.json` in the project.

**Tools**
- OWASP Dependency-Track
- Syft (generate SBOM)

**Risk Rating**  
High (process risk)

**Remediation**
- Generate and maintain an SBOM.
- Verify software provenance using signatures.
- Use tools like Sigstore for supply chain security.

---

## ✅ **SUMMARY**

Software and Data Integrity Failures (A08) focus on ensuring that software and data are not tampered with during development, deployment, and runtime. This guide covers 30 integrity-related vulnerabilities, from insecure deserialization to missing signatures and supply chain attacks.

### **Key Testing Areas Summary**

| Failure Type | Key Indicators | Risk |
|--------------|----------------|------|
| Insecure Deserialization | Binary/structured data, `unserialize` | Critical |
| Unsafe Pickle/YAML | `pickle.loads`, `YAML.load` | Critical |
| Software Updates | HTTP, no signature | Critical |
| Code Signing | Unsigned binaries | High-Critical |
| CI/CD Pipeline | Unpinned actions, `curl | bash` | High |
| Dependency Confusion | Internal package names public | Critical |
| Typosquatting | Misspelled dependencies | High |
| CDN without SRI | Missing `integrity` attribute | High |
| Config Integrity | No signature on config | High |
| File Upload Integrity | No hash verification | High |
| Critical Data in Transit | No request signing | Critical |
| Download Checksums | Missing hash | Medium-High |
| `eval()` / `innerHTML` | User input in eval | High |
| Prototype Pollution | `__proto__` injection | High-Critical |
| Mobile Deserialization | `ObjectInputStream`, `NSKeyedUnarchiver` | High |
| Database Integrity | No row hash, no audit | High |
| API Response Signing | Unsigned responses | High |
| JWT Algorithm Confusion | RS256/HS256 mix | Critical |
| Lockfiles Missing | No `package-lock.json` | Medium |
| Bypassable Integrity | Client-side checks | Medium-High |
| Sideloaded Updates | Unverified APK/EXE | High |
| Serverless Integrity | Unverified deployments | High |
| Container Signing | Docker Content Trust disabled | High |
| Log Integrity | No HMAC on logs | Medium |
| Config Signatures | Unsigned configs | High |
| WebSocket Deserialization | Binary serialization | High |
| SRI for CSS/JS | Missing integrity | High |
| Cookie HMAC | Tamperable cookies | High |
| SBOM Missing | No component inventory | High (process) |

### **Pro Tips for Testing Integrity Failures**
1. **Look for serialized data** – binary blobs, base64 strings, PHP serialized format.
2. **Check for missing SRI** – inspect all external scripts and stylesheets.
3. **Review dependency management** – lockfiles, pinning, private registries.
4. **Test for tampering** – modify cookies, API responses, file uploads, and see if server rejects.
5. **Verify update mechanisms** – simulate malicious updates.
6. **Use integrity-focused tools** – SRI hash generator, Docker Content Trust, Sigstore.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
