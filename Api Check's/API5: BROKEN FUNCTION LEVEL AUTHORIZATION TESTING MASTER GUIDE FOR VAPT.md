# 🎯 **API5: BROKEN FUNCTION LEVEL AUTHORIZATION TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Missing Function-Level Access Controls in APIs*

---

## 📋 **TABLE OF CONTENTS**

1. [Admin Functions Accessible to Regular Users](#1-admin-functions-accessible-to-regular-users)
2. [Privilege Escalation via Role Parameter Tampering (e.g., `role=admin`)](#2-privilege-escalation-via-role-parameter-tampering)
3. [Hidden or Obfuscated Admin Endpoints Discoverable via Forced Browsing](#3-hidden-or-obfuscated-admin-endpoints-discoverable-via-forced-browsing)
4. [Missing Function-Level Authorization on API Endpoints (UI Hidden but API Exposed)](#4-missing-function-level-authorization-on-api-endpoints-ui-hidden-but-api-exposed)
5. [Different Authorization Logic for Different HTTP Methods (GET vs POST vs PUT)](#5-different-authorization-logic-for-different-http-methods)
6. [Insecure Direct Function Reference (Calling Internal Functions via Parameters)](#6-insecure-direct-function-reference-calling-internal-functions-via-parameters)
7. [Privilege Escalation via JWT Role/Claim Tampering](#7-privilege-escalation-via-jwt-roleclaim-tampering)
8. [Accessing Another User’s Functions via IDOR in Function Names](#8-accessing-another-users-functions-via-idor-in-function-names)
9. [GraphQL Mutation Authorization Bypass (Unauthorized Mutations)](#9-graphql-mutation-authorization-bypass-unauthorized-mutations)
10. [GraphQL Query Authorization Bypass (Accessing Admin Queries)](#10-graphql-query-authorization-bypass-accessing-admin-queries)
11. [Missing Role-Based Access Control (RBAC) on Administrative APIs](#11-missing-role-based-access-control-rbac-on-administrative-apis)
12. [Function-Level Authorization Bypass via HTTP Method Override](#12-function-level-authorization-bypass-via-http-method-override)
13. [Versioned API Endpoints with Weaker Authorization in Older Versions](#13-versioned-api-endpoints-with-weaker-authorization-in-older-versions)
14. [Internal APIs Exposed to Frontend (No Authorization Checks)](#14-internal-apis-exposed-to-frontend-no-authorization-checks)
15. [Authorization Bypass via Referer Header Spoofing](#15-authorization-bypass-via-referer-header-spoofing)
16. [Function-Level Access Control via Client-Side Only (UI Disable but API Callable)](#16-function-level-access-control-via-client-side-only-ui-disable-but-api-callable)
17. [Privilege Escalation via Accessing Another User’s Function (e.g., `/user/123/delete`)](#17-privilege-escalation-via-accessing-another-users-function)
18. [Broken Authorization in Workflow Functions (Skip Approval Steps)](#18-broken-authorization-in-workflow-functions-skip-approval-steps)
19. [Unauthorized Access to Debug or Development Functions (`/debug`, `/test`, `/cron`)](#19-unauthorized-access-to-debug-or-development-functions-debug-test-cron)
20. [Authorization Bypass via Case‑Sensitivity or Path Normalization](#20-authorization-bypass-via-case-sensitivity-or-path-normalization)
21. [Function-Level Authorization Missing on File Operations (Delete, Rename)](#21-function-level-authorization-missing-on-file-operations-delete-rename)
22. [Authorization Bypass via Batch Operations (Mix of Authorized and Unauthorized Functions)](#22-authorization-bypass-via-batch-operations-mix-of-authorized-and-unauthorized-functions)
23. [Privilege Escalation via WebSocket Actions (Calling Admin Actions)](#23-privilege-escalation-via-websocket-actions-calling-admin-actions)
24. [Missing Authorization on System Health or Metrics Endpoints](#24-missing-authorization-on-system-health-or-metrics-endpoints)
25. [Broken Function-Level Authorization in Serverless Functions](#25-broken-function-level-authorization-in-serverless-functions)
26. [Privilege Escalation via Impersonation Functions (`/api/admin/impersonate`)](#26-privilege-escalation-via-impersonation-functions-apiadminimpersonate)
27. [Unauthorized Access to Export or Reporting Functions](#27-unauthorized-access-to-export-or-reporting-functions)
28. [Authorization Bypass via URL Path Truncation or Trailing Slashes](#28-authorization-bypass-via-url-path-truncation-or-trailing-slashes)
29. [Missing Function-Level Authorization on Webhook or Callback Endpoints](#29-missing-function-level-authorization-on-webhook-or-callback-endpoints)
30. [Privilege Escalation via User‑Supplied Function Names (e.g., `?action=deleteUser`)](#30-privilege-escalation-via-user-supplied-function-names)

---

## 1. ADMIN FUNCTIONS ACCESSIBLE TO REGULAR USERS

**Description**  
Administrative functions (e.g., user deletion, system configuration, role assignment) are often protected only by obscurity. If a regular user can call these endpoints, it’s a critical broken function level authorization flaw.

**What to Look For**
- Endpoints with `/admin`, `/manage`, `/system`, `/user/delete`, `/role/update` in the path.
- API documentation (Swagger) listing admin functions without proper authentication warnings.

**What to Ignore**
- Endpoints that explicitly check for admin role and return `403 Forbidden` for non‑admins.

**How to Test with Burp Suite**
1. Log in as a regular user and capture a request to a sensitive endpoint (e.g., `GET /api/admin/users`).
2. If you don’t know admin endpoints, use forced browsing wordlists to discover them.
3. Send the request with the regular user’s token or session cookie.
4. If the endpoint returns data or performs an action, authorization is missing.

**Example**
```http
DELETE /api/admin/users/123 HTTP/1.1
Authorization: Bearer REGULAR_USER_TOKEN
```
If user 123 is deleted, function‑level authorization is broken.

**Tools**
- Burp Repeater
- Dirb/Gobuster (to discover admin endpoints)

**Risk Rating**  
Critical

**Remediation**
- Implement role‑based access control (RBAC) on every administrative endpoint.
- Use a consistent authorization middleware that checks user roles.

---

## 2. PRIVILEGE ESCALATION VIA ROLE PARAMETER TAMPERING (E.G., `ROLE=ADMIN`)

**Description**  
Some APIs accept role or permission parameters in the request body or query string. Attackers can change these to escalate privileges.

**What to Look For**
- Parameters like `role`, `isAdmin`, `user_type`, `permissions`, `group` in requests.
- Registration or profile update endpoints that accept such fields.

**What to Ignore**
- Server‑side role determination that ignores client‑supplied values.

**How to Test with Burp Suite**
1. Capture a request that creates or updates a user (e.g., `POST /api/users`).
2. Add or modify a role parameter: `"role": "admin"`, `"isAdmin": true`.
3. Send the request and check if the user gains admin privileges.

**Example**
```http
POST /api/register HTTP/1.1
{"username":"attacker","password":"pass","role":"admin"}
```
If the user is created as admin, vulnerable.

**Tools**
- Burp Repeater
- Param Miner

**Risk Rating**  
Critical

**Remediation**
- Never trust client‑supplied role or permission fields.
- Derive roles from server‑side session or database.

---

## 3. HIDDEN OR OBFUSCATED ADMIN ENDPOINTS DISCOVERABLE VIA FORCED BROWSING

**Description**  
Developers may hide admin functions in non‑obvious paths (e.g., `/xyzAdmin`, `/backdoor`), but attackers can discover them using wordlists.

**What to Look For**
- Unusual path names that suggest administrative functionality.
- Endpoints that return `200 OK` but are not linked from the UI.

**What to Ignore**
- Properly authenticated endpoints with strong access controls.

**How to Test with Burp Suite**
1. Use a wordlist of common admin paths (e.g., SecLists `admin-panels.txt`).
2. Use Intruder or Gobuster to brute‑force paths.
3. For each discovered path, test with a regular user’s session.

**Example**
```http
GET /secret-admin-panel/users HTTP/1.1
Cookie: session=REGULAR_USER_SESSION
```
If the page loads, function is exposed.

**Tools**
- Gobuster
- FFUF
- Burp Intruder

**Risk Rating**  
High

**Remediation**
- Do not rely on obscurity; enforce authorization on every endpoint.
- Use consistent URL naming and authentication.

---

## 4. MISSING FUNCTION-LEVEL AUTHORIZATION ON API ENDPOINTS (UI HIDDEN BUT API EXPOSED)

**Description**  
The UI may hide admin buttons from regular users, but the underlying API endpoints remain accessible if the user knows the URL.

**What to Look For**
- API endpoints that are called only from admin UI pages.
- No server‑side role check on those endpoints.

**What to Ignore**
- Server‑side authorization on every API call.

**How to Test with Burp Suite**
1. Browse the application as an admin and note all API requests.
2. Log in as a regular user and replay those requests.
3. If any succeed, function‑level authorization is missing.

**Example**
```http
POST /api/updateGlobalSettings HTTP/1.1
Cookie: session=REGULAR_USER_SESSION
{"setting":"maintenance_mode","value":true}
```
If settings are changed, vulnerable.

**Tools**
- Burp Repeater
- Autorize extension

**Risk Rating**  
Critical

**Remediation**
- Enforce authorization on every API endpoint, regardless of UI visibility.

---

## 5. DIFFERENT AUTHORIZATION LOGIC FOR DIFFERENT HTTP METHODS (GET VS POST VS PUT)

**Description**  
Sometimes authorization is enforced for GET (read) but not for POST/PUT/DELETE (write), or vice versa.

**What to Look For**
- Endpoints that behave differently based on HTTP method.
- GET requests may be blocked, but POST or DELETE allowed.

**What to Ignore**
- Consistent authorization across all methods.

**How to Test with Burp Suite**
1. Identify an endpoint that performs a sensitive action (e.g., `/api/user/delete`).
2. Try different HTTP methods (GET, POST, PUT, PATCH, DELETE).
3. If any method performs the action without proper authorization, vulnerable.

**Example**
```http
GET /api/admin/deleteUser?user_id=123 HTTP/1.1
```
May return `405 Method Not Allowed`, but:
```http
POST /api/admin/deleteUser HTTP/1.1
{"user_id":123}
```
If successful, method‑based bypass exists.

**Tools**
- Burp Repeater
- Method override headers

**Risk Rating**  
High

**Remediation**
- Apply same authorization logic to all HTTP methods.
- Validate HTTP method on the server.

---

## 6. INSECURE DIRECT FUNCTION REFERENCE (CALLING INTERNAL FUNCTIONS VIA PARAMETERS)

**Description**  
Some APIs accept a `function` or `action` parameter that specifies which internal function to call. Attackers can change this to call privileged functions.

**What to Look For**
- Parameters like `action=`, `function=`, `cmd=`, `operation=`.
- Endpoints like `/api/execute?action=addUser`.

**What to Ignore**
- Whitelist of allowed actions with authorization checks.

**How to Test with Burp Suite**
1. Capture a request with an `action` parameter.
2. Change the action to a privileged one (e.g., from `getProfile` to `deleteAllUsers`).
3. Send the request with a regular user’s session.

**Example**
```http
POST /api/handler?action=getProfile HTTP/1.1
```
Change to:
```http
POST /api/handler?action=deleteUser&userId=123 HTTP/1.1
```

**Tools**
- Burp Repeater
- Wordlist of common action names

**Risk Rating**  
Critical

**Remediation**
- Never map user input directly to function calls.
- Use a whitelist of allowed actions and enforce authorization per action.

---

## 7. PRIVILEGE ESCALATION VIA JWT ROLE/CLAIM TAMPERING

**Description**  
JWTs often contain role or permission claims. If the server does not validate the token’s signature properly, attackers can modify the claims to escalate privileges.

**What to Look For**
- JWT tokens with claims like `role`, `isAdmin`, `permissions`, `groups`.
- No signature validation (or weak validation).

**What to Ignore**
- Properly signed JWTs with server‑side role mapping.

**How to Test with Burp Suite**
1. Decode the JWT using jwt.io or Burp JWT Editor.
2. Modify the role claim (e.g., `"role":"user"` to `"role":"admin"`).
3. Re‑encode without a signature or with a weak secret.
4. Send the modified token to an admin endpoint.

**Example**
Original payload: `{"user":"john","role":"user"}`
Modified: `{"user":"john","role":"admin"}`

**Tools**
- Burp JWT Editor
- jwt_tool

**Risk Rating**  
Critical

**Remediation**
- Validate JWT signatures strictly.
- Do not rely solely on JWT claims; map roles server‑side from a secure source.

---

## 8. ACCESSING ANOTHER USER’S FUNCTIONS VIA IDOR IN FUNCTION NAMES

**Description**  
When functions are tied to specific users (e.g., `/api/user/123/updateProfile`), an attacker may change the user ID in the function path to perform actions on behalf of another user.

**What to Look For**
- Endpoints that include a user ID in the path before the function name.
- No ownership check on the resource.

**What to Ignore**
- Authorization that verifies the authenticated user owns the resource.

**How to Test with Burp Suite**
1. As User A, call a function for your own resource (e.g., `POST /api/user/123/updateProfile`).
2. Change the user ID to that of User B (`/api/user/124/updateProfile`).
3. If the function executes on User B’s profile, broken function‑level authorization exists.

**Example**
```http
POST /api/user/124/delete HTTP/1.1
Cookie: session=USER_A_SESSION
```
If User B’s account is deleted, vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Always verify that the authenticated user is authorized to perform the function on the target resource.

---

## 9. GRAPHQL MUTATION AUTHORIZATION BYPASS (UNAUTHORIZED MUTATIONS)

**Description**  
GraphQL mutations that perform sensitive actions (e.g., `deleteUser`, `updateRole`) may not have proper authorization checks in their resolvers.

**What to Look For**
- GraphQL schema with mutations that sound administrative (`deleteUser`, `makeAdmin`, `grantPermission`).
- Introspection enabled to discover mutation names.

**What to Ignore**
- Resolvers that check user roles before executing.

**How to Test with Burp Suite**
1. Use GraphQL introspection to list all mutations.
2. As a regular user, attempt to call an admin mutation (e.g., `mutation { deleteUser(id: 123) }`).
3. If the mutation succeeds, authorization is missing.

**Example**
```graphql
mutation {
  makeAdmin(userId: 123, role: "admin")
}
```

**Tools**
- GraphQL Raider
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Implement role‑based authorization in every GraphQL resolver.
- Use directives (e.g., `@auth`) to enforce access.

---

## 10. GRAPHQL QUERY AUTHORIZATION BYPASS (ACCESSING ADMIN QUERIES)

**Description**  
Similar to mutations, certain GraphQL queries may expose administrative data (e.g., `allUsers`, `systemLogs`). Regular users should not be able to execute them.

**What to Look For**
- Queries that return sensitive data or perform administrative reads.
- No authorization checks in resolvers.

**What to Ignore**
- Queries that filter results based on the authenticated user.

**How to Test with Burp Suite**
1. Discover admin‑like queries via introspection: `users`, `auditLogs`, `config`.
2. Execute them with a regular user’s token.
3. If sensitive data is returned, broken authorization.

**Example**
```graphql
query {
  allUsers {
    id
    email
    role
  }
}
```

**Tools**
- GraphQL Raider

**Risk Rating**  
Critical

**Remediation**
- Apply authorization checks to all GraphQL queries and mutations.

---

## 11. MISSING ROLE-BASED ACCESS CONTROL (RBAC) ON ADMINISTRATIVE APIS

**Description**  
The application may have separate administrative APIs that lack any role verification, assuming they are only accessible from internal networks.

**What to Look For**
- Administrative APIs on non‑standard ports or subdomains (e.g., `admin-api.internal.com`).
- No authentication or authorization headers required.

**What to Ignore**
- Proper RBAC with network‑level and application‑level controls.

**How to Test with Burp Suite**
1. Discover administrative subdomains or endpoints via DNS enumeration or forced browsing.
2. Call them without any token or with a regular user’s token.
3. If they return data, RBAC is missing.

**Example**
```http
GET https://admin-api.target.com/users HTTP/1.1
```
No token → returns user list.

**Tools**
- DNS enumeration (dnsrecon, subfinder)
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Enforce strong authentication and authorization on all administrative APIs.
- Use network segmentation and VPNs for internal APIs.

---

## 12. FUNCTION-LEVEL AUTHORIZATION BYPASS VIA HTTP METHOD OVERRIDE

**Description**  
Some frameworks support method override headers (e.g., `X-HTTP-Method-Override`). Attackers can change the method to bypass method‑specific authorization checks.

**What to Look For**
- Support for `X-HTTP-Method-Override` or `_method` parameters.
- Different authorization rules for different methods.

**What to Ignore**
- Consistent authorization regardless of method.

**How to Test with Burp Suite**
1. Capture a request that would be blocked (e.g., `DELETE /api/resource`).
2. Change the method to POST and add `X-HTTP-Method-Override: DELETE`.
3. Send the request with a regular user’s token.

**Example**
```http
POST /api/resource HTTP/1.1
X-HTTP-Method-Override: DELETE
```
If the resource is deleted, vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Disable method override in production.
- Validate the actual HTTP method in authorization logic.

---

## 13. VERSIONED API ENDPOINTS WITH WEAKER AUTHORIZATION IN OLDER VERSIONS

**Description**  
Newer API versions (v2) may have proper authorization, but older versions (v1) may still be exposed and lack checks.

**What to Look For**
- Multiple API versions: `/api/v1/`, `/api/v2/`, `/api/v3/`.
- Different behavior between versions.

**What to Ignore**
- Consistent authorization across all versions.

**How to Test with Burp Suite**
1. Call the same sensitive endpoint on different API versions (e.g., `/api/v1/admin/users`, `/api/v2/admin/users`).
2. Compare responses; if v1 allows access with a regular user’s token, vulnerable.

**Example**
```http
GET /api/v1/admin/users HTTP/1.1
Cookie: session=REGULAR_USER_SESSION
```
If returns user list, v1 is less secure.

**Tools**
- Burp Repeater
- API version discovery

**Risk Rating**  
High

**Remediation**
- Apply consistent authorization across all API versions.
- Deprecate and remove older, insecure versions.

---

## 14. INTERNAL APIS EXPOSED TO FRONTEND (NO AUTHORIZATION CHECKS)

**Description**  
Developers may expose internal APIs intended for backend services to the frontend, but forget to add authorization.

**What to Look For**
- Endpoints like `/internal/`, `/system/`, `/private/`, `/worker/`.
- No authentication required or weak checks.

**What to Ignore**
- Internal APIs protected by network restrictions and authentication.

**How to Test with Burp Suite**
1. Browse the frontend application and look for requests to `/internal/` or similar paths.
2. Replay those requests with a regular user’s session.
3. If they return sensitive data, vulnerable.

**Example**
```http
GET /internal/user-sync HTTP/1.1
Cookie: session=REGULAR_USER_SESSION
```
If the sync function is triggered, vulnerable.

**Tools**
- Burp Proxy
- API discovery

**Risk Rating**  
Critical

**Remediation**
- Do not expose internal APIs to client‑side code.
- If unavoidable, enforce strong authentication and authorization.

---

## 15. AUTHORIZATION BYPASS VIA REFERER HEADER SPOOFING

**Description**  
Some APIs rely on the `Referer` header to check if the request came from an admin page. Attackers can spoof this header.

**What to Look For**
- Authorization logic that checks `Referer` header for a specific domain or path.
- No token‑based authentication.

**What to Ignore**
- Proper token‑based authorization.

**How to Test with Burp Suite**
1. Capture a sensitive request and add a `Referer` header pointing to an admin page.
2. Send the request with a regular user’s session.

**Example**
```http
POST /api/deleteUser HTTP/1.1
Referer: https://target.com/admin/dashboard
Cookie: session=REGULAR_USER_SESSION
```
If the user is deleted, vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Never rely on the `Referer` header for authorization.
- Use proper tokens and role checks.

---

## 16. FUNCTION-LEVEL ACCESS CONTROL VIA CLIENT-SIDE ONLY (UI DISABLE BUT API CALLABLE)

**Description**  
The UI may disable buttons for non‑admin users, but the corresponding API endpoint is still accessible.

**What to Look For**
- UI buttons that are disabled or hidden based on user role.
- API endpoints called by those buttons that lack server‑side checks.

**What to Ignore**
- Server‑side authorization on all API endpoints.

**How to Test with Burp Suite**
1. Log in as a regular user and identify a disabled admin button (e.g., “Delete User”).
2. Use browser DevTools to find the API endpoint that the button would call.
3. Send that API request directly with the regular user’s session.

**Example**
```http
DELETE /api/user/456 HTTP/1.1
Cookie: session=REGULAR_USER_SESSION
```
If successful, client‑side only protection.

**Tools**
- Browser DevTools
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Enforce authorization on the server side for every API endpoint.

---

## 17. PRIVILEGE ESCALATION VIA ACCESSING ANOTHER USER’S FUNCTION

**Description**  
Some functions are user‑specific (e.g., `/api/user/123/updatePreferences`). Attackers can change the user ID in the path to act on behalf of another user.

**What to Look For**
- Endpoints that include a user ID in the path and perform an action (update, delete, export).
- No ownership validation.

**What to Ignore**
- Verification that the authenticated user owns the resource.

**How to Test with Burp Suite**
1. As User A, call a function for your own user ID.
2. Change the user ID to that of User B.
3. If the function executes on User B’s resource, vulnerable.

**Example**
```http
POST /api/user/124/disable HTTP/1.1
Cookie: session=USER_A_SESSION
```
If User B’s account is disabled, broken authorization.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Validate that the authenticated user has permission to perform the function on the target resource.

---

## 18. BROKEN AUTHORIZATION IN WORKFLOW FUNCTIONS (SKIP APPROVAL STEPS)

**Description**  
Multi‑step workflows (e.g., order approval, account registration) may have functions that skip verification steps. Attackers may call the final approval function directly.

**What to Look For**
- Workflow endpoints like `/api/order/submit`, `/api/order/approve`, `/api/order/finalize`.
- No state validation.

**What to Ignore**
- State validation that prevents skipping steps.

**How to Test with Burp Suite**
1. Map a workflow (e.g., submit → approve → finalize).
2. As a regular user, directly call the final function (e.g., `POST /api/order/finalize`).
3. If the action is performed without prior approval, vulnerable.

**Example**
```http
POST /api/loan/approve HTTP/1.1
Cookie: session=USER_SESSION
{"loan_id":123}
```
If loan is approved without review, broken workflow authorization.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Validate workflow state on every step.
- Ensure that only authorized users can transition between states.

---

## 19. UNAUTHORIZED ACCESS TO DEBUG OR DEVELOPMENT FUNCTIONS (`/DEBUG`, `/TEST`, `/CRON`)

**Description**  
Debug and test endpoints often lack proper authorization and may expose sensitive functionality or data.

**What to Look For**
- Paths like `/debug`, `/test`, `/cron`, `/phpinfo`, `/health`, `/metrics`, `/swagger`, `/api-docs`.
- No authentication required.

**What to Ignore**
- Debug endpoints disabled or protected by IP whitelisting.

**How to Test with Burp Suite**
1. Use a wordlist of common debug/test paths.
2. Access them with an unauthenticated session or regular user session.
3. If they return sensitive information or execute actions, vulnerable.

**Example**
```http
GET /debug/run-sql?query=SELECT+*+FROM+users HTTP/1.1
```
If SQL results are returned, vulnerable.

**Tools**
- Gobuster
- FFUF
- Burp Intruder

**Risk Rating**  
Critical

**Remediation**
- Remove debug and test endpoints from production.
- If necessary, protect them with strong authentication and IP restrictions.

---

## 20. AUTHORIZATION BYPASS VIA CASE‑SENSITIVITY OR PATH NORMALIZATION

**Description**  
Some authorization filters rely on exact path matching. Attackers can use case variations or path traversal to bypass.

**What to Look For**
- Authorization logic that checks for `/admin` but not `/ADMIN` or `/a/../admin`.
- Web server or framework normalizes paths differently.

**What to Ignore**
- Canonical path normalization before authorization.

**How to Test with Burp Suite**
1. Try different case variations: `/Admin`, `/ADMIN`, `/AdMiN`.
2. Try path traversal: `/a/../admin/users`.
3. Try URL encoding: `/%61dmin/users`.

**Example**
```http
GET /ADMIN/users HTTP/1.1
Cookie: session=REGULAR_USER_SESSION
```
If allowed, case‑sensitivity bypass works.

**Tools**
- Burp Repeater
- Encoding scripts

**Risk Rating**  
Medium

**Remediation**
- Normalize URLs to a canonical form before authorization checks.
- Use case‑insensitive matching or enforce consistent case.

---

## 21. FUNCTION-LEVEL AUTHORIZATION MISSING ON FILE OPERATIONS (DELETE, RENAME)

**Description**  
APIs that perform file operations (delete, rename, move) often have broken function‑level authorization, allowing users to delete other users’ files.

**What to Look For**
- Endpoints like `/api/files/delete?file_id=123`, `/api/files/rename`.
- No ownership validation.

**What to Ignore**
- Authorization checks that verify file ownership.

**How to Test with Burp Suite**
1. As User A, upload a file and note its `file_id`.
2. As User A, call a delete function with User B’s `file_id`.
3. If User B’s file is deleted, vulnerable.

**Example**
```http
DELETE /api/files/456 HTTP/1.1
Cookie: session=USER_A_SESSION
```
File 456 belongs to User B.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Validate that the authenticated user owns the file or has permission to delete it.

---

## 22. AUTHORIZATION BYPASS VIA BATCH OPERATIONS (MIX OF AUTHORIZED AND UNAUTHORIZED FUNCTIONS)

**Description**  
Batch APIs may process multiple operations in one request. Attackers can include one authorized operation and one unauthorized operation; if the server processes both, authorization is flawed.

**What to Look For**
- Batch endpoints that accept an array of operations.
- No per‑operation authorization check.

**What to Ignore**
- Per‑operation authorization validation.

**How to Test with Burp Suite**
1. Send a batch request with one legitimate operation (e.g., update your own profile) and one admin operation (e.g., delete another user).
2. If both succeed, vulnerable.

**Example**
```json
[
  {"op":"updateProfile","userId":123,"name":"new"},
  {"op":"deleteUser","userId":124}
]
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Validate authorization for each operation in the batch independently.

---

## 23. PRIVILEGE ESCALATION VIA WEBSOCKET ACTIONS (CALLING ADMIN ACTIONS)

**Description**  
WebSocket connections may support actions or events. Attackers can send admin actions if the server does not validate the user’s role.

**What to Look For**
- WebSocket messages with an `action` or `type` field.
- No role verification on the server.

**What to Ignore**
- Per‑message authorization checks.

**How to Test with Burp Suite**
1. Intercept WebSocket messages using Burp.
2. Modify the action to an admin action (e.g., `{"action":"banUser","userId":124}`).
3. Send the message with a regular user’s WebSocket session.

**Example**
```json
{"action": "broadcastAdminMessage", "message": "spam"}
```

**Tools**
- Burp WebSocket

**Risk Rating**  
High

**Remediation**
- Authenticate WebSocket connections and enforce role‑based authorization on every action.

---

## 24. MISSING AUTHORIZATION ON SYSTEM HEALTH OR METRICS ENDPOINTS

**Description**  
Health and metrics endpoints (e.g., `/health`, `/metrics`, `/actuator`) may expose internal system information and should be protected.

**What to Look For**
- Endpoints like `/actuator`, `/health`, `/metrics`, `/prometheus`.
- No authentication required.

**What to Ignore**
- Protected endpoints (e.g., with basic auth or IP whitelist).

**How to Test with Burp Suite**
1. Access common health/metrics paths.
2. If they return data (e.g., memory usage, database status, environment variables), vulnerable.

**Example**
```http
GET /actuator/env HTTP/1.1
```
May expose environment variables including secrets.

**Tools**
- Burp Repeater
- Wordlist for actuator paths

**Risk Rating**  
High

**Remediation**
- Restrict access to health and metrics endpoints (authentication, IP whitelist, or network segmentation).

---

## 25. BROKEN FUNCTION-LEVEL AUTHORIZATION IN SERVERLESS FUNCTIONS

**Description**  
Serverless functions (AWS Lambda, Azure Functions) often have separate endpoints. If not properly secured, regular users can invoke administrative functions.

**What to Look For**
- Serverless endpoints with function names that suggest admin operations (e.g., `adminHandler`, `deleteAllData`).
- No authorization in the function code.

**What to Ignore**
- Functions that validate the caller’s role via API Gateway authorizers.

**How to Test with Burp Suite**
1. Discover serverless endpoints (e.g., via `/.aws/` or cloud metadata).
2. Call a function with a regular user’s token.
3. If it executes, vulnerable.

**Example**
```http
POST https://lambda.execute-api.region.amazonaws.com/prod/adminHandler
```
No authorization.

**Tools**
- Burp Repeater
- API discovery

**Risk Rating**  
Critical

**Remediation**
- Use API Gateway authorizers (Lambda authorizers, Cognito) to enforce authentication and authorization.

---

## 26. PRIVILEGE ESCALATION VIA IMPERSONATION FUNCTIONS (`/API/ADMIN/IMPERSONATE`)

**Description**  
Some applications have an impersonation feature that allows admins to log in as other users. If not properly protected, regular users could impersonate admins.

**What to Look For**
- Endpoints like `/api/admin/impersonate`, `/api/su`, `/api/switch-user`.
- No role check.

**What to Ignore**
- Impersonation functions that require admin role and MFA.

**How to Test with Burp Suite**
1. As a regular user, call the impersonation endpoint with a target user ID.
2. If you gain that user’s session or token, vulnerable.

**Example**
```http
POST /api/admin/impersonate HTTP/1.1
{"userId":1}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Restrict impersonation functions to super‑admins only.
- Log all impersonation actions.

---

## 27. UNAUTHORIZED ACCESS TO EXPORT OR REPORTING FUNCTIONS

**Description**  
Export functions (e.g., `/api/export/all-users.csv`) may be accessible to regular users, leading to data exfiltration.

**What to Look For**
- Endpoints that generate reports or exports (`/export`, `/report`, `/download-all`).
- No authorization check.

**What to Ignore**
- Exports that are limited to the user’s own data and properly authorized.

**How to Test with Burp Suite**
1. As a regular user, call an export endpoint that should be admin‑only.
2. If you receive a CSV/PDF containing all users’ data, vulnerable.

**Example**
```http
GET /api/export/users.csv HTTP/1.1
Cookie: session=REGULAR_USER_SESSION
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Enforce role‑based access on all export endpoints.

---

## 28. AUTHORIZATION BYPASS VIA URL PATH TRUNCATION OR TRAILING SLASHES

**Description**  
Some authorization filters match exact paths. Attackers can add trailing slashes or extra path segments to bypass.

**What to Look For**
- Authorization rules that check `/admin` but not `/admin/` or `/admin/anything`.
- Web server normalizes paths inconsistently.

**What to Ignore**
- Path normalization before authorization.

**How to Test with Burp Suite**
1. Try `/admin/`, `/admin//`, `/admin/anything`.
2. Try `/admin/users/..` (if path traversal allowed).

**Example**
```http
GET /admin/ HTTP/1.1
```
If allowed while `/admin` is blocked, vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Normalize URLs (remove trailing slashes, resolve `..`) before authorization.

---

## 29. MISSING FUNCTION-LEVEL AUTHORIZATION ON WEBHOOK OR CALLBACK ENDPOINTS

**Description**  
Webhook endpoints that are called by third‑party services may not check the caller’s role, allowing attackers to trigger sensitive actions.

**What to Look For**
- Public webhook endpoints that perform state changes (e.g., `/webhook/order-update`).
- No authentication or signature validation.

**What to Ignore**
- Webhooks that verify signatures (e.g., HMAC) and have role checks.

**How to Test with Burp Suite**
1. Identify a webhook endpoint from API documentation or source code.
2. Send a crafted request mimicking the expected webhook event.
3. If the action is performed without proper authorization, vulnerable.

**Example**
```http
POST /webhook/delete-user HTTP/1.1
{"userId":123}
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Require signature verification for webhook callbacks.
- Limit webhook actions to non‑sensitive operations or require authentication.

---

## 30. PRIVILEGE ESCALATION VIA USER‑SUPPLIED FUNCTION NAMES (E.G., `?ACTION=DELETEUSER`)

**Description**  
Some APIs accept the function name as a parameter (e.g., `?action=addUser`). Attackers can supply arbitrary function names to execute unauthorized actions.

**What to Look For**
- Parameters like `action`, `function`, `cmd`, `operation` that control which function is called.
- No whitelist or authorization per action.

**What to Ignore**
- Whitelist of allowed actions with role‑based authorization.

**How to Test with Burp Suite**
1. Capture a request with an `action` parameter (e.g., `?action=viewProfile`).
2. Change the action to `deleteUser` or `makeAdmin`.
3. Send with a regular user’s token.

**Example**
```http
GET /api/dispatch?action=deleteUser&userId=123 HTTP/1.1
```
If user 123 is deleted, vulnerable.

**Tools**
- Burp Repeater
- Common action wordlists

**Risk Rating**  
Critical

**Remediation**
- Use a whitelist of allowed actions.
- Implement authorization checks per action.

---

## ✅ **SUMMARY**

Broken Function Level Authorization (API5) occurs when an API endpoint that performs a sensitive function is accessible to users who should not have permission. This guide covers 30 distinct testing techniques for function‑level flaws.

### **Key Testing Areas Summary**

| Failure Type | Key Indicators | Risk |
|--------------|----------------|------|
| Admin Functions | `/admin`, `/manage` accessible to regular users | Critical |
| Role Parameter Tampering | `role=admin` in request | Critical |
| Hidden Admin Endpoints | Discoverable via forced browsing | High |
| UI Hidden but API Exposed | Admin API called from frontend | Critical |
| Method‑Based Bypass | GET vs POST different auth | High |
| Direct Function Reference | `action=deleteUser` parameter | Critical |
| JWT Role Tampering | Modify `role` claim | Critical |
| IDOR in Function Path | `/user/124/delete` | Critical |
| GraphQL Mutations | Unauthorized mutations | Critical |
| GraphQL Queries | Admin queries accessible | Critical |
| Missing RBAC | No role checks on admin APIs | Critical |
| Method Override | `X-HTTP-Method-Override` | High |
| Versioned APIs | V1 weaker than V2 | High |
| Internal APIs Exposed | `/internal/` endpoints | Critical |
| Referer Spoofing | `Referer: /admin` | Medium |
| Client‑Side Only | Disabled buttons, callable API | Critical |
| Another User’s Function | Change user ID in path | Critical |
| Workflow Bypass | Skip approval steps | High |
| Debug Endpoints | `/debug`, `/test`, `/cron` | Critical |
| Case‑Sensitivity | `/ADMIN` bypass | Medium |
| File Operations | Delete others’ files | Critical |
| Batch Operations | Mix of auth and unauth | High |
| WebSocket Actions | Admin actions via WS | High |
| Health/Metrics | `/actuator` exposed | High |
| Serverless Functions | Lambda without auth | Critical |
| Impersonation | `/admin/impersonate` | Critical |
| Export Functions | Download all users | Critical |
| Path Truncation | `/admin/` vs `/admin` | Medium |
| Webhooks | Unsigned webhooks | High |
| User‑Supplied Function Names | `?action=deleteUser` | Critical |

### **Pro Tips for Testing Broken Function Level Authorization**
1. **Map all API endpoints** – use Burp Spider, OpenAPI/Swagger, and forced browsing.
2. **Use two accounts** – one with high privileges, one with low privileges. Compare which endpoints are accessible.
3. **Automate with Autorize** – configure high‑privilege session as “authorized” and low‑privilege session as “unauthorized”.
4. **Test all HTTP methods** – an endpoint may be protected for GET but not for POST.
5. **Check for role parameters** – try adding `role=admin`, `isAdmin=true`, `permissions=*`.
6. **Test GraphQL separately** – use introspection to find mutations and queries, then test with low‑privilege token.
7. **Don’t trust UI hiding** – always call the API directly.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
