# 🎯 **API1: BROKEN OBJECT LEVEL AUTHORIZATION (BOLA) TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Object-Level Access Control Flaws in APIs*

---

## 📋 **TABLE OF CONTENTS**

1. [IDOR via Numeric Object Identifiers in URL Path](#1-idor-via-numeric-object-identifiers-in-url-path)
2. [IDOR via UUID/GUID Object Identifiers in URL Path](#2-idor-via-uuidguid-object-identifiers-in-url-path)
3. [IDOR via Object Identifiers in Query Parameters](#3-idor-via-object-identifiers-in-query-parameters)
4. [IDOR via Object Identifiers in Request Body (JSON/XML)](#4-idor-via-object-identifiers-in-request-body-jsonxml)
5. [IDOR via Nested or Composite Object References](#5-idor-via-nested-or-composite-object-references)
6. [IDOR via Batch/GraphQL Operations](#6-idor-via-batchgraphql-operations)
7. [IDOR via File Download Endpoints (Document, Image, Export)](#7-idor-via-file-download-endpoints-document-image-export)
8. [IDOR via File Upload Endpoints (Overwrite Others' Files)](#8-idor-via-file-upload-endpoints-overwrite-others-files)
9. [IDOR via API Parameters that Accept Usernames or Emails](#9-idor-via-api-parameters-that-accept-usernames-or-emails)
10. [IDOR via Business Resource (Orders, Invoices, Transactions)](#10-idor-via-business-resource-orders-invoices-transactions)
11. [IDOR via User Profile or Account Settings Endpoints](#11-idor-via-user-profile-or-account-settings-endpoints)
12. [IDOR via Administrative Resources (User Management, Logs)](#12-idor-via-administrative-resources-user-management-logs)
13. [IDOR via Time‑Based or Sequential Tokens](#13-idor-via-timebased-or-sequential-tokens)
14. [IDOR via Encoded or Hashed Object Identifiers (Base64, JWT)](#14-idor-via-encoded-or-hashed-object-identifiers-base64-jwt)
15. [IDOR via Path Traversal in Object Identifiers](#15-idor-via-path-traversal-in-object-identifiers)
16. [IDOR via HTTP Method Override (GET to POST, POST to PUT)](#16-idor-via-http-method-override-get-to-post-post-to-put)
17. [IDOR via Versioned API Endpoints (V1 vs V2 Differences)](#17-idor-via-versioned-api-endpoints-v1-vs-v2-differences)
18. [IDOR via Filter or Search Parameters (Listing All Objects)](#18-idor-via-filter-or-search-parameters-listing-all-objects)
19. [IDOR via GraphQL Field‑Level Queries (Unauthorized Field Access)](#19-idor-via-graphql-fieldlevel-queries-unauthorized-field-access)
20. [IDOR via GraphQL Object Identification (Node Interface)](#20-idor-via-graphql-object-identification-node-interface)
21. [IDOR via WebSocket Messages (Real‑Time Updates)](#21-idor-via-websocket-messages-realtime-updates)
22. [IDOR via API Rate Limit Bypass for Enumeration](#22-idor-via-api-rate-limit-bypass-for-enumeration)
23. [IDOR via Cross‑Tenant Object Access (Multi‑Tenancy Bypass)](#23-idor-via-crosstenant-object-access-multitenancy-bypass)
24. [IDOR via Referer Header or Custom Headers Manipulation](#24-idor-via-referer-header-or-custom-headers-manipulation)
25. [IDOR via Session or Token Context Confusion](#25-idor-via-session-or-token-context-confusion)
26. [IDOR via Insecure Direct Object Reference in Callback URLs](#26-idor-via-insecure-direct-object-reference-in-callback-urls)
27. [IDOR via Mobile API Endpoints (Less Secure than Web)](#27-idor-via-mobile-api-endpoints-less-secure-than-web)
28. [IDOR via Internal API Endpoints (Exposed to Frontend)](#28-idor-via-internal-api-endpoints-exposed-to-frontend)
29. [IDOR via Object Reference Leakage in Response (Previous/Next Links)](#29-idor-via-object-reference-leakage-in-response-previousnext-links)
30. [IDOR via Mass Assignment Combined with Object References](#30-idor-via-mass-assignment-combined-with-object-references)

---

## 1. IDOR VIA NUMERIC OBJECT IDENTIFIERS IN URL PATH

**Description**  
APIs that use sequential numeric IDs in URL paths (e.g., `/api/users/123`, `/api/orders/456`) are vulnerable if they do not verify that the authenticated user owns or is authorized to access that specific object.

**What to Look For**
- API endpoints with numeric IDs in the path: `/users/{id}`, `/orders/{order_id}`, `/documents/{docId}`.
- Sequential or predictable IDs (e.g., 1001, 1002, 1003).

**What to Ignore**
- APIs that use random UUIDs and implement proper authorization checks.
- APIs that always derive the object ID from the authenticated session (e.g., `/me/orders`).

**How to Test with Burp Suite**
1. Log in as User A and capture a request to an endpoint that fetches an object by ID (e.g., `GET /api/users/123`).
2. Log in as User B (or use a different browser) and obtain User B’s object ID (e.g., `124`).
3. In Repeater, change the ID in User A’s request from `123` to `124` and send.
4. If the response contains User B’s data, BOLA exists.

**Example**
```http
GET /api/v1/users/124 HTTP/1.1
Host: api.target.com
Authorization: Bearer <USER_A_TOKEN>
```
If response returns user 124’s details, vulnerable.

**Tools**
- Burp Repeater
- Burp Intruder (for enumeration)
- Autorize extension (automated BOLA testing)

**Risk Rating**  
Critical

**Remediation**
- Enforce authorization checks on every endpoint that accesses objects by ID.
- Use unpredictable identifiers (e.g., UUID v4).
- Derive the object ID from the session context where possible (e.g., `/me/orders`).

---

## 2. IDOR VIA UUID/GUID OBJECT IDENTIFIERS IN URL PATH

**Description**  
Even when using UUIDs, developers often assume they are unguessable and skip authorization checks. However, UUIDs can be leaked, guessed (v1), or brute‑forced (if short).

**What to Look For**
- UUIDs in URLs: `/api/users/550e8400-e29b-41d4-a716-446655440000`.
- UUID version 1 (timestamp‑based) may be predictable.
- UUIDs exposed in client‑side code (JavaScript, HTML, or in other API responses).

**What to Ignore**
- Cryptographically random UUIDs (v4) with proper server‑side authorization.

**How to Test with Burp Suite**
1. Collect multiple UUIDs from the application (e.g., by creating resources).
2. Analyze UUID version (13th character: `1` = v1, `4` = v4).
3. If v1, attempt to predict other UUIDs (timestamps may be guessable).
4. Even if v4, test IDOR by swapping UUIDs between users (if you have two different users’ UUIDs).
5. Use Burp Intruder with a list of known UUIDs (from enumeration) to test access.

**Example**
```http
GET /api/invoices/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
Authorization: Bearer USER_A_TOKEN
```
Replace with another user’s invoice UUID; if accessible, BOLA exists.

**Tools**
- Burp Repeater
- UUID version detection tools
- Custom scripts for UUID generation

**Risk Rating**  
High

**Remediation**
- Always implement authorization checks regardless of identifier type.
- Use UUID v4 and treat them as opaque identifiers (still need access control).

---

## 3. IDOR VIA OBJECT IDENTIFIERS IN QUERY PARAMETERS

**Description**  
Some APIs pass object identifiers as query parameters rather than in the URL path (e.g., `GET /api/profile?user_id=123`). These are equally vulnerable.

**What to Look For**
- Parameters like `id=`, `user_id=`, `account_id=`, `resource_id=` in query strings.
- POST bodies may also contain such parameters (covered in next section).

**What to Ignore**
- Parameters that are not used to directly fetch or modify objects.

**How to Test with Burp Suite**
1. Identify API endpoints with object ID parameters in the query string.
2. Change the parameter value to another user’s ID.
3. Observe if you receive that user’s data.

**Example**
```http
GET /api/account/settings?account_id=456 HTTP/1.1
Authorization: Bearer USER_A_TOKEN
```
Change `account_id=456` to `account_id=457`.

**Tools**
- Burp Repeater
- Burp Intruder (for parameter fuzzing)

**Risk Rating**  
Critical

**Remediation**
- Same as path‑based IDOR: enforce authorization checks on the server.
- Avoid exposing object IDs as direct query parameters; use session context.

---

## 4. IDOR VIA OBJECT IDENTIFIERS IN REQUEST BODY (JSON/XML)

**Description**  
APIs often accept object identifiers in the request body for POST, PUT, PATCH, or DELETE operations. Attackers can modify these identifiers to act on other users’ objects.

**What to Look For**
- JSON fields like `"user_id": 123`, `"order_id": 456`, `"resource": {"id": 789}`.
- PATCH requests that update a specific object identified by an ID in the body.

**What to Ignore**
- The object ID is taken from the URL path and not also trusted from the body.

**How to Test with Burp Suite**
1. Capture a request that modifies or deletes an object (e.g., `PUT /api/profile`).
2. Change the `user_id` or `id` field in the JSON body to another user’s ID.
3. Send the request and see if the operation affects the other user’s object.

**Example**
```http
PUT /api/profile HTTP/1.1
Content-Type: application/json

{"user_id": 124, "email": "attacker@evil.com"}
```
If user 124’s email changes, BOLA exists.

**Tools**
- Burp Repeater
- Burp Intruder

**Risk Rating**  
Critical

**Remediation**
- Do not trust object IDs from the request body for authorization.
- Use the ID from the URL path or from the authenticated session.

---

## 5. IDOR VIA NESTED OR COMPOSITE OBJECT REFERENCES

**Description**  
Some APIs use composite keys (e.g., `tenant_id` + `user_id`) or nested objects. Attackers must manipulate multiple identifiers to exploit BOLA.

**What to Look For**
- Hierarchical resources: `/companies/{companyId}/departments/{deptId}/employees/{empId}`.
- JSON objects with multiple ID fields.

**What to Ignore**
- Proper validation that all IDs belong to the same tenant/user.

**How to Test with Burp Suite**
1. Test each ID parameter individually (change one at a time).
2. Test cross‑hierarchy combinations (e.g., `companyId=1&deptId=5` where dept 5 belongs to company 2).
3. Use Burp Intruder with multiple payload positions (Cluster Bomb).

**Example**
```http
GET /api/companies/1/departments/2/employees/123 HTTP/1.1
```
Try `employees/124` (same company/dept), then try `departments/3`, etc.

**Tools**
- Burp Intruder (Cluster Bomb)
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Validate that all supplied IDs are consistent with the authenticated user’s access rights.
- Use a single resource ID (e.g., a global UUID) instead of composite keys.

---

## 6. IDOR VIA BATCH/GRAPHQL OPERATIONS

**Description**  
APIs that support batch requests (multiple operations in one call) or GraphQL may expose BOLA where a user can mix authorized and unauthorized object IDs.

**What to Look For**
- Batch endpoints: `POST /api/batch` with an array of requests.
- GraphQL queries that request multiple objects by ID (e.g., `query { user(id:1) { name }, user(id:2) { name } }`).

**What to Ignore**
- Batch/GraphQL endpoints that enforce authorization per object.

**How to Test with Burp Suite**
1. For GraphQL, send a query that requests two user profiles: one belonging to you and one to another user.
2. If both are returned, BOLA exists.
3. For batch APIs, include one legitimate request and one request for another user’s object.

**Example**
```graphql
query {
  user(id: 123) { name email }
  user(id: 124) { name email }
}
```

**Tools**
- Burp Repeater
- GraphQL IDE or GraphQL Raider extension

**Risk Rating**  
Critical

**Remediation**
- Implement authorization checks for each object accessed in a batch or GraphQL query.
- Limit batch sizes and validate all requested IDs.

---

## 7. IDOR VIA FILE DOWNLOAD ENDPOINTS (DOCUMENT, IMAGE, EXPORT)

**Description**  
APIs that serve files (e.g., `/api/download?file_id=123`) are often vulnerable to BOLA, allowing users to download other users’ files.

**What to Look For**
- Endpoints with parameters like `file_id`, `document_id`, `attachment_id`, `export_id`.
- File naming patterns that include user identifiers (e.g., `/uploads/user_123/invoice.pdf`).

**What to Ignore**
- Signed, time‑limited URLs or authorization checks on file access.

**How to Test with Burp Suite**
1. Upload a file as User A, note the `file_id`.
2. Upload another file as User B, note its `file_id`.
3. As User A, try to download User B’s file by changing the `file_id`.
4. If successful, BOLA exists.

**Example**
```http
GET /api/documents/download?doc_id=789 HTTP/1.1
Authorization: Bearer USER_A_TOKEN
```
Change `doc_id` to a document owned by User B.

**Tools**
- Burp Repeater
- Burp Intruder (for ID enumeration)

**Risk Rating**  
Critical

**Remediation**
- Implement authorization checks on every file access endpoint.
- Store files with random names and map them to user IDs server‑side.
- Use indirect references (e.g., database mapping).

---

## 8. IDOR VIA FILE UPLOAD ENDPOINTS (OVERWRITE OTHERS' FILES)

**Description**  
File upload APIs may allow users to specify a filename or file ID, enabling them to overwrite other users’ files.

**What to Look For**
- Upload endpoints that accept a `file_id` or `filename` parameter.
- APIs that allow specifying the destination path or ID.

**What to Ignore**
- Uploads that always generate a new, unique ID not controllable by the user.

**How to Test with Burp Suite**
1. As User A, upload a file and capture the request.
2. Change the `file_id` or `filename` to a value belonging to User B (if you know it).
3. If the file is overwritten, BOLA exists.

**Example**
```http
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data

file_id=456&file=@malicious.txt
```
If `456` is User B’s file, it may be overwritten.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Do not allow clients to specify file IDs or paths.
- Always generate new, unique identifiers on the server.

---

## 9. IDOR VIA API PARAMETERS THAT ACCEPT USERNAMES OR EMAILS

**Description**  
Some APIs use usernames or email addresses as object identifiers. Attackers can guess or enumerate valid usernames to access others’ data.

**What to Look For**
- Parameters like `username=`, `email=`, `user_email=` in API requests.
- Endpoints like `/api/user?email=user@example.com`.

**What to Ignore**
- Email or username used only for login, not for direct object access, or with proper authorization.

**How to Test with Burp Suite**
1. As User A, try to fetch a profile using another user’s email address.
2. If the API returns that user’s data, BOLA exists.

**Example**
```http
GET /api/user/profile?email=victim@example.com HTTP/1.1
Authorization: Bearer USER_A_TOKEN
```

**Tools**
- Burp Repeater
- Email/username enumeration

**Risk Rating**  
High

**Remediation**
- Do not allow direct lookup of users by email unless the requester is an admin or the target is the same as the authenticated user.

---

## 10. IDOR VIA BUSINESS RESOURCE (ORDERS, INVOICES, TRANSACTIONS)

**Description**  
Business resources (orders, invoices, transactions, payments) are prime targets for BOLA because they often contain sensitive financial data.

**What to Look For**
- Endpoints like `/api/orders/{orderId}`, `/api/invoices/{invoiceId}`, `/api/transactions/{txnId}`.

**What to Ignore**
- Orders that are tied to the authenticated user’s session and validated.

**How to Test with Burp Suite**
1. Place an order as User A, capture the order ID.
2. Place another order as User B, capture that order ID.
3. As User A, try to access User B’s order details.
4. If successful, BOLA exists.

**Example**
```http
GET /api/orders/9876 HTTP/1.1
Authorization: Bearer USER_A_TOKEN
```
Change to `9877` (User B’s order).

**Tools**
- Burp Repeater
- Burp Intruder (to enumerate order IDs)

**Risk Rating**  
Critical

**Remediation**
- Always verify that the order belongs to the authenticated user.
- Use session‑based identifiers instead of global order IDs in URLs.

---

## 11. IDOR VIA USER PROFILE OR ACCOUNT SETTINGS ENDPOINTS

**Description**  
Profile and account settings APIs often allow users to view or modify their own data. BOLA occurs when one user can access or modify another’s profile.

**What to Look For**
- Endpoints like `/api/profile/{userId}`, `/api/settings?user_id=123`.
- PATCH requests that update user attributes.

**What to Ignore**
- Endpoints that derive the user ID from the session token (e.g., `/api/me`).

**How to Test with Burp Suite**
1. Log in as User A and capture a profile view request.
2. Change the user ID to that of User B.
3. If User B’s profile is returned or modified, BOLA exists.

**Example**
```http
PUT /api/users/124/profile HTTP/1.1
Authorization: Bearer USER_A_TOKEN
{"email": "new@evil.com"}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Use a dedicated `/me` endpoint that derives the user ID from the session.
- For admin endpoints, enforce role‑based access control.

---

## 12. IDOR VIA ADMINISTRATIVE RESOURCES (USER MANAGEMENT, LOGS)

**Description**  
Administrative APIs (user management, audit logs, system configuration) are especially critical. BOLA here can lead to full system compromise.

**What to Look For**
- Endpoints like `/api/admin/users`, `/api/audit-logs`, `/api/system/config`.
- Admin endpoints may have weak or missing authorization.

**What to Ignore**
- Admin endpoints properly protected by role checks and multi‑factor authentication.

**How to Test with Burp Suite**
1. Log in as a regular user.
2. Attempt to access admin endpoints (e.g., `GET /api/admin/users`).
3. If you can list or modify other users, BOLA exists.

**Example**
```http
DELETE /api/admin/users/123 HTTP/1.1
Authorization: Bearer REGULAR_USER_TOKEN
```

**Tools**
- Burp Repeater
- Autorize extension

**Risk Rating**  
Critical

**Remediation**
- Implement role‑based access control (RBAC) with server‑side enforcement.
- Use separate API paths with dedicated middleware for admin functions.

---

## 13. IDOR VIA TIME‑BASED OR SEQUENTIAL TOKENS

**Description**  
Some APIs use time‑based tokens (e.g., JWTs with predictable claims) or sequential tokens that can be guessed, leading to BOLA.

**What to Look For**
- Tokens that contain user ID or other object references in plaintext.
- Sequential or timestamp‑based token generation.

**What to Ignore**
- Cryptographically random tokens.

**How to Test with Burp Suite**
1. Collect several tokens (e.g., password reset tokens, shareable links).
2. Use Burp Sequencer to analyze randomness.
3. If tokens are sequential or predictable, attempt to guess another user’s token.

**Example**
```
Reset token: 1001, 1002, 1003...
```
Attacker can guess `1004` for another user.

**Tools**
- Burp Sequencer
- Burp Intruder

**Risk Rating**  
High

**Remediation**
- Use cryptographically secure random tokens.
- Do not embed object IDs directly in tokens (use server‑side mapping).

---

## 14. IDOR VIA ENCODED OR HASHED OBJECT IDENTIFIERS (BASE64, JWT)

**Description**  
Developers may encode object IDs (e.g., base64, JWT) hoping to hide them, but these can be easily decoded and manipulated.

**What to Look For**
- Base64‑encoded IDs: `eyJpZCI6MTIzfQ==`.
- JWTs that contain object IDs in the payload.

**What to Ignore**
- Properly signed and validated JWTs where the ID is not user‑controlled.

**How to Test with Burp Suite**
1. Decode the ID using Burp Decoder or jwt.io.
2. Modify the decoded value (e.g., change user ID from 123 to 124).
3. Re‑encode and send.
4. If the server accepts the modified ID, BOLA exists.

**Example**
```http
GET /api/user/eyJpZCI6MTIzfQ== HTTP/1.1
```
Decodes to `{"id":123}`. Change to `{"id":124}` and re‑encode.

**Tools**
- Burp Decoder
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Never rely on encoding for security.
- Use server‑side mapping (indirect references) and enforce authorization.

---

## 15. IDOR VIA PATH TRAVERSAL IN OBJECT IDENTIFIERS

**Description**  
Some APIs construct file paths or resource locators using user input. Attackers can use path traversal (`../`) to access resources outside the intended directory.

**What to Look For**
- Parameters like `file=user123/doc.pdf` where the path is built by the server.
- Endpoints that serve static files based on user input.

**What to Ignore**
- Proper sanitization and use of allowlists.

**How to Test with Burp Suite**
1. Inject `../` sequences to traverse directories.
2. Example: `GET /api/files?path=../../config/secrets.json`.
3. If the server returns the file, BOLA via path traversal exists.

**Example**
```http
GET /api/download?file=../../../etc/passwd HTTP/1.1
```

**Tools**
- Burp Repeater
- Path traversal wordlists

**Risk Rating**  
Critical

**Remediation**
- Do not construct file paths from user input.
- Use a database mapping from an opaque identifier to the actual file path.

---

## 16. IDOR VIA HTTP METHOD OVERRIDE (GET TO POST, POST TO PUT)

**Description**  
Some APIs enforce authorization only on certain HTTP methods (e.g., POST for update). Attackers can change the method to bypass checks.

**What to Look For**
- Different authorization logic for GET, POST, PUT, DELETE.
- Support for method override headers (`X-HTTP-Method-Override`).

**What to Ignore**
- Consistent authorization across all methods.

**How to Test with Burp Suite**
1. Capture a request that modifies a resource (e.g., `POST /api/user/123`).
2. Change the method to GET and move parameters to the URL.
3. If the server processes the request, authorization may be bypassed.

**Example**
```http
GET /api/user/123?email=new@evil.com HTTP/1.1
```
If the user’s email is updated, vulnerable.

**Tools**
- Burp Repeater
- Method override headers

**Risk Rating**  
High

**Remediation**
- Apply the same authorization logic to all HTTP methods.
- Follow REST semantics (GET should not modify state).

---

## 17. IDOR VIA VERSIONED API ENDPOINTS (V1 VS V2 DIFFERENCES)

**Description**  
Older API versions (v1) may lack proper authorization while newer versions (v2) are fixed. Attackers can target the older version.

**What to Look For**
- Multiple API versions: `/api/v1/users/123`, `/api/v2/users/123`.
- Different behavior between versions.

**What to Ignore**
- Consistent authorization across all versions.

**How to Test with Burp Suite**
1. Test an endpoint in the latest version; if protected, try the same in an older version (e.g., `/api/v1/...`).
2. If the older version returns data without proper authorization, BOLA exists.

**Example**
```http
GET /api/v1/users/124 HTTP/1.1
```
V1 may not check ownership, while V2 does.

**Tools**
- Burp Repeater
- API version enumeration

**Risk Rating**  
High

**Remediation**
- Apply consistent authorization across all API versions.
- Deprecate and remove vulnerable versions.

---

## 18. IDOR VIA FILTER OR SEARCH PARAMETERS (LISTING ALL OBJECTS)

**Description**  
Search or filter endpoints may return objects belonging to other users if proper scoping is missing.

**What to Look For**
- Endpoints like `/api/search?q=*`, `/api/orders?status=all`.
- No user context applied to the query.

**What to Ignore**
- Search endpoints that always filter by the authenticated user.

**How to Test with Burp Suite**
1. As User A, perform a search that should only return User A’s resources.
2. Modify parameters to try to fetch all resources (e.g., `?user_id=*`, `?scope=all`).
3. If you see other users’ resources, BOLA exists.

**Example**
```http
GET /api/transactions?account_id=* HTTP/1.1
```

**Tools**
- Burp Repeater
- Burp Intruder (for parameter fuzzing)

**Risk Rating**  
High

**Remediation**
- Always filter search results by the authenticated user’s context.
- Do not allow wildcards or cross‑user queries.

---

## 19. IDOR VIA GRAPHQL FIELD‑LEVEL QUERIES (UNAUTHORIZED FIELD ACCESS)

**Description**  
GraphQL APIs may allow users to request fields on objects they should not access, even if the object itself is allowed.

**What to Look For**
- GraphQL queries that request sensitive fields (`email`, `phone`, `ssn`) on an object the user can access partially.
- No field‑level authorization.

**What to Ignore**
- Field‑level authorization or restriction of sensitive fields.

**How to Test with Burp Suite**
1. Query an object you are allowed to access (e.g., your own profile).
2. Add fields that should be restricted (e.g., `internal_notes`, `password_hash`).
3. If the API returns those fields, field‑level BOLA exists.

**Example**
```graphql
query {
  user(id: 123) {
    name
    passwordHash
    ssn
  }
}
```

**Tools**
- GraphQL Raider
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Implement field‑level authorization in GraphQL resolvers.
- Use a schema that excludes sensitive fields for non‑privileged users.

---

## 20. IDOR VIA GRAPHQL OBJECT IDENTIFICATION (NODE INTERFACE)

**Description**  
GraphQL’s node interface (global object identification) often uses opaque IDs. Attackers may decode or enumerate these IDs to access unauthorized objects.

**What to Look For**
- `node(id: "base64encoded")` queries.
- Global ID format that reveals object type and internal ID (e.g., `"VXNlcjoxMjM="` decodes to `User:123`).

**What to Ignore**
- Global IDs that are cryptographically random and validated server‑side.

**How to Test with Burp Suite**
1. Decode a global ID to see if it reveals type and numeric ID.
2. Modify the numeric portion and re‑encode.
3. Query the node with the modified ID.
4. If the API returns a different user’s object, BOLA exists.

**Example**
```
GlobalID: VXNlcjoxMjM= (decodes to "User:123")
Change to VXNlcjoxMjQ= ("User:124")
```
Query `node(id: "VXNlcjoxMjQ=")`.

**Tools**
- Burp Decoder
- GraphQL ID enumeration

**Risk Rating**  
High

**Remediation**
- Use random, unguessable global IDs.
- Enforce authorization in the node resolver.

---

## 21. IDOR VIA WEBSOCKET MESSAGES (REAL‑TIME UPDATES)

**Description**  
WebSocket APIs may allow users to subscribe to channels or send messages with object IDs, leading to BOLA.

**What to Look For**
- WebSocket messages containing `user_id`, `room_id`, `document_id`.
- Subscription to topics like `user/123/updates`.

**What to Ignore**
- Authorization checks on every WebSocket message.

**How to Test with Burp Suite**
1. Intercept WebSocket messages using Burp.
2. Modify object IDs in subscription or action messages.
3. If you receive updates for another user, BOLA exists.

**Example**
```json
{"subscribe": "user/124/updates"}
```

**Tools**
- Burp Suite (WebSocket support)
- Custom WebSocket clients

**Risk Rating**  
High

**Remediation**
- Validate user authorization for every WebSocket message.
- Use server‑assigned session IDs, not client‑supplied IDs.

---

## 22. IDOR VIA API RATE LIMIT BYPASS FOR ENUMERATION

**Description**  
To exploit BOLA, attackers often need to enumerate valid object IDs. Weak rate limiting allows mass enumeration.

**What to Look For**
- No rate limiting on endpoints that accept object IDs.
- Ability to send many requests without interruption.

**What to Ignore**
- Rate limiting that prevents enumeration.

**How to Test with Burp Suite**
1. Use Intruder to send many requests with sequential IDs.
2. If all requests are processed without blocking, rate limiting is insufficient.
3. Use the responses to map valid IDs, then exploit BOLA.

**Example**
```http
GET /api/user/1
GET /api/user/2
... (1000 requests)
```

**Tools**
- Burp Intruder / Turbo Intruder

**Risk Rating**  
Medium

**Remediation**
- Implement rate limiting on enumeration‑prone endpoints.
- Use unpredictable identifiers.

---

## 23. IDOR VIA CROSS‑TENANT OBJECT ACCESS (MULTI‑TENANCY BYPASS)

**Description**  
In multi‑tenant SaaS applications, users from one tenant should not access objects from another tenant. BOLA can occur when tenant context is missing.

**What to Look For**
- Parameters like `tenant_id`, `company_id`, `org_id`.
- Subdomain‑based tenants (`tenant1.app.com`, `tenant2.app.com`).

**What to Ignore**
- Proper tenant isolation with context derived from session.

**How to Test with Burp Suite**
1. Log in as a user in Tenant A.
2. Change the `tenant_id` parameter to Tenant B’s ID.
3. If you can access Tenant B’s resources, cross‑tenant BOLA exists.

**Example**
```http
GET /api/companies/456/employees HTTP/1.1
Authorization: Bearer USER_FROM_COMPANY_123
```

**Tools**
- Burp Repeater
- Burp Intruder for tenant ID enumeration

**Risk Rating**  
Critical

**Remediation**
- Always derive tenant context from the authenticated session.
- Do not trust tenant IDs from the client.

---

## 24. IDOR VIA REFERER HEADER OR CUSTOM HEADERS MANIPULATION

**Description**  
Some APIs use the `Referer` header or custom headers (e.g., `X-Original-URI`) to make authorization decisions. Attackers can spoof these headers.

**What to Look For**
- Authorization logic that depends on `Referer`, `X-Forwarded-For`, or `X-Original-URL`.

**What to Ignore**
- Headers not used for authorization.

**How to Test with Burp Suite**
1. Capture a request to an API endpoint.
2. Modify the `Referer` header to point to an admin page.
3. If the API grants access, BOLA exists.

**Example**
```http
GET /api/admin/users HTTP/1.1
Referer: https://admin.target.com/dashboard
```

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Do not rely on headers for authorization.
- Use proper authentication tokens and session validation.

---

## 25. IDOR VIA SESSION OR TOKEN CONTEXT CONFUSION

**Description**  
When an application uses both session cookies and bearer tokens, a user may be able to mix contexts to access objects belonging to a different session.

**What to Look For**
- APIs that accept both cookie and token authentication.
- Lack of binding between the token and the user ID.

**What to Ignore**
- Single authentication mechanism with strong user binding.

**How to Test with Burp Suite**
1. Log in as User A, capture a valid session cookie.
2. Log in as User B, capture a bearer token.
3. Send a request using User A’s cookie and User B’s token.
4. If the server accepts it, context confusion exists.

**Example**
```http
GET /api/user/124 HTTP/1.1
Cookie: session=USER_A_SESSION
Authorization: Bearer USER_B_TOKEN
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Use a single, consistent authentication mechanism.
- Bind the session/token to a specific user ID and validate on every request.

---

## 26. IDOR VIA INSECURE DIRECT OBJECT REFERENCE IN CALLBACK URLS

**Description**  
APIs that accept callback URLs with object IDs (e.g., webhook endpoints) may expose BOLA where an attacker can trigger actions on another user’s behalf.

**What to Look For**
- Webhook registration endpoints that allow specifying a URL with an object ID.
- Callbacks that include object identifiers in the path.

**What to Ignore**
- Callbacks that are signed and validated.

**How to Test with Burp Suite**
1. Register a webhook with a URL that includes another user’s object ID.
2. Trigger the event that sends the callback.
3. If the callback is sent and the object is modified, BOLA exists.

**Example**
```http
POST /api/webhooks
{"url": "http://evil.com/callback?user_id=124"}
```

**Tools**
- Burp Repeater
- Public callback listener

**Risk Rating**  
Medium

**Remediation**
- Do not include object IDs in callback URLs; use opaque tokens.
- Validate that the callback initiator is authorized.

---

## 27. IDOR VIA MOBILE API ENDPOINTS (LESS SECURE THAN WEB)

**Description**  
Mobile apps often use different API endpoints or older versions that may have weaker authorization than the web version.

**What to Look For**
- API endpoints like `/mobile/api/...`, `/v1/mobile/...`.
- Differences in request structure between mobile and web.

**What to Ignore**
- Consistent security across all client types.

**How to Test with Burp Suite**
1. Intercept traffic from the mobile app (using Burp’s mobile setup).
2. Identify API endpoints not used by the web app.
3. Test those endpoints for BOLA using the same techniques.

**Example**
```http
GET /mobile/api/user/124 HTTP/1.1
```

**Tools**
- Burp Suite (mobile configuration)
- Frida (for SSL pinning bypass)

**Risk Rating**  
High

**Remediation**
- Apply the same authorization logic across all API versions and client types.

---

## 28. IDOR VIA INTERNAL API ENDPOINTS (EXPOSED TO FRONTEND)

**Description**  
Some APIs intended for internal use (e.g., microservices) are accidentally exposed to frontend clients and may lack authorization.

**What to Look For**
- Endpoints with paths like `/internal/`, `/admin/`, `/system/`, `/debug/`.
- APIs that are not documented but are called by the frontend.

**What to Ignore**
- Properly authenticated internal APIs.

**How to Test with Burp Suite**
1. Browse the application and observe all API calls.
2. Look for endpoints that seem internal (e.g., `/internal/user/list`).
3. Test them for BOLA by modifying object IDs.

**Example**
```http
GET /internal/user/124 HTTP/1.1
```

**Tools**
- Burp Proxy
- API discovery tools

**Risk Rating**  
Critical

**Remediation**
- Do not expose internal APIs to frontend clients.
- Apply strict authentication and authorization to all endpoints.

---

## 29. IDOR VIA OBJECT REFERENCE LEAKAGE IN RESPONSE (PREVIOUS/NEXT LINKS)

**Description**  
API responses may include links to related objects (e.g., `"next": "/api/users/124"`). An attacker can use these to discover other object IDs.

**What to Look For**
- Pagination links containing object IDs.
- Responses that include IDs of other users (e.g., `"created_by": 123`).

**What to Ignore**
- Responses that do not leak other users’ IDs.

**How to Test with Burp Suite**
1. Request a list of your own objects (e.g., `/api/my/orders`).
2. Examine the response for any foreign IDs (e.g., `"user_id": 124`).
3. Use those IDs to test BOLA on other endpoints.

**Example**
```json
{"order_id": 1001, "user_id": 124}
```
Now try `GET /api/orders/1001` with your own token.

**Tools**
- Burp Proxy
- Manual inspection

**Risk Rating**  
Medium

**Remediation**
- Do not expose foreign object IDs in responses.
- If necessary, use indirect references.

---

## 30. IDOR VIA MASS ASSIGNMENT COMBINED WITH OBJECT REFERENCES

**Description**  
Mass assignment vulnerabilities can allow an attacker to change the object ID of a resource being updated, leading to BOLA.

**What to Look For**
- Endpoints that accept extra parameters, including `id` or `user_id`.
- Frameworks that auto‑bind request parameters to model attributes.

**What to Ignore**
- Explicit whitelisting of allowed parameters.

**How to Test with Burp Suite**
1. Capture an update request (e.g., `PATCH /api/profile`).
2. Add an extra parameter: `"user_id": 124`.
3. If the server updates user 124’s profile instead of yours, BOLA exists.

**Example**
```http
PATCH /api/profile HTTP/1.1
{"name": "New Name", "user_id": 124}
```

**Tools**
- Burp Repeater
- Param Miner

**Risk Rating**  
Critical

**Remediation**
- Protect against mass assignment (whitelist allowed fields).
- Derive the object ID from the session, not from the request body.

---

## ✅ **SUMMARY**

Broken Object Level Authorization (BOLA) is the most critical and common API vulnerability. Attackers exploit missing or flawed authorization checks to access or modify resources belonging to other users. This guide covers 30 distinct BOLA vectors and testing techniques.

### **Key Testing Areas Summary**

| BOLA Vector | Key Indicators | Risk |
|-------------|----------------|------|
| Numeric IDs in Path | `/users/123` | Critical |
| UUIDs in Path | `/users/550e8400-...` | High |
| Query Parameter IDs | `?user_id=123` | Critical |
| Request Body IDs | `{"user_id": 123}` | Critical |
| Composite Keys | Multiple ID parameters | High |
| Batch/GraphQL | Mixing IDs | Critical |
| File Download | `?file_id=123` | Critical |
| File Upload | Overwrite by ID | High |
| Username/Email | `?email=victim@` | High |
| Business Resources | Orders, invoices | Critical |
| Profile Endpoints | `/profile/{id}` | Critical |
| Admin Endpoints | `/admin/users` | Critical |
| Predictable Tokens | Sequential tokens | High |
| Encoded IDs | Base64, JWT | High |
| Path Traversal | `../` in ID | Critical |
| Method Override | GET instead of POST | High |
| Versioned APIs | V1 vs V2 differences | High |
| Search Parameters | `?scope=all` | High |
| GraphQL Fields | Sensitive field access | High |
| GraphQL Node | Global ID enumeration | High |
| WebSocket | Subscription to other IDs | High |
| Rate Limit Bypass | Enumeration possible | Medium |
| Cross‑Tenant | `tenant_id` tampering | Critical |
| Header Manipulation | `Referer` spoofing | Medium |
| Context Confusion | Mixed auth mechanisms | High |
| Callback URLs | Webhook with ID | Medium |
| Mobile APIs | Weaker endpoints | High |
| Internal APIs | Exposed to frontend | Critical |
| Leaked References | Pagination links | Medium |
| Mass Assignment | Extra `user_id` param | Critical |

### **Pro Tips for Testing BOLA**
1. **Use Autorize / AuthMatrix extensions** – automate testing of different user sessions.
2. **Create multiple test accounts** – at least two users with different privilege levels.
3. **Fuzz for ID parameters** – use Param Miner to discover hidden parameters.
4. **Enumerate IDs** – if numeric, test range (e.g., 1‑1000). If UUID, look for patterns.
5. **Test all HTTP methods** – GET, POST, PUT, PATCH, DELETE.
6. **Check for IDOR in indirect references** – pagination, search results, GraphQL node queries.
7. **Automate with Burp Intruder** – send requests with different IDs and compare responses.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
