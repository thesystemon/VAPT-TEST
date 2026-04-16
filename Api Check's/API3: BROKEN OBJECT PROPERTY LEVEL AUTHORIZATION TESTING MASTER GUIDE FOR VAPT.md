# 🔓 **API3: BROKEN OBJECT PROPERTY LEVEL AUTHORIZATION TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Object Property Exposure & Mass Assignment Flaws in APIs*

---

## 📋 **TABLE OF CONTENTS**

1. [Excessive Data Exposure – Returned Properties Include Sensitive Fields](#1-excessive-data-exposure--returned-properties-include-sensitive-fields)
2. [Mass Assignment – Extra Properties Accepted in Request Body (Create)](#2-mass-assignment--extra-properties-accepted-in-request-body-create)
3. [Mass Assignment – Extra Properties Accepted in Request Body (Update)](#3-mass-assignment--extra-properties-accepted-in-request-body-update)
4. [Hidden Properties Exposed via API Versioning Differences](#4-hidden-properties-exposed-via-api-versioning-differences)
5. [Sensitive Properties Exposed in GraphQL Responses (Over‑fetching)](#5-sensitive-properties-exposed-in-graphql-responses-over-fetching)
6. [GraphQL Introspection Revealing Sensitive Field Names](#6-graphql-introspection-revealing-sensitive-field-names)
7. [Exposure of Internal Properties via `__proto__` or `constructor` in JSON](#7-exposure-of-internal-properties-via-__proto__-or-constructor-in-json)
8. [Property Exposure in Nested Objects (Deep JSON Responses)](#8-property-exposure-in-nested-objects-deep-json-responses)
9. [Mass Assignment via PATCH with Partial Updates (JSON Patch)](#9-mass-assignment-via-patch-with-partial-updates-json-patch)
10. [Exposure of Calculated or Derived Properties (e.g., `isAdmin`)](#10-exposure-of-calculated-or-derived-properties)
11. [Property Exposure in Array Responses (Listing Endpoints)](#11-property-exposure-in-array-responses-listing-endpoints)
12. [Exposure of User‑Specific Properties in Shared Objects](#12-exposure-of-user-specific-properties-in-shared-objects)
13. [Mass Assignment via `_method` Parameter (HTTP Method Override)](#13-mass-assignment-via-_method-parameter-http-method-override)
14. [Sensitive Properties in Error Messages or Validation Responses](#14-sensitive-properties-in-error-messages-or-validation-responses)
15. [Property Exposure in API Documentation (Swagger/OpenAPI)](#15-property-exposure-in-api-documentation-swaggeropenapi)
16. [Mass Assignment via Query String Parameters (Form Data)](#16-mass-assignment-via-query-string-parameters-form-data)
17. [Property Exposure in Batch API Responses (Multiple Objects)](#17-property-exposure-in-batch-api-responses-multiple-objects)
18. [Mass Assignment via XML Payloads (XXE Combined)](#18-mass-assignment-via-xml-payloads-xxe-combined)
19. [Exposure of Properties Intended Only for Internal Use (e.g., `internal_id`)](#19-exposure-of-properties-intended-only-for-internal-use)
20. [Mass Assignment via CSV or File Upload Imports](#20-mass-assignment-via-csv-or-file-upload-imports)
21. [Property Exposure in WebSocket Messages (Real‑Time Updates)](#21-property-exposure-in-websocket-messages-real-time-updates)
22. [Mass Assignment via GraphQL Input Object Injection](#22-mass-assignment-via-graphql-input-object-injection)
23. [Exposure of Properties via Different User Roles (Vertical Privilege)](#23-exposure-of-properties-via-different-user-roles-vertical-privilege)
24. [Mass Assignment via Array of Objects (Multiple Resources)](#24-mass-assignment-via-array-of-objects-multiple-resources)
25. [Property Exposure via Pagination or Sorting Parameters](#25-property-exposure-via-pagination-or-sorting-parameters)
26. [Mass Assignment via Content-Type Switching (JSON to XML)](#26-mass-assignment-via-content-type-switching-json-to-xml)
27. [Exposure of Properties via Headers or Custom Response Fields](#27-exposure-of-properties-via-headers-or-custom-response-fields)
28. [Mass Assignment via Null or Empty Value Injection](#28-mass-assignment-via-null-or-empty-value-injection)
29. [Property Exposure via GraphQL Field Aliasing](#29-property-exposure-via-graphql-field-aliasing)
30. [Mass Assignment via Default Values Not Properly Sanitized](#30-mass-assignment-via-default-values-not-properly-sanitized)

---

## 1. EXCESSIVE DATA EXPOSURE – RETURNED PROPERTIES INCLUDE SENSITIVE FIELDS

**Description**  
APIs often return entire database objects, including sensitive fields (passwords, API keys, internal IDs, email addresses, phone numbers) that the client does not need and should not see.

**What to Look For**
- Response JSON/XML contains fields like `password_hash`, `ssn`, `credit_card`, `api_key`, `internal_id`, `reset_token`.
- More data returned than necessary for the client functionality.

**What to Ignore**
- Responses that only include necessary, non‑sensitive fields.

**How to Test with Burp Suite**
1. Intercept API responses and examine the JSON/XML structure.
2. Look for field names that indicate sensitive data (e.g., `password`, `token`, `secret`, `ssn`, `credit_card`).
3. Compare the response for different user roles (admin vs regular user) to see if sensitive fields are filtered.

**Example**
```json
{
  "id": 123,
  "username": "john",
  "email": "john@example.com",
  "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
  "ssn": "123-45-6789"
}
```
`password_hash` and `ssn` should not be exposed.

**Tools**
- Burp Proxy (manual inspection)
- Burp Scanner (passive)
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Use view models or DTOs that include only the fields needed by the client.
- Never return sensitive fields from the database.

---

## 2. MASS ASSIGNMENT – EXTRA PROPERTIES ACCEPTED IN REQUEST BODY (CREATE)

**Description**  
Mass assignment occurs when an API automatically binds all request parameters to internal object properties, allowing attackers to add extra fields (e.g., `role`, `isAdmin`, `balance`) that they should not be able to set.

**What to Look For**
- Endpoints that create resources (POST /api/users, POST /api/orders).
- Frameworks known to auto‑bind parameters (Rails, Laravel, Spring MVC).

**What to Ignore**
- Explicit whitelisting of allowed fields (`$fillable`, `@Validated`).

**How to Test with Burp Suite**
1. Capture a request that creates a resource (e.g., user registration).
2. Add an extra property that should not be settable (e.g., `"role": "admin"`, `"isAdmin": true`, `"balance": 99999`).
3. Send the request and check if the extra property is applied (e.g., user becomes admin).

**Example**
```http
POST /api/users HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@evil.com",
  "password": "password123",
  "role": "admin"
}
```
If the user is created with admin role, mass assignment is possible.

**Tools**
- Burp Repeater
- Param Miner

**Risk Rating**  
Critical

**Remediation**
- Whitelist allowed fields for each endpoint.
- Use data transfer objects (DTOs) that define exactly which fields can be set.

---

## 3. MASS ASSIGNMENT – EXTRA PROPERTIES ACCEPTED IN REQUEST BODY (UPDATE)

**Description**  
Similar to create, update endpoints (PUT, PATCH) may allow attackers to modify fields they should not control, such as `account_balance`, `is_admin`, or `user_id`.

**What to Look For**
- PUT or PATCH endpoints that update resources (e.g., `/api/users/123`).
- No server‑side validation of which fields can be updated.

**What to Ignore**
- Explicit whitelist of updatable fields.

**How to Test with Burp Suite**
1. Capture an update request for a resource you own.
2. Add an extra property (e.g., `"isAdmin": true`, `"credit_limit": 99999`).
3. Send the request and check if the property is updated.

**Example**
```http
PATCH /api/users/123 HTTP/1.1
Content-Type: application/json

{
  "email": "new@example.com",
  "isAdmin": true
}
```
If the user becomes admin, vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Whitelist allowed update fields.
- Use PATCH with JSON Patch (RFC 6902) and validate each operation.

---

## 4. HIDDEN PROPERTIES EXPOSED VIA API VERSIONING DIFFERENCES

**Description**  
Older API versions (v1) may expose more fields than newer versions (v2), and attackers can target the older version to access sensitive data.

**What to Look For**
- Multiple API versions: `/api/v1/users`, `/api/v2/users`.
- Different response structures between versions.

**What to Ignore**
- Consistent field exposure across versions.

**How to Test with Burp Suite**
1. Call the same endpoint on different API versions.
2. Compare responses for extra sensitive fields in older versions.

**Example**
```http
GET /api/v1/users/123 HTTP/1.1
```
V1 may return `password_hash`, while V2 does not.

**Tools**
- Burp Repeater
- API version enumeration

**Risk Rating**  
High

**Remediation**
- Apply consistent data exposure policies across all API versions.
- Deprecate and remove vulnerable versions.

---

## 5. SENSITIVE PROPERTIES EXPOSED IN GRAPHQL RESPONSES (OVER‑FETCHING)

**Description**  
GraphQL allows clients to request specific fields. If field‑level authorization is missing, a user can request sensitive fields that should be restricted.

**What to Look For**
- GraphQL endpoints where introspection is enabled.
- Ability to request fields like `password`, `email`, `ssn` on objects the user can access.

**What to Ignore**
- Field‑level authorization implemented in resolvers.

**How to Test with Burp Suite**
1. Use GraphQL introspection to discover available fields.
2. Construct a query that includes sensitive fields.
3. Send the query and see if sensitive data is returned.

**Example**
```graphql
query {
  user(id: 123) {
    username
    email
    passwordHash
    ssn
  }
}
```
If `passwordHash` and `ssn` are returned, excessive data exposure exists.

**Tools**
- GraphQL Raider
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Implement field‑level authorization in GraphQL resolvers.
- Restrict sensitive fields based on user role.

---

## 6. GRAPHQL INTROSPECTION REVEALING SENSITIVE FIELD NAMES

**Description**  
Even if the fields are not returned, introspection may reveal the names of sensitive fields, giving attackers a roadmap for further attacks.

**What to Look For**
- Introspection query (`__schema`) returns field names like `password`, `ssn`, `creditCard`.
- Introspection enabled in production.

**What to Ignore**
- Introspection disabled in production.

**How to Test with Burp Suite**
1. Send an introspection query:
```graphql
query { __schema { types { name fields { name } } } }
```
2. Look for sensitive field names in the response.

**Example**
```json
{"name": "User", "fields": [{"name": "passwordHash"}, {"name": "ssn"}]}
```

**Tools**
- GraphQL Raider
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Disable introspection in production environments.
- Use a schema allowlist or rate limiting.

---

## 7. EXPOSURE OF INTERNAL PROPERTIES VIA `__PROTO__` OR `CONSTRUCTOR` IN JSON

**Description**  
Some JSON parsers or ORMs may expose prototype pollution vectors or internal properties when returning objects, leading to information disclosure.

**What to Look For**
- Responses containing `__proto__`, `constructor`, `prototype` fields.
- Unusual property names that suggest internal objects.

**What to Ignore**
- No such properties in responses.

**How to Test with Burp Suite**
1. Intercept API responses and search for `__proto__`, `constructor`, `prototype`.
2. If present, the API may be leaking internal structures.

**Example**
```json
{
  "user": {
    "name": "John",
    "__proto__": { "polluted": true }
  }
}
```

**Tools**
- Burp Proxy (search feature)

**Risk Rating**  
Low to Medium

**Remediation**
- Sanitize JSON output to remove internal properties.
- Use safe JSON serialization libraries.

---

## 8. PROPERTY EXPOSURE IN NESTED OBJECTS (DEEP JSON RESPONSES)

**Description**  
Sensitive properties may be hidden in deeply nested objects that developers overlook when designing DTOs.

**What to Look For**
- Responses with nested structures (e.g., `user.profile.medical_history`).
- Nested objects that contain sensitive fields.

**What to Ignore**
- All nested fields properly filtered.

**How to Test with Burp Suite**
1. Examine the full JSON response, including all nesting levels.
2. Look for sensitive field names deep inside the response.

**Example**
```json
{
  "user": {
    "name": "John",
    "settings": {
      "apiKey": "sk_live_abc123"
    }
  }
}
```

**Tools**
- Burp Proxy (manual inspection)
- JSON beautifier

**Risk Rating**  
Medium to High

**Remediation**
- Recursively filter all nested objects.
- Use DTOs for all levels of nesting.

---

## 9. MASS ASSIGNMENT VIA PATCH WITH PARTIAL UPDATES (JSON PATCH)

**Description**  
JSON Patch (RFC 6902) operations can be abused to modify properties that should be read‑only or protected.

**What to Look For**
- PATCH endpoints using `application/json-patch+json`.
- Operations like `add`, `replace`, `remove` on sensitive fields.

**What to Ignore**
- Validation of each patch operation against a whitelist.

**How to Test with Burp Suite**
1. Capture a PATCH request with JSON Patch format.
2. Add an operation that modifies a sensitive field (e.g., `{"op": "replace", "path": "/isAdmin", "value": true}`).
3. Send and check if the field is updated.

**Example**
```http
PATCH /api/users/123 HTTP/1.1
Content-Type: application/json-patch+json

[
  { "op": "replace", "path": "/email", "value": "new@example.com" },
  { "op": "replace", "path": "/role", "value": "admin" }
]
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Whitelist allowed JSON Patch paths.
- Validate each operation against user permissions.

---

## 10. EXPOSURE OF CALCULATED OR DERIVED PROPERTIES (E.G., `ISADMIN`)

**Description**  
APIs may return computed properties that reveal sensitive information, such as `isAdmin`, `hasPremium`, or `accountStatus`.

**What to Look For**
- Boolean or status fields that indicate user privileges or internal state.
- Fields that could be used for privilege escalation or profiling.

**What to Ignore**
- Non‑sensitive computed fields (e.g., `fullName`).

**How to Test with Burp Suite**
1. Call an API endpoint that returns user information.
2. Look for fields like `isAdmin`, `role`, `permissions`, `isPremium`.
3. If these fields are present, they may be used by the client for UI decisions (and could be manipulated in requests).

**Example**
```json
{
  "username": "john",
  "isAdmin": false,
  "creditScore": 750
}
```

**Tools**
- Burp Proxy

**Risk Rating**  
Medium

**Remediation**
- Avoid exposing sensitive computed properties to regular users.
- Derive privileges server‑side, not from client‑side data.

---

## 11. PROPERTY EXPOSURE IN ARRAY RESPONSES (LISTING ENDPOINTS)

**Description**  
Listing endpoints (e.g., `/api/users`) may return more fields than necessary for each object, exposing sensitive data for multiple users at once.

**What to Look For**
- Array responses where each object contains sensitive fields (e.g., email, phone, internal ID).
- No pagination or field selection.

**What to Ignore**
- Lists that return only safe, public fields.

**How to Test with Burp Suite**
1. Call a listing endpoint (e.g., `/api/users`, `/api/orders`).
2. Examine the response for sensitive fields in each array element.

**Example**
```json
{
  "users": [
    {"id": 1, "username": "alice", "email": "alice@example.com", "ssn": "123-45-6789"},
    {"id": 2, "username": "bob", "email": "bob@example.com", "ssn": "987-65-4321"}
  ]
}
```

**Tools**
- Burp Proxy

**Risk Rating**  
Critical

**Remediation**
- Return only necessary fields in list endpoints.
- Use field selection (e.g., `?fields=id,username`).

---

## 12. EXPOSURE OF USER‑SPECIFIC PROPERTIES IN SHARED OBJECTS

**Description**  
When an object is shared between users (e.g., a group or company resource), the API may expose properties specific to other members, such as their private email or role.

**What to Look For**
- Endpoints that return shared resources (groups, teams, companies).
- Properties of other users within those resources.

**What to Ignore**
- Only public or aggregated information about other members.

**How to Test with Burp Suite**
1. As User A, request a shared resource (e.g., `/api/teams/123/members`).
2. Check if the response includes other members’ sensitive fields (email, phone, role).

**Example**
```json
{
  "team_id": 123,
  "members": [
    {"user_id": 1, "name": "Alice", "email": "alice@private.com"},
    {"user_id": 2, "name": "Bob", "email": "bob@private.com"}
  ]
}
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Return only necessary information about other members (e.g., username, public profile).
- Apply field‑level authorization based on relationship.

---

## 13. MASS ASSIGNMENT VIA `_METHOD` PARAMETER (HTTP METHOD OVERRIDE)

**Description**  
Some frameworks support method override parameters (e.g., `_method=PUT`). Attackers can use this to change the HTTP method and bypass input validation or mass assignment protections.

**What to Look For**
- Support for `_method` or `X-HTTP-Method-Override` parameters.
- Different validation logic for different methods.

**What to Ignore**
- No method override support.

**How to Test with Burp Suite**
1. Send a POST request with `_method=PUT` and extra properties.
2. If the server processes it as a PUT (update) and accepts extra fields, mass assignment may be possible.

**Example**
```http
POST /api/users/123?_method=PUT HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=new@example.com&isAdmin=true
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Disable method override in production.
- Validate HTTP method server‑side.

---

## 14. SENSITIVE PROPERTIES IN ERROR MESSAGES OR VALIDATION RESPONSES

**Description**  
Validation error responses may reveal sensitive fields or internal property names that should not be exposed.

**What to Look For**
- Error messages that include field names like `password`, `token`, `ssn`.
- Validation responses that list all properties, including internal ones.

**What to Ignore**
- Generic error messages without field details.

**How to Test with Burp Suite**
1. Send malformed requests to trigger validation errors.
2. Examine the error response for sensitive field names.

**Example**
```json
{
  "errors": [
    {"field": "password_hash", "message": "cannot be null"},
    {"field": "ssn", "message": "invalid format"}
  ]
}
```

**Tools**
- Burp Repeater
- Burp Intruder (fuzzing)

**Risk Rating**  
Medium

**Remediation**
- Return generic error messages (e.g., `"Invalid input"`).
- Do not expose internal field names in validation errors.

---

## 15. PROPERTY EXPOSURE IN API DOCUMENTATION (SWAGGER/OPENAPI)

**Description**  
API documentation (Swagger, OpenAPI) may list all properties, including sensitive ones, giving attackers a blueprint for excessive data exposure or mass assignment.

**What to Look For**
- Accessible `/swagger`, `/api-docs`, `/openapi.json` endpoints.
- Documentation showing fields like `password`, `ssn`, `creditCard`.

**What to Ignore**
- Documentation that excludes sensitive fields or is protected by authentication.

**How to Test with Burp Suite**
1. Request common documentation paths: `/swagger/v1/swagger.json`, `/api-docs`, `/openapi.json`.
2. Examine the schema definitions for sensitive property names.

**Example**
```json
"User": {
  "properties": {
    "id": {"type": "integer"},
    "username": {"type": "string"},
    "passwordHash": {"type": "string"}
  }
}
```

**Tools**
- Burp Proxy
- Swagger UI

**Risk Rating**  
Medium

**Remediation**
- Restrict access to API documentation.
- Remove sensitive fields from public documentation.

---

## 16. MASS ASSIGNMENT VIA QUERY STRING PARAMETERS (FORM DATA)

**Description**  
APIs that accept `application/x-www-form-urlencoded` may allow mass assignment via query string or form parameters, including extra properties.

**What to Look For**
- Endpoints that accept form‑encoded data.
- No whitelist of allowed parameters.

**What to Ignore**
- JSON‑only APIs with strict validation.

**How to Test with Burp Suite**
1. Capture a form submission request.
2. Add extra parameters like `role=admin` or `isAdmin=true`.
3. Send and check if the extra parameter is applied.

**Example**
```http
POST /api/register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=attacker&password=123&role=admin
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Whitelist allowed parameters for form‑encoded endpoints.
- Use JSON APIs with schema validation.

---

## 17. PROPERTY EXPOSURE IN BATCH API RESPONSES (MULTIPLE OBJECTS)

**Description**  
Batch APIs that return multiple objects in one response may inadvertently expose sensitive properties across all objects, amplifying the impact.

**What to Look For**
- Batch endpoints: `/api/batch`, `/api/export`, GraphQL with many objects.
- No field filtering.

**What to Ignore**
- Batch responses with limited, safe fields.

**How to Test with Burp Suite**
1. Request a batch operation that returns many objects.
2. Examine the response for sensitive fields in each object.

**Example**
```json
{
  "results": [
    {"id": 1, "email": "alice@example.com", "passwordHash": "..."},
    {"id": 2, "email": "bob@example.com", "passwordHash": "..."}
  ]
}
```

**Tools**
- Burp Proxy

**Risk Rating**  
Critical

**Remediation**
- Limit fields returned in batch responses.
- Implement field selection (e.g., `?fields=id,name`).

---

## 18. MASS ASSIGNMENT VIA XML PAYLOADS (XXE COMBINED)

**Description**  
APIs that accept XML input may allow mass assignment of extra properties via XML elements, sometimes combined with XXE.

**What to Look For**
- Endpoints with `Content-Type: application/xml`.
- XML to object binding without whitelisting.

**What to Ignore**
- JSON‑only APIs.

**How to Test with Burp Suite**
1. Send an XML request with extra elements.
2. Check if the extra elements are processed.

**Example**
```xml
<user>
  <username>attacker</username>
  <password>123</password>
  <isAdmin>true</isAdmin>
</user>
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Whitelist allowed XML elements.
- Avoid XML deserialization of untrusted data.

---

## 19. EXPOSURE OF PROPERTIES INTENDED ONLY FOR INTERNAL USE (E.G., `INTERNAL_ID`)

**Description**  
Internal identifiers (e.g., database IDs, trace IDs, internal status flags) may be exposed in API responses, aiding attackers in enumeration or further exploitation.

**What to Look For**
- Fields like `internal_id`, `db_id`, `trace_id`, `row_version`.
- Fields that are not needed by the client.

**What to Ignore**
- Only necessary, non‑sensitive fields.

**How to Test with Burp Suite**
1. Intercept API responses and look for unusual field names.
2. Compare with API documentation; any extra fields may be internal.

**Example**
```json
{
  "user_id": 123,
  "username": "john",
  "internal_trace_id": "xyz789"
}
```

**Tools**
- Burp Proxy

**Risk Rating**  
Low to Medium

**Remediation**
- Remove internal fields from public responses.
- Use separate DTOs for internal vs external.

---

## 20. MASS ASSIGNMENT VIA CSV OR FILE UPLOAD IMPORTS

**Description**  
APIs that allow CSV or file uploads to import data may be vulnerable to mass assignment if column headers map directly to object properties.

**What to Look For**
- Import endpoints (e.g., `/api/import/users`).
- CSV headers that match database column names.

**What to Ignore**
- Strict validation of allowed columns.

**How to Test with Burp Suite**
1. Upload a CSV with extra columns (e.g., `role`, `isAdmin`).
2. Check if the extra columns are processed.

**Example**
```csv
username,email,role
attacker,attacker@evil.com,admin
```

**Tools**
- Burp Repeater (file upload)

**Risk Rating**  
High

**Remediation**
- Whitelist allowed columns for import.
- Map input columns to safe DTO fields.

---

## 21. PROPERTY EXPOSURE IN WEBSOCKET MESSAGES (REAL‑TIME UPDATES)

**Description**  
WebSocket messages may contain full object representations, including sensitive fields that are not filtered.

**What to Look For**
- WebSocket connections used for real‑time updates.
- Messages containing sensitive properties.

**What to Ignore**
- Filtered WebSocket messages.

**How to Test with Burp Suite**
1. Intercept WebSocket messages using Burp.
2. Examine the JSON payloads for sensitive fields.

**Example**
```json
{"event": "user_update", "data": {"user_id": 123, "password_hash": "..."}}
```

**Tools**
- Burp Suite (WebSocket support)

**Risk Rating**  
High

**Remediation**
- Apply the same field filtering to WebSocket messages as to REST APIs.

---

## 22. MASS ASSIGNMENT VIA GRAPHQL INPUT OBJECT INJECTION

**Description**  
GraphQL mutations often accept input objects. Attackers can add extra fields to the input object that map to internal properties.

**What to Look For**
- GraphQL mutations with input object types.
- No validation of allowed input fields.

**What to Ignore**
- Input objects with strict field whitelists.

**How to Test with Burp Suite**
1. Capture a GraphQL mutation.
2. Add extra fields to the input object (e.g., `role: "admin"`).
3. Send the mutation and check if the extra field is applied.

**Example**
```graphql
mutation {
  updateUser(input: { id: 123, name: "new", role: "admin" }) {
    user { name }
  }
}
```

**Tools**
- GraphQL Raider
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Whitelist allowed input fields for each mutation.
- Validate input objects against a schema.

---

## 23. EXPOSURE OF PROPERTIES VIA DIFFERENT USER ROLES (VERTICAL PRIVILEGE)

**Description**  
Regular users and admin users may receive the same API response, but the response may contain properties that are only meaningful for admins, exposing internal data.

**What to Look For**
- APIs that return the same structure for all roles.
- Fields that are empty or null for regular users but filled for admins.

**What to Ignore**
- Different DTOs for different roles.

**How to Test with Burp Suite**
1. Call the same endpoint as a regular user and as an admin.
2. Compare the responses for extra fields in the admin response.
3. If the regular user can see those fields (even if empty), it may leak property names.

**Example**
Regular user response:
```json
{"id": 123, "username": "john", "admin_notes": null}
```
Admin response:
```json
{"id": 123, "username": "john", "admin_notes": "sensitive internal note"}
```
The field name `admin_notes` is exposed to regular users.

**Tools**
- Burp Repeater (with different tokens)

**Risk Rating**  
Medium

**Remediation**
- Use different DTOs for different roles.
- Do not include privileged fields in responses for unprivileged users.

---

## 24. MASS ASSIGNMENT VIA ARRAY OF OBJECTS (MULTIPLE RESOURCES)

**Description**  
APIs that accept arrays of objects in a single request may allow mass assignment across multiple resources simultaneously.

**What to Look For**
- Batch create/update endpoints that accept an array of objects.
- No per‑object field validation.

**What to Ignore**
- Each object in the array validated independently.

**How to Test with Burp Suite**
1. Send a batch request with an array of objects.
2. Add extra properties to one of the objects.
3. Check if the extra property is applied.

**Example**
```http
POST /api/batch/users HTTP/1.1
[
  {"username": "user1", "password": "pass1", "role": "admin"},
  {"username": "user2", "password": "pass2"}
]
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Validate each object in the array against the same whitelist.

---

## 25. PROPERTY EXPOSURE VIA PAGINATION OR SORTING PARAMETERS

**Description**  
Pagination or sorting parameters may reveal the names of database columns or internal properties.

**What to Look For**
- Parameters like `sort=field`, `orderBy=column`, `orderBy=internal_id`.
- Error messages when sorting by an invalid field reveal allowed fields.

**What to Ignore**
- Whitelist of allowed sort fields.

**How to Test with Burp Suite**
1. Try sorting by a non‑standard field (e.g., `sort=password_hash`).
2. If the API returns an error listing allowed fields, those field names are exposed.

**Example**
```http
GET /api/users?sort=password_hash
```
Error response:
```
"Invalid sort field. Allowed fields: id, username, email, password_hash, ssn"
```

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Return generic error messages for invalid sort fields.
- Do not list allowed fields in error responses.

---

## 26. MASS ASSIGNMENT VIA CONTENT‑TYPE SWITCHING (JSON TO XML)

**Description**  
APIs that accept both JSON and XML may have different parsing behaviors, leading to mass assignment via the less‑secure format.

**What to Look For**
- Endpoints that accept multiple `Content-Type` values.
- Different validation logic for JSON vs XML.

**What to Ignore**
- Consistent validation across formats.

**How to Test with Burp Suite**
1. Send a JSON request with extra properties; if blocked, try the same with XML.
2. If XML accepts extra properties, vulnerable.

**Example**
```xml
<user>
  <username>attacker</username>
  <password>123</password>
  <isAdmin>true</isAdmin>
</user>
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Apply consistent validation across all content types.
- Prefer a single format (e.g., JSON).

---

## 27. EXPOSURE OF PROPERTIES VIA HEADERS OR CUSTOM RESPONSE FIELDS

**Description**  
Sensitive properties may be exposed in custom response headers rather than the JSON body.

**What to Look For**
- Headers like `X-User-Role`, `X-Internal-ID`, `X-Debug-Info`.
- Headers that reveal internal state.

**What to Ignore**
- No sensitive data in headers.

**How to Test with Burp Suite**
1. Intercept responses and examine all headers.
2. Look for custom headers that might contain sensitive information.

**Example**
```http
X-Internal-User-ID: 12345
X-User-Permissions: admin
```

**Tools**
- Burp Proxy

**Risk Rating**  
Low to Medium

**Remediation**
- Do not put sensitive data in headers.
- Use standard authentication headers only.

---

## 28. MASS ASSIGNMENT VIA NULL OR EMPTY VALUE INJECTION

**Description**  
Attackers may send `null` or empty values for properties that should have default values, potentially causing unintended state changes.

**What to Look For**
- Update endpoints that accept `null` for fields like `role`, `status`.
- No validation against null values for required fields.

**What to Ignore**
- Rejection of null values for critical fields.

**How to Test with Burp Suite**
1. Send an update request with `"role": null` or `"isAdmin": null`.
2. Check if the property is cleared or set to a default.

**Example**
```http
PATCH /api/users/123
{"role": null}
```
If the user’s role is removed, vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Validate that required fields are not set to null.
- Use default values server‑side.

---

## 29. PROPERTY EXPOSURE VIA GRAPHQL FIELD ALIASING

**Description**  
GraphQL aliasing can be used to request the same field multiple times or to request fields that are normally filtered by the client, but server‑side filtering may still apply.

**What to Look For**
- GraphQL endpoints with field‑level authorization.
- Aliasing to request the same field with different names.

**What to Ignore**
- Server‑side field filtering independent of alias.

**How to Test with Burp Suite**
1. Use aliasing to request a sensitive field under a different name.
2. Check if the server returns it.

**Example**
```graphql
query {
  user(id: 123) {
    name
    secret: passwordHash
  }
}
```

**Tools**
- GraphQL Raider
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Implement field‑level authorization that does not depend on field names (use a resolver interceptor).

---

## 30. MASS ASSIGNMENT VIA DEFAULT VALUES NOT PROPERLY SANITIZED

**Description**  
When creating a resource, default values for properties (e.g., `role = "user"`) may be overridden if the client sends a value, even if not explicitly allowed.

**What to Look For**
- Creation endpoints where default values are set server‑side.
- No whitelist of allowed fields; any field sent by the client overrides the default.

**What to Ignore**
- Only whitelisted fields are accepted; others ignored.

**How to Test with Burp Suite**
1. Send a creation request with an extra field (e.g., `role: "admin"`).
2. Check if the default value is overridden.

**Example**
```http
POST /api/register
{"username":"attacker","password":"123","role":"admin"}
```
If the user is created with role `admin`, vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Whitelist allowed fields for creation.
- Do not allow client‑supplied values for sensitive default fields.

---

## ✅ **SUMMARY**

Broken Object Property Level Authorization (BOPLA) encompasses two main issues: **Excessive Data Exposure** (returning more properties than necessary) and **Mass Assignment** (allowing clients to modify properties they should not control). This guide covers 30 distinct property‑level flaws.

### **Key Testing Areas Summary**

| Failure Type | Key Indicators | Risk |
|--------------|----------------|------|
| Excessive Data Exposure | `password_hash`, `ssn` in response | High |
| Mass Assignment (Create) | Extra `role` in POST request | Critical |
| Mass Assignment (Update) | Extra `isAdmin` in PATCH | Critical |
| API Versioning | V1 returns more fields | High |
| GraphQL Over‑fetching | Requesting sensitive fields | High |
| GraphQL Introspection | Field names exposed | Medium |
| Nested Object Exposure | Deep JSON with secrets | Medium-High |
| JSON Patch | Replace `/role` | Critical |
| Derived Properties | `isAdmin` in response | Medium |
| Array Responses | Sensitive fields in lists | Critical |
| Shared Resources | Other users' emails | High |
| Method Override | `_method=PUT` | High |
| Error Messages | Field names leaked | Medium |
| API Documentation | Swagger shows sensitive fields | Medium |
| Form Data | Extra parameters in form | Critical |
| Batch APIs | Many objects with secrets | Critical |
| XML Payloads | Extra XML elements | High |
| Internal Fields | `internal_id` exposed | Low-Medium |
| CSV Import | Extra columns | High |
| WebSocket | Secrets in real‑time messages | High |
| GraphQL Input Injection | Extra input fields | Critical |
| Role‑Based Exposure | Field names visible to all | Medium |
| Batch Arrays | Per‑object mass assignment | High |
| Sorting Parameters | Column names leaked | Medium |
| Content‑Type Switching | XML bypass | High |
| Headers | Sensitive data in headers | Low-Medium |
| Null Injection | Setting role to null | Medium |
| GraphQL Aliasing | Request secret under alias | High |
| Default Value Override | Client overrides role | Critical |

### **Pro Tips for Testing BOPLA**
1. **Compare request and response fields** – look for extra fields in responses and extra fields in requests.
2. **Use Burp’s search** – search responses for keywords like `password`, `token`, `secret`, `ssn`, `admin`, `role`.
3. **Fuzz for mass assignment** – add common property names (`role`, `is_admin`, `isAdmin`, `permissions`, `balance`, `status`) to requests.
4. **Test with different user roles** – see if the same endpoint returns different fields for admins vs regular users.
5. **Check GraphQL introspection** – discover all available fields and test each for access.
6. **Automate with custom scripts** – send common sensitive field names in POST/PUT requests.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
