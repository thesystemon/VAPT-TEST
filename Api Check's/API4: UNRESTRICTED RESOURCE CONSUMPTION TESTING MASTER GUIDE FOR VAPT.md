# 🚦 **API4: UNRESTRICTED RESOURCE CONSUMPTION TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into API Resource Exhaustion & Rate Limiting Flaws*

---

## 📋 **TABLE OF CONTENTS**

1. [Missing Rate Limiting on API Endpoints](#1-missing-rate-limiting-on-api-endpoints)
2. [Rate Limiting Bypass via IP Rotation (X-Forwarded-For)](#2-rate-limiting-bypass-via-ip-rotation-x-forwarded-for)
3. [Rate Limiting Bypass via User Enumeration (Different User IDs)](#3-rate-limiting-bypass-via-user-enumeration-different-user-ids)
4. [Rate Limiting Based Only on User Session (Not IP)](#4-rate-limiting-based-only-on-user-session-not-ip)
5. [No Limit on Request Payload Size (Large JSON/XML)](#5-no-limit-on-request-payload-size-large-jsonxml)
6. [No Limit on Number of Query Parameters or Array Elements](#6-no-limit-on-number-of-query-parameters-or-array-elements)
7. [No Limit on Number of Fields in JSON Request Body](#7-no-limit-on-number-of-fields-in-json-request-body)
8. [GraphQL Depth Limiting Missing (Deeply Nested Queries)](#8-graphql-depth-limiting-missing-deeply-nested-queries)
9. [GraphQL Query Cost / Complexity Limiting Missing](#9-graphql-query-cost--complexity-limiting-missing)
10. [GraphQL Batch / Aliases Abuse (Batching Requests)](#10-graphql-batch--aliases-abuse-batching-requests)
11. [No Limit on File Upload Size or Number of Files](#11-no-limit-on-file-upload-size-or-number-of-files)
12. [No Rate Limiting on Authentication Endpoints (Login, OTP, Reset)](#12-no-rate-limiting-on-authentication-endpoints-login-otp-reset)
13. [No Rate Limiting on Password Reset or OTP Generation](#13-no-rate-limiting-on-password-reset-or-otp-generation)
14. [No Limit on Search Query Length or Complexity](#14-no-limit-on-search-query-length-or-complexity)
15. [No Pagination or Cursor Limiting on List Endpoints](#15-no-pagination-or-cursor-limiting-on-list-endpoints)
16. [Unbounded Array Expansion in Request (Denial of Service)](#16-unbounded-array-expansion-in-request-denial-of-service)
17. [No Timeout on Long‑Running Operations (Slowloris Style)](#17-no-timeout-on-long-running-operations-slowloris-style)
18. [No Connection Limit per Client (TCP Connection Exhaustion)](#18-no-connection-limit-per-client-tcp-connection-exhaustion)
19. [No Limit on Concurrent Requests (Race Condition via Parallelism)](#19-no-limit-on-concurrent-requests-race-condition-via-parallelism)
20. [No Rate Limiting on WebSocket Messages (Message Flood)](#20-no-rate-limiting-on-websocket-messages-message-flood)
21. [No Limit on WebSocket Connection Duration or Messages](#21-no-limit-on-websocket-connection-duration-or-messages)
22. [No Limit on Number of Items in Batch API Requests](#22-no-limit-on-number-of-items-in-batch-api-requests)
23. [No Limit on File Uploads for Image Processing (ImageTragick)](#23-no-limit-on-file-uploads-for-image-processing-imagetragick)
24. [No Limit on XML Entity Expansion (Billion Laughs Attack)](#24-no-limit-on-xml-entity-expansion-billion-laughs-attack)
25. [No Limit on URL Parameter Length or Redirect Loops](#25-no-limit-on-url-parameter-length-or-redirect-loops)
26. [No Rate Limiting on Webhook / Callback Endpoints](#26-no-rate-limiting-on-webhook--callback-endpoints)
27. [No Limit on Regular Expression Complexity (ReDoS)](#27-no-limit-on-regular-expression-complexity-redos)
28. [No Limit on Database Query Result Size (Full Table Scan)](#28-no-limit-on-database-query-result-size-full-table-scan)
29. [No Throttling on Cache Invalidation Requests](#29-no-throttling-on-cache-invalidation-requests)
30. [No Resource Limits on Serverless Functions (AWS Lambda, Azure Functions)](#30-no-resource-limits-on-serverless-functions-aws-lambda-azure-functions)

---

## 1. MISSING RATE LIMITING ON API ENDPOINTS

**Description**  
APIs without rate limiting allow attackers to send an unlimited number of requests, leading to brute force attacks, resource exhaustion, denial of service, and financial loss (e.g., in paid APIs).

**What to Look For**
- No `X-RateLimit-*` headers in responses.
- Ability to send hundreds of requests without receiving `429 Too Many Requests`.
- Publicly documented endpoints with no mention of rate limits.

**What to Ignore**
- Endpoints with documented and enforced rate limits (e.g., 100 requests per minute).

**How to Test with Burp Suite**
1. Use Intruder or Turbo Intruder to send 200 requests to the same endpoint.
2. Observe responses: if all return `200 OK` (or normal responses), rate limiting is missing.
3. Check for any `Retry-After` header or `429` status code.

**Example**
```http
GET /api/search?q=test HTTP/1.1
```
Sent 500 times in 1 second – all return `200 OK`.

**Tools**
- Burp Intruder
- Turbo Intruder
- Custom scripts (e.g., `ab`, `wrk`)

**Risk Rating**  
High to Critical (depends on endpoint sensitivity)

**Remediation**
- Implement rate limiting based on client IP, user ID, or API key.
- Use `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` headers.
- Return `429 Too Many Requests` with `Retry-After`.

---

## 2. RATE LIMITING BYPASS VIA IP ROTATION (X-FORWARDED-FOR)

**Description**  
If rate limiting is based solely on the `X-Forwarded-For` header, attackers can spoof IP addresses to bypass limits.

**What to Look For**
- Rate limiting that uses the `X-Forwarded-For` header instead of the real source IP.
- Application behind a reverse proxy that trusts client‑supplied IP headers.

**What to Ignore**
- Rate limiting based on the actual TCP connection IP (not spoofable).

**How to Test with Burp Suite**
1. Send a request with a custom `X-Forwarded-For: 1.2.3.4` header.
2. Repeat with different IP values (e.g., `1.2.3.5`, `1.2.3.6`).
3. If each request is counted separately, bypass is possible.

**Example**
```http
GET /api/login HTTP/1.1
X-Forwarded-For: 10.0.0.1
```
Then with `X-Forwarded-For: 10.0.0.2`.

**Tools**
- Burp Intruder (with payload position on IP header)

**Risk Rating**  
High

**Remediation**
- Configure the reverse proxy to strip `X-Forwarded-For` or use the real IP from the connection.
- Rate limit on the actual client IP (e.g., `$remote_addr` in Nginx).

---

## 3. RATE LIMITING BYPASS VIA USER ENUMERATION (DIFFERENT USER IDS)

**Description**  
If rate limiting is per user (e.g., by user ID in the request), attackers can bypass limits by cycling through many user IDs.

**What to Look For**
- Endpoints that accept a `user_id` or `account_id` parameter.
- Rate limiting tied to that ID, not to the client.

**What to Ignore**
- Rate limiting based on client IP or authentication token (one token per attacker).

**How to Test with Burp Suite**
1. Send requests to a resource with different user IDs in each request (e.g., `user_id=1`, `user_id=2`, ...).
2. If all requests are allowed without hitting a limit, rate limiting is per‑user and can be bypassed.

**Example**
```http
GET /api/user/profile?user_id=1
GET /api/user/profile?user_id=2
...
```

**Tools**
- Burp Intruder (payload on `user_id`)

**Risk Rating**  
Medium

**Remediation**
- Rate limit on client IP or authenticated session, not on the object ID.
- Use API keys or tokens to identify clients.

---

## 4. RATE LIMITING BASED ONLY ON USER SESSION (NOT IP)

**Description**  
If rate limiting is tied only to the session (cookie or token), an attacker can create many sessions (e.g., via automated registration) and bypass limits.

**What to Look For**
- Rate limiting that resets when a new session is created.
- Ability to register many accounts quickly.

**What to Ignore**
- Rate limiting that combines IP and session, or uses API keys.

**How to Test with Burp Suite**
1. Create multiple user accounts (or sessions) programmatically.
2. Use a different session token for each request.
3. If all requests succeed, the limit is session‑only.

**Example**
- Use 100 different `Authorization: Bearer` tokens from 100 registered users.

**Tools**
- Burp Intruder (with payload on session token)

**Risk Rating**  
High

**Remediation**
- Combine IP‑based rate limiting with session‑based limits.
- Use CAPTCHA to prevent automated account creation.

---

## 5. NO LIMIT ON REQUEST PAYLOAD SIZE (LARGE JSON/XML)

**Description**  
APIs that accept large request bodies without size limits can be used to exhaust server memory, CPU, or disk, leading to denial of service.

**What to Look For**
- No `Content-Length` validation; large payloads accepted.
- Endpoints that process JSON/XML without size restrictions.

**What to Ignore**
- Payload size limits (e.g., 1MB) enforced by server configuration.

**How to Test with Burp Suite**
1. Send a request with a very large JSON body (e.g., 100MB of `"x":"y"`).
2. Observe if the server responds with `413 Payload Too Large` or crashes.

**Example**
```json
{"data": "A" * 100000000}
```

**Tools**
- Burp Repeater (with large payloads)
- Custom script to generate large bodies

**Risk Rating**  
High

**Remediation**
- Enforce maximum payload size (e.g., 1MB for JSON, 10MB for file uploads).
- Return `413 Payload Too Large` when exceeded.

---

## 6. NO LIMIT ON NUMBER OF QUERY PARAMETERS OR ARRAY ELEMENTS

**Description**  
APIs that allow an unbounded number of query parameters or array elements can be exploited for denial of service via parameter pollution or large array processing.

**What to Look For**
- Endpoints that accept arrays: `?id=1&id=2&id=3...`.
- No limit on the number of parameters.

**What to Ignore**
- Maximum parameter count enforced.

**How to Test with Burp Suite**
1. Send a request with 10,000 query parameters (e.g., `?id1=1&id2=2...`).
2. Observe server response time and memory usage.

**Example**
```http
GET /api/data?ids=1&ids=2&ids=3&... (1000 times)
```

**Tools**
- Burp Intruder (generate many parameters)
- Custom script

**Risk Rating**  
Medium

**Remediation**
- Limit the number of query parameters and array elements (e.g., max 100).
- Use pagination instead of bulk IDs.

---

## 7. NO LIMIT ON NUMBER OF FIELDS IN JSON REQUEST BODY

**Description**  
JSON requests with an excessive number of fields can cause CPU exhaustion during parsing and validation.

**What to Look For**
- No validation of maximum object size or field count.
- Endpoints that accept arbitrary JSON structures.

**What to Ignore**
- Schemas that limit field count.

**How to Test with Burp Suite**
1. Send a JSON with 10,000 fields (e.g., `{"field1":"value", "field2":"value"...}`).
2. Measure response time and server resources.

**Example**
```json
{"f1":"v1","f2":"v2",... (10000 fields)}
```

**Tools**
- Burp Repeater
- Custom script to generate large JSON

**Risk Rating**  
Medium

**Remediation**
- Define JSON schema with maximum field count.
- Reject requests exceeding the limit.

---

## 8. GRAPHQL DEPTH LIMITING MISSING (DEEPLY NESTED QUERIES)

**Description**  
GraphQL allows deeply nested queries. Without depth limiting, an attacker can craft a query with hundreds of nested levels, causing CPU exhaustion.

**What to Look For**
- GraphQL endpoint with introspection enabled.
- No error when sending very deep queries.

**What to Ignore**
- Depth limiting configured (e.g., max depth 10).

**How to Test with Burp Suite**
1. Send a GraphQL query with 50+ levels of nesting:
```graphql
query {
  user {
    friends {
      friends {
        friends { ... } } } } }
```
2. Observe if the server rejects it (error) or becomes slow.

**Example**
```graphql
query {
  user(id:1) {
    posts {
      comments {
        author {
          posts {
            comments { ... } } } } } }
```

**Tools**
- GraphQL Raider
- Custom depth payload generator

**Risk Rating**  
High

**Remediation**
- Implement query depth limiting (e.g., max depth 10).
- Use query cost analysis.

---

## 9. GRAPHQL QUERY COST / COMPLEXITY LIMITING MISSING

**Description**  
Even with depth limits, queries with high complexity (many fields, large arrays) can exhaust resources.

**What to Look For**
- GraphQL endpoint that accepts large queries without cost analysis.
- No rejection for queries with many fields or aliases.

**What to Ignore**
- Query cost calculation and limiting (e.g., max cost 1000).

**How to Test with Burp Suite**
1. Send a query that requests hundreds of fields on a single object.
2. Use aliases to request the same field many times.
3. Observe server performance.

**Example**
```graphql
query {
  user(id:1) {
    field1: name
    field2: name
    ... (1000 times)
  }
}
```

**Tools**
- GraphQL Raider
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Implement query cost analysis (field weights, depth, pagination limits).
- Reject queries exceeding a cost threshold.

---

## 10. GRAPHQL BATCH / ALIASES ABUSE (BATCHING REQUESTS)

**Description**  
GraphQL allows batching multiple queries or using many aliases. Attackers can send thousands of operations in a single request, bypassing rate limits.

**What to Look For**
- GraphQL endpoint that supports batching (array of queries).
- No limit on number of operations per request.

**What to Ignore**
- Maximum batch size enforced.

**How to Test with Burp Suite**
1. Send a batch query with 500 operations:
```json
[{"query": "query { user(id:1) { name } }"}, ... 500 times]
```
2. Observe if the server processes all.

**Tools**
- Burp Repeater
- Custom JSON generator

**Risk Rating**  
High

**Remediation**
- Limit the number of operations per batch (e.g., max 10).
- Apply rate limiting on total operations, not just requests.

---

## 11. NO LIMIT ON FILE UPLOAD SIZE OR NUMBER OF FILES

**Description**  
File upload endpoints without size limits can be used to fill disk space or exhaust memory.

**What to Look For**
- Upload endpoints that accept large files without validation.
- No limit on the number of files per request (multiple uploads).

**What to Ignore**
- File size limits (e.g., 10MB) and count limits.

**How to Test with Burp Suite**
1. Upload a 1GB file (if allowed) or multiple large files.
2. Observe if the server returns an error or becomes slow.

**Example**
```http
POST /api/upload
Content-Type: multipart/form-data

file: huge_file.zip (1GB)
```

**Tools**
- Burp Repeater (with large file)
- Custom upload scripts

**Risk Rating**  
High

**Remediation**
- Enforce maximum file size (e.g., 10MB).
- Limit number of files per request (e.g., 5).
- Use streaming to avoid memory exhaustion.

---

## 12. NO RATE LIMITING ON AUTHENTICATION ENDPOINTS (LOGIN, OTP, RESET)

**Description**  
Authentication endpoints without rate limiting allow brute force, credential stuffing, and OTP brute forcing.

**What to Look For**
- Login endpoint accepts many requests without `429`.
- OTP verification endpoint without limit.

**What to Ignore**
- Rate limiting on authentication endpoints (e.g., 5 attempts per minute).

**How to Test with Burp Suite**
1. Send 100 login attempts with wrong passwords.
2. If all return `401 Unauthorized` (or similar) without delay, rate limiting missing.

**Example**
```http
POST /api/login
{"username":"admin","password":"guess"}
```

**Tools**
- Burp Intruder

**Risk Rating**  
Critical

**Remediation**
- Apply strict rate limiting on login, OTP, and password reset (e.g., 5 per minute per IP).

---

## 13. NO RATE LIMITING ON PASSWORD RESET OR OTP GENERATION

**Description**  
Password reset and OTP generation endpoints without rate limiting can be abused to send thousands of emails/SMS, causing financial cost and user annoyance.

**What to Look For**
- Ability to request password reset for the same email many times.
- No CAPTCHA or rate limiting.

**What to Ignore**
- Rate limiting (e.g., 3 requests per hour per email).

**How to Test with Burp Suite**
1. Send 100 password reset requests for the same email.
2. If all succeed, the endpoint is vulnerable.

**Example**
```http
POST /api/password-reset
{"email":"victim@example.com"}
```

**Tools**
- Burp Intruder

**Risk Rating**  
High

**Remediation**
- Rate limit password reset requests (e.g., 3 per hour per email).
- Use CAPTCHA after a few requests.

---

## 14. NO LIMIT ON SEARCH QUERY LENGTH OR COMPLEXITY

**Description**  
Search endpoints that accept very long or complex queries can cause database CPU exhaustion (e.g., full‑text search on large fields).

**What to Look For**
- Search query parameter with no length limit.
- No timeout on search execution.

**What to Ignore**
- Maximum query length (e.g., 200 characters).

**How to Test with Burp Suite**
1. Send a search query with 10,000 characters.
2. Send a query with many `OR` conditions or regex patterns.

**Example**
```http
GET /api/search?q=A*10000
```

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Limit search query length (e.g., 200 characters).
- Implement query timeout and complexity limits.

---

## 15. NO PAGINATION OR CURSOR LIMITING ON LIST ENDPOINTS

**Description**  
APIs that return all resources without pagination can cause large data transfer, memory exhaustion, and denial of service.

**What to Look For**
- Endpoints like `/api/users` that return all users.
- No `limit`, `offset`, or `cursor` parameters.

**What to Ignore**
- Pagination with reasonable maximum page size (e.g., limit 100).

**How to Test with Burp Suite**
1. Call a list endpoint that returns all records.
2. If the response is huge (e.g., 100MB), it's a problem.

**Example**
```http
GET /api/users HTTP/1.1
```
Returns 1 million users.

**Tools**
- Burp Proxy (observe response size)

**Risk Rating**  
High

**Remediation**
- Implement pagination with mandatory `limit` and `offset` or cursor.
- Set a maximum page size (e.g., 100 items).

---

## 16. UNBOUNDED ARRAY EXPANSION IN REQUEST (DENIAL OF SERVICE)

**Description**  
Attackers can send arrays with thousands of elements to cause excessive processing, memory allocation, or database queries.

**What to Look For**
- Endpoints that accept arrays in request body (e.g., `{"ids": [1,2,3,...]}`).
- No validation of array size.

**What to Ignore**
- Maximum array size enforced.

**How to Test with Burp Suite**
1. Send a JSON with an array of 10,000 IDs.
2. Observe server response time and memory.

**Example**
```json
{"ids": [1,2,3, ... 10000]}
```

**Tools**
- Burp Repeater
- Custom JSON generator

**Risk Rating**  
High

**Remediation**
- Limit array size (e.g., max 100 elements).
- Use batch processing with limits.

---

## 17. NO TIMEOUT ON LONG‑RUNNING OPERATIONS (SLOWLORIS STYLE)

**Description**  
APIs that do not set timeouts on request processing can be tied up by slow, incomplete requests (Slowloris) or complex operations.

**What to Look For**
- No `Keep-Alive` timeout or request timeout.
- Ability to send headers very slowly.

**What to Ignore**
- Timeouts configured (e.g., 30 seconds).

**How to Test with Burp Suite**
1. Use Slowloris tool to send partial HTTP headers.
2. Observe if connections remain open indefinitely.

**Tools**
- Slowloris script
- Burp Intruder with slow send

**Risk Rating**  
Medium

**Remediation**
- Configure request timeouts (e.g., 30 seconds).
- Limit concurrent connections per IP.

---

## 18. NO CONNECTION LIMIT PER CLIENT (TCP CONNECTION EXHAUSTION)

**Description**  
Without limits on concurrent connections, an attacker can open thousands of TCP connections, exhausting server resources.

**What to Look For**
- No connection limit in web server configuration.
- Ability to open many connections from one IP.

**What to Ignore**
- Connection limits (e.g., 10 per IP).

**How to Test with Burp Suite**
1. Use `wrk` or `ab` to open many concurrent connections.
2. If server accepts all, vulnerable.

**Tools**
- wrk, ab (ApacheBench)
- Custom script

**Risk Rating**  
High

**Remediation**
- Configure web server (Nginx, Apache) to limit concurrent connections per IP.

---

## 19. NO LIMIT ON CONCURRENT REQUESTS (RACE CONDITION VIA PARALLELISM)

**Description**  
APIs that allow many concurrent requests from the same client can lead to race conditions and resource contention.

**What to Look For**
- No throttling on concurrent requests.
- Ability to send 100 requests simultaneously.

**What to Ignore**
- Concurrent request limits.

**How to Test with Burp Suite**
1. Use Turbo Intruder to send 100 concurrent requests.
2. Observe if any fail due to rate limiting.

**Example**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=100,
                           requestsPerConnection=1)
    for i in range(100):
        engine.queue(target.req)
```

**Tools**
- Burp Turbo Intruder

**Risk Rating**  
Medium

**Remediation**
- Limit concurrent requests per client (e.g., 10).
- Use queuing mechanisms.

---

## 20. NO RATE LIMITING ON WEBSOCKET MESSAGES (MESSAGE FLOOD)

**Description**  
WebSocket connections without message rate limiting can be flooded with thousands of messages per second, causing CPU exhaustion.

**What to Look For**
- WebSocket endpoint that accepts unlimited messages.
- No per‑second or per‑minute limit.

**What to Ignore**
- Message rate limiting implemented.

**How to Test with Burp Suite**
1. Connect to WebSocket and send 1000 messages rapidly.
2. Observe server response time.

**Tools**
- Burp WebSocket support
- Custom WebSocket client

**Risk Rating**  
High

**Remediation**
- Implement message rate limiting (e.g., 100 per second per connection).

---

## 21. NO LIMIT ON WEBSOCKET CONNECTION DURATION OR MESSAGES

**Description**  
WebSocket connections that can stay open indefinitely can be used for resource exhaustion (memory, file descriptors).

**What to Look For**
- No idle timeout on WebSocket.
- Connections remain open forever.

**What to Ignore**
- Idle timeout (e.g., 5 minutes).

**How to Test with Burp Suite**
1. Open a WebSocket connection and send no messages.
2. See if the connection closes after a reasonable time.

**Tools**
- Burp WebSocket

**Risk Rating**  
Medium

**Remediation**
- Set WebSocket idle timeout (e.g., 5 minutes).
- Limit total connection duration.

---

## 22. NO LIMIT ON NUMBER OF ITEMS IN BATCH API REQUESTS

**Description**  
Batch APIs that accept many operations in one request can overwhelm the server.

**What to Look For**
- Batch endpoint that accepts an array of operations.
- No limit on batch size.

**What to Ignore**
- Maximum batch size (e.g., 20 operations).

**How to Test with Burp Suite**
1. Send a batch request with 1000 operations.
2. Observe response time.

**Example**
```json
{"requests": [{"method":"GET","url":"/api/user/1"}, ... 1000 times]}
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Limit batch size (e.g., 20 operations per request).

---

## 23. NO LIMIT ON FILE UPLOADS FOR IMAGE PROCESSING (IMAGETRAGICK)

**Description**  
Image processing endpoints without limits on image dimensions or pixel count can be exploited using crafted images (e.g., ImageTragick, decompression bombs).

**What to Look For**
- Image upload with resize or format conversion.
- No validation of image dimensions.

**What to Ignore**
- Maximum dimensions (e.g., 4000x4000) and file size.

**How to Test with Burp Suite**
1. Upload a small file that decompresses to huge dimensions (e.g., a 1KB JPEG that expands to 10000x10000).
2. Observe if server crashes.

**Tools**
- ImageMagick decompression bomb generator

**Risk Rating**  
High

**Remediation**
- Limit image dimensions (width, height) and pixel count.
- Use secure image processing libraries.

---

## 24. NO LIMIT ON XML ENTITY EXPANSION (BILLION LAUGHS ATTACK)

**Description**  
XML parsers without entity expansion limits can be exploited with recursive entities, causing memory exhaustion.

**What to Look For**
- Endpoints that accept XML input.
- No limit on entity expansion.

**What to Ignore**
- Entity expansion limits (e.g., max 1000 expansions).

**How to Test with Burp Suite**
1. Send a Billion Laughs XML payload:
```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;">
  ...
]>
<lolz>&lol100;</lolz>
```
2. Observe if the server becomes unresponsive.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Disable external entities and limit entity expansion.
- Use secure XML parser configurations.

---

## 25. NO LIMIT ON URL PARAMETER LENGTH OR REDIRECT LOOPS

**Description**  
Long URL parameters can cause buffer overflows or log spam. Redirect loops can cause infinite request chains.

**What to Look For**
- No limit on URL length (e.g., 10,000 characters).
- Redirect endpoint that can create loops (e.g., `?url=http://target.com/redirect?url=...`).

**What to Ignore**
- Maximum URL length enforced.

**How to Test with Burp Suite**
1. Send a request with a 50,000 character parameter.
2. For redirect loops, create a chain of redirects that points back to itself.

**Tools**
- Burp Repeater

**Risk Rating**  
Low to Medium

**Remediation**
- Limit URL length (e.g., 2000 characters).
- Prevent redirect loops by checking visited URLs.

---

## 26. NO RATE LIMITING ON WEBHOOK / CALLBACK ENDPOINTS

**Description**  
Webhook endpoints can be abused to send a flood of requests to a target server, turning the API into a DoS amplifier.

**What to Look For**
- Webhook registration that allows many calls per second.
- No rate limiting on outgoing webhook calls.

**What to Ignore**
- Rate limiting on webhook delivery.

**How to Test with Burp Suite**
1. Register a webhook to a slow endpoint.
2. Trigger events that cause many callbacks.

**Tools**
- Burp Proxy
- Custom webhook listener

**Risk Rating**  
Medium

**Remediation**
- Rate limit outgoing webhook calls per client.
- Implement circuit breakers.

---

## 27. NO LIMIT ON REGULAR EXPRESSION COMPLEXITY (REDOS)

**Description**  
User‑supplied regex patterns (or server‑side regex with user input) can cause ReDoS (Regular Expression Denial of Service) via catastrophic backtracking.

**What to Look For**
- Endpoints that accept regex patterns (e.g., search with regex).
- Server‑side regex that processes user input.

**What to Ignore**
- Timeout on regex execution.

**How to Test with Burp Suite**
1. Send a regex like `(a+)+$` with a long string of `a`s.
2. Observe if the request takes a very long time.

**Example**
```http
GET /api/search?regex=(a+)+$&input=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

**Tools**
- ReDoS payload generators

**Risk Rating**  
Medium

**Remediation**
- Set a timeout on regex execution.
- Avoid user‑supplied regex; use whitelisted patterns.

---

## 28. NO LIMIT ON DATABASE QUERY RESULT SIZE (FULL TABLE SCAN)

**Description**  
APIs that execute database queries without `LIMIT` can cause full table scans, leading to performance degradation.

**What to Look For**
- Endpoints that return all rows from a table.
- No pagination or result size limit.

**What to Ignore**
- Default `LIMIT` applied to queries.

**How to Test with Burp Suite**
1. Call an endpoint that lists resources (e.g., `/api/transactions`).
2. If the response contains thousands of records, the API may be performing full table scans.

**Tools**
- Burp Proxy

**Risk Rating**  
High

**Remediation**
- Always apply `LIMIT` and `OFFSET` in database queries.
- Enforce maximum result size (e.g., 1000).

---

## 29. NO THROTTLING ON CACHE INVALIDATION REQUESTS

**Description**  
Cache purging endpoints without rate limiting can be abused to repeatedly invalidate cache, causing performance degradation.

**What to Look For**
- Endpoints like `/api/cache/purge` or `Cache-Control` purge.
- No rate limiting on purge requests.

**What to Ignore**
- Authentication and rate limiting on purge.

**How to Test with Burp Suite**
1. Send 100 purge requests in a short time.
2. Observe if they are all processed.

**Tools**
- Burp Intruder

**Risk Rating**  
Medium

**Remediation**
- Rate limit cache invalidation requests.
- Require authentication for purge endpoints.

---

## 30. NO RESOURCE LIMITS ON SERVERLESS FUNCTIONS (AWS LAMBDA, AZURE FUNCTIONS)

**Description**  
Serverless functions may have default resource limits, but an attacker can cause excessive invocations, leading to high cloud bills.

**What to Look For**
- Publicly accessible serverless API endpoints.
- No rate limiting or budget alerts.

**What to Ignore**
- Concurrency limits and budget caps.

**How to Test with Burp Suite**
1. Use Turbo Intruder to invoke the serverless function many times.
2. Monitor cloud provider dashboard for invocation count.

**Tools**
- Burp Turbo Intruder
- Cloud monitoring

**Risk Rating**  
Critical (financial)

**Remediation**
- Implement API rate limiting at the API gateway.
- Set concurrency limits and budget alerts.
- Use AWS WAF or CloudFront rate limiting.

---

## ✅ **SUMMARY**

Unrestricted Resource Consumption (API4) covers a wide range of attacks that exhaust server resources, including rate limiting bypasses, large payloads, deep GraphQL queries, and file upload bombs. This guide provides 30 testing vectors.

### **Key Testing Areas Summary**

| Failure Type | Key Indicators | Risk |
|--------------|----------------|------|
| Missing Rate Limiting | No `429` responses | High-Critical |
| IP Rotation Bypass | `X-Forwarded-For` spoofing | High |
| User Enumeration Bypass | Cycling user IDs | Medium |
| Session‑Only Limits | Many sessions bypass | High |
| Large Payload | No `413` response | High |
| Many Query Params | 1000+ parameters | Medium |
| Many JSON Fields | 10,000 fields | Medium |
| GraphQL Depth | Deep nesting | High |
| GraphQL Complexity | Many fields | High |
| GraphQL Batching | Batch with 100 ops | High |
| File Upload Size | 1GB uploads | High |
| Auth Endpoint Limits | No login rate limit | Critical |
| Password Reset Limits | Many reset emails | High |
| Long Search Queries | 10k chars | Medium |
| No Pagination | Huge responses | High |
| Array Expansion | 10k array elements | High |
| No Timeout | Slowloris | Medium |
| Connection Limit | Many TCP connections | High |
| Concurrent Requests | 100 parallel | Medium |
| WebSocket Flood | 1000 messages/sec | High |
| WebSocket Duration | Never closes | Medium |
| Batch Size | 1000 operations | High |
| Image Bomb | Decompression attack | High |
| XML Billion Laughs | Entity expansion | Critical |
| Long URL | 50k chars | Low-Medium |
| Webhook Flood | Many callbacks | Medium |
| ReDoS | Catastrophic backtracking | Medium |
| Full Table Scan | No `LIMIT` | High |
| Cache Purge | Unlimited purges | Medium |
| Serverless Limits | Infinite invocations | Critical |

### **Pro Tips for Testing Unrestricted Resource Consumption**
1. **Use Turbo Intruder** for high‑rate tests (but be careful not to crash the target).
2. **Check for rate limit headers** – `X-RateLimit-*`, `Retry-After`.
3. **Test both authenticated and unauthenticated endpoints**.
4. **Try to bypass limits** using IP rotation, user ID rotation, or session cycling.
5. **Send large payloads** (JSON, XML, files) to test size limits.
6. **For GraphQL**, always test depth, complexity, and batching.
7. **Monitor response times** – a sudden increase may indicate resource exhaustion.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
