# 🔗 **API10:2023 - UNSAFE CONSUMPTION OF APIS TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Risks When APIs Consume Other APIs*

---

## 📋 **TABLE OF CONTENTS**

1. [Trusting External API Responses Without Validation (Data Injection)](#1-trusting-external-api-responses-without-validation-data-injection)
2. [No Input Sanitisation of Data from Third‑Party APIs (XSS, SQLi)](#2-no-input-sanitisation-of-data-from-third-party-apis-xss-sqli)
3. [Insecure Handling of Webhook Callbacks (No Signature Verification)](#3-insecure-handling-of-webhook-callbacks-no-signature-verification)
4. [SSRF via Consumed API URLs (Attacker‑Controlled Endpoints)](#4-ssrf-via-consumed-api-urls-attacker-controlled-endpoints)
5. [JWT or Token Validation Bypass from External Identity Providers](#5-jwt-or-token-validation-bypass-from-external-identity-providers)
6. [Insecure Deserialisation of API Responses (Pickle, YAML, Java)](#6-insecure-deserialisation-of-api-responses-pickle-yaml-java)
7. [No Response Schema Validation (Unexpected Fields Accepted)](#7-no-response-schema-validation-unexpected-fields-accepted)
8. [Improper Error Handling from External APIs (Information Leakage)](#8-improper-error-handling-from-external-apis-information-leakage)
9. [Lack of Timeout on External API Calls (Slowloris, DoS)](#9-lack-of-timeout-on-external-api-calls-slowloris-dos)
10. [Missing Rate Limiting When Consuming Third‑Party APIs (Abuse of Quota)](#10-missing-rate-limiting-when-consuming-third-party-apis-abuse-of-quota)
11. [Insecure Storage of Third‑Party API Credentials (Hardcoded Secrets)](#11-insecure-storage-of-third-party-api-credentials-hardcoded-secrets)
12. [No Validation of Webhook Source IP or Origin](#12-no-validation-of-webhook-source-ip-or-origin)
13. [Consuming APIs Over Unencrypted Channels (HTTP)](#13-consuming-apis-over-unencrypted-channels-http)
14. [No Handling of Malformed or Unexpected API Responses (DoS)](#14-no-handling-of-malformed-or-unexpected-api-responses-dos)
15. [Insecure Redirect Handling (Following 302 to Malicious Sites)](#15-insecure-redirect-handling-following-302-to-malicious-sites)
16. [Exposure of Internal Data to Third‑Party APIs (Over‑sharing)](#16-exposure-of-internal-data-to-third-party-apis-over-sharing)
17. [No Certificate Pinning for External API Calls](#17-no-certificate-pinning-for-external-api-calls)
18. [Race Conditions When Calling External Idempotent APIs](#18-race-conditions-when-calling-external-idempotent-apis)
19. [Logging Sensitive Data from External API Responses](#19-logging-sensitive-data-from-external-api-responses)
20. [Insecure Handling of API Versioning from Dependencies](#20-insecure-handling-of-api-versioning-from-dependencies)
21. [No Validation of Webhook Retry Logic (Replay Attacks)](#21-no-validation-of-webhook-retry-logic-replay-attacks)
22. [Missing HMAC or Signature Verification on Callbacks](#22-missing-hmac-or-signature-verification-on-callbacks)
23. [Insecure Consumption of GraphQL APIs (Deep Queries)](#23-insecure-consumption-of-graphql-apis-deep-queries)
24. [No Handling of Large API Responses (Memory Exhaustion)](#24-no-handling-of-large-api-responses-memory-exhaustion)
25. [Consuming APIs Without Proper Authentication (Missing API Keys)](#25-consuming-apis-without-proper-authentication-missing-api-keys)
26. [Insecure Caching of External API Responses (Sensitive Data)](#26-insecure-caching-of-external-api-responses-sensitive-data)
27. [No Validation of Webhook Event Types (Unauthorised Actions)](#27-no-validation-of-webhook-event-types-unauthorised-actions)
28. [Exposing Internal Error Details When External API Fails](#28-exposing-internal-error-details-when-external-api-fails)
29. [Consuming Deprecated or Unmaintained Third‑Party APIs](#29-consuming-deprecated-or-unmaintained-third-party-apis)
30. [Lack of Fallback or Circuit Breaker for External API Failures](#30-lack-of-fallback-or-circuit-breaker-for-external-api-failures)

---

## 1. TRUSTING EXTERNAL API RESPONSES WITHOUT VALIDATION (DATA INJECTION)

**Description**  
When an API consumes data from an external API (e.g., a third‑party weather service, payment gateway, or social media API) and uses that data directly without validation, an attacker who compromises the external API or performs a MITM attack can inject malicious content (XSS, SQLi, command injection) into the consuming API.

**What to Look For**
- The application fetches data from a third‑party API and embeds it into responses or database queries.
- No validation, sanitisation, or schema checking of the external response.

**What to Ignore**
- External responses validated against a strict schema or sanitised before use.

**How to Test with Burp Suite**
1. Identify endpoints that call external APIs (e.g., `/weather`, `/social-posts`, `/payment-status`).
2. Use Burp Suite to intercept the external API response (if you can control the external server or use a MITM approach).
3. Modify the response to include malicious payloads (e.g., `<script>alert(1)</script>`, `' OR '1'='1`).
4. Observe if the consuming API reflects the payload in its own response or uses it in a query.

**Example**
```http
GET /api/weather?city=London HTTP/1.1
```
The backend calls `https://weather-api.com?q=London` and returns:
```json
{"temp": "22", "condition": "<script>alert(1)</script>"}
```
If the consuming API returns this condition in an HTML page without encoding, XSS occurs.

**Tools**
- Burp Suite (with upstream proxy or MITM)
- Custom mock API server

**Risk Rating**  
High to Critical

**Remediation**
- Validate external API responses against a strict schema.
- Sanitise or encode data before using it in outputs or database queries.

---

## 2. NO INPUT SANITISATION OF DATA FROM THIRD‑PARTY APIS (XSS, SQLI)

**Description**  
Data received from third‑party APIs is often stored in a database or rendered in web pages. If not sanitised, it can lead to SQL injection, XSS, or command injection when the consuming API processes it.

**What to Look For**
- External data stored directly in SQL queries without parameterisation.
- External data reflected in HTML/JSON without encoding.

**What to Ignore**
- Data sanitised (e.g., using parameterised queries, output encoding).

**How to Test with Burp Suite**
1. Identify an external API that the application trusts.
2. If you can control the external API (e.g., via SSRF or by registering a test webhook), send a malicious payload in the response.
3. Trigger the consuming API endpoint that processes that data.
4. Observe if the payload executes (e.g., XSS alert, SQL error).

**Example**
- External API returns `{"name": "'; DROP TABLE users; --"}`.
- The consuming API uses this value in an SQL query without parameterisation → SQL injection.

**Tools**
- Burp Suite
- Custom external API simulator

**Risk Rating**  
Critical

**Remediation**
- Always use parameterised queries for database operations.
- Output‑encode data based on context (HTML, JSON, etc.).

---

## 3. INSECURE HANDLING OF WEBHOOK CALLBACKS (NO SIGNATURE VERIFICATION)

**Description**  
APIs that receive webhook callbacks from third‑party services often fail to verify the authenticity of the request (e.g., missing HMAC signature validation). Attackers can forge webhook events to trigger unauthorised actions.

**What to Look For**
- Webhook endpoints that accept POST requests without checking a signature header.
- No validation of the request origin or payload integrity.

**What to Ignore**
- Webhook signatures verified (e.g., `X-Signature` header with HMAC).

**How to Test with Burp Suite**
1. Identify a webhook endpoint (e.g., `/webhook/payment`, `/webhook/github`).
2. Send a crafted POST request that mimics a legitimate webhook event.
3. If the consuming API processes the event without rejecting the request, signature verification is missing.

**Example**
```http
POST /webhook/order-update HTTP/1.1
{"orderId":123,"status":"paid"}
```
If the order is marked as paid without verifying a signature, vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Verify webhook signatures using a shared secret (e.g., HMAC‑SHA256).
- Reject requests without valid signatures.

---

## 4. SSRF VIA CONSUMED API URLS (ATTACKER‑CONTROLLED ENDPOINTS)

**Description**  
If an API consumes another API and the target URL is partially or fully controlled by the attacker (e.g., via a parameter), it can lead to SSRF, allowing the server to make requests to internal services.

**What to Look For**
- Parameters like `callback_url`, `webhook_url`, `redirect_uri`, `external_endpoint`.
- The server makes an HTTP request to that URL.

**What to Ignore**
- URLs validated against a whitelist or hardened.

**How to Test with Burp Suite**
1. Find an endpoint that accepts a URL parameter.
2. Set the URL to `http://169.254.169.254/latest/meta-data/`.
3. If the server fetches the metadata, SSRF is present.

**Example**
```http
POST /api/register-webhook
{"url": "http://169.254.169.254/latest/meta-data/"}
```
The server then makes a request to the metadata service.

**Tools**
- Burp Repeater
- Burp Collaborator

**Risk Rating**  
Critical

**Remediation**
- Validate and whitelist allowed URLs.
- Do not allow user‑controlled URLs for server‑side requests.

---

## 5. JWT OR TOKEN VALIDATION BYPASS FROM EXTERNAL IDENTITY PROVIDERS

**Description**  
When an API accepts JWTs from external identity providers (e.g., Google, Auth0), it must validate the signature, issuer, audience, and expiry. Failure to do so allows attackers to forge tokens.

**What to Look For**
- JWT tokens from external IdPs accepted without signature validation.
- No check of `iss`, `aud`, or `exp` claims.

**What to Ignore**
- Proper JWT validation with well‑known public keys.

**How to Test with Burp Suite**
1. Obtain a JWT from the external IdP (e.g., using a test account).
2. Modify the payload (e.g., change `"role":"user"` to `"role":"admin"`).
3. Keep the original signature (or use `none` algorithm if accepted).
4. Send the modified token to the API.
5. If the API accepts it, validation is flawed.

**Example**
```json
{
  "alg": "RS256",
  "typ": "JWT"
}
{
  "user_id": 123,
  "role": "admin"
}
```
Modified token accepted.

**Tools**
- jwt_tool
- Burp JWT Editor

**Risk Rating**  
Critical

**Remediation**
- Validate JWT signature using the IdP’s public key.
- Check `iss`, `aud`, `exp`, and `nbf` claims.

---

## 6. INSECURE DESERIALIZATION OF API RESPONSES (PICKLE, YAML, JAVA)

**Description**  
Some APIs deserialize external responses using unsafe formats (Python `pickle`, Ruby `YAML.load`, Java `ObjectInputStream`). Attackers who control the external API can execute arbitrary code.

**What to Look For**
- Use of `pickle.loads()` on data from third‑party APIs.
- Use of `YAML.load` instead of `safe_load`.

**What to Ignore**
- Safe deserialisation (JSON, XML with schema validation).

**How to Test with Burp Suite**
1. Identify an external API that returns serialised data (e.g., base64‑encoded pickle).
2. If you can control the external API, send a malicious serialised payload.
3. Trigger the consuming API endpoint that deserialises it.
4. Observe for code execution or errors.

**Example**
```python
# Consuming API code
data = pickle.loads(external_response)
```
Attacker sends a crafted pickle payload.

**Tools**
- ysoserial
- Custom payload generators

**Risk Rating**  
Critical

**Remediation**
- Avoid deserialising untrusted data.
- Use safe formats (JSON) and validate schemas.

---

## 7. NO RESPONSE SCHEMA VALIDATION (UNEXPECTED FIELDS ACCEPTED)

**Description**  
APIs that consume external services often blindly accept all fields in the response. Attackers can inject extra fields that the consuming API might store or act upon (mass assignment).

**What to Look For**
- The consuming API uses external response data to update internal objects without filtering fields.
- No schema validation or whitelist of allowed fields.

**What to Ignore**
- Strict schema validation; only expected fields are processed.

**How to Test with Burp Suite**
1. If you can control the external API response, add an extra field (e.g., `"isAdmin": true`).
2. See if the consuming API applies that field to an internal object.

**Example**
External API returns:
```json
{"username": "john", "isAdmin": true}
```
The consuming API updates a user object with all fields, making the user admin.

**Tools**
- Burp Repeater
- Custom external API mock

**Risk Rating**  
High

**Remediation**
- Validate external responses against a strict schema.
- Only copy allowed fields into internal objects.

---

## 8. IMPROPER ERROR HANDLING FROM EXTERNAL APIS (INFORMATION LEAKAGE)

**Description**  
When an external API call fails, the consuming API may return verbose error details (stack traces, internal paths, database errors) to the client, leaking sensitive information.

**What to Look For**
- Error responses containing stack traces or internal error messages.
- No generic error handling.

**What to Ignore**
- Generic error messages (e.g., `{"error":"External service unavailable"}`).

**How to Test with Burp Suite**
1. Cause an external API call to fail (e.g., by providing an invalid parameter or causing the external API to return an error).
2. Observe the response from the consuming API.

**Example**
```json
{"error": "SQLSTATE[42S02]: Table 'prod.orders' doesn't exist"}
```
Leaks database structure.

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Catch exceptions from external API calls and return generic error messages.
- Log detailed errors internally.

---

## 9. LACK OF TIMEOUT ON EXTERNAL API CALLS (SLOWLORIS, DOS)

**Description**  
If the consuming API does not set a timeout when calling external APIs, an attacker can cause the external API to hang (e.g., Slowloris) and tie up server threads, leading to denial of service.

**What to Look For**
- No timeout configuration for HTTP client.
- Requests that never return.

**What to Ignore**
- Timeouts set (e.g., 5 seconds).

**How to Test with Burp Suite**
1. Identify an endpoint that calls an external API.
2. Configure a malicious external server that never responds (or responds very slowly).
3. Send a request and observe if the consuming API times out or hangs indefinitely.

**Tools**
- Slowloris script
- Custom slow server

**Risk Rating**  
High

**Remediation**
- Set reasonable timeouts (e.g., 5–10 seconds) for all external API calls.

---

## 10. MISSING RATE LIMITING WHEN CONSUMING THIRD‑PARTY APIS (ABUSE OF QUOTA)

**Description**  
If the consuming API does not rate limit its calls to third‑party services, an attacker can trigger many calls and exhaust the third‑party’s quota, causing financial cost or denial of service.

**What to Look For**
- No rate limiting on endpoints that call expensive external APIs (e.g., geocoding, SMS, payment).
- Ability to send many requests quickly.

**What to Ignore**
- Rate limiting implemented per user/IP.

**How to Test with Burp Suite**
1. Use Intruder to send 100 requests to an endpoint that calls a paid external API.
2. If all requests go through, rate limiting is missing.

**Example**
```http
POST /api/send-sms HTTP/1.1
{"phone":"+1234567890","message":"test"}
```
100 requests all succeed, incurring cost.

**Tools**
- Burp Intruder

**Risk Rating**  
High

**Remediation**
- Implement rate limiting on endpoints that call external APIs.
- Use caching to reduce duplicate calls.

---

## 11. INSECURE STORAGE OF THIRD‑PARTY API CREDENTIALS (HARDCODED SECRETS)

**Description**  
API keys or secrets for external services are often hardcoded in source code, configuration files, or environment variables without proper protection, leading to credential leakage.

**What to Look For**
- API keys in source code, `config.js`, `.env` files exposed.
- Keys in client‑side JavaScript.

**What to Ignore**
- Secrets stored in secure vaults (e.g., HashiCorp Vault, AWS Secrets Manager).

**How to Test with Burp Suite**
1. Search for common API key patterns in source code, responses, and files.
2. Use forced browsing to find `.env`, `config.json`, `settings.php`.

**Example**
```javascript
const STRIPE_SECRET = "sk_live_abc123";
```

**Tools**
- Burp search
- TruffleHog

**Risk Rating**  
Critical

**Remediation**
- Store secrets in secure vaults.
- Never hardcode secrets; use environment variables with restricted access.

---

## 12. NO VALIDATION OF WEBHOOK SOURCE IP OR ORIGIN

**Description**  
Webhook endpoints that do not validate the source IP or `User-Agent` of incoming requests can be spoofed by attackers to send fake events.

**What to Look For**
- No IP whitelisting for webhook callbacks.
- No verification of `User-Agent` or `Origin` header.

**What to Ignore**
- IP whitelisting (e.g., only allow GitHub’s IP ranges).

**How to Test with Burp Suite**
1. Identify a webhook endpoint.
2. Send a request from an IP not on the whitelist (or spoof `X-Forwarded-For`).
3. If the webhook is processed, source validation is missing.

**Example**
```http
POST /webhook/github HTTP/1.1
```
If any IP can trigger it, vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Whitelist known IP ranges of the external service.
- Verify webhook signatures instead of relying on IP.

---

## 13. CONSUMING APIS OVER UNENCRYPTED CHANNELS (HTTP)

**Description**  
Calling external APIs over plain HTTP exposes the request and response to MITM attacks, allowing attackers to intercept or modify data.

**What to Look For**
- API calls using `http://` instead of `https://`.
- No enforcement of HTTPS for external endpoints.

**What to Ignore**
- All external calls over HTTPS.

**How to Test with Burp Suite**
1. Monitor traffic from the consuming API.
2. If any request goes to an HTTP URL, it is insecure.

**Example**
```http
GET http://api.weather.com/current?city=London
```

**Tools**
- Burp Proxy
- Wireshark

**Risk Rating**  
Critical

**Remediation**
- Always use HTTPS for external API calls.
- Enforce certificate validation.

---

## 14. NO HANDLING OF MALFORMED OR UNEXPECTED API RESPONSES (DOS)

**Description**  
If the consuming API does not handle malformed responses (e.g., missing fields, invalid JSON), it may crash or behave unpredictably, leading to DoS.

**What to Look For**
- No error handling for unexpected response structures.
- Assumptions that external API will always return correct data.

**What to Ignore**
- Defensive parsing and validation.

**How to Test with Burp Suite**
1. Intercept an external API response (if you can control it) and corrupt it (e.g., missing brackets, invalid types).
2. See if the consuming API crashes or returns a 5xx error.

**Example**
External API returns `{"temp": }` (invalid JSON). The consuming API throws an unhandled exception.

**Tools**
- Burp Suite (manual response modification)

**Risk Rating**  
Medium

**Remediation**
- Implement robust error handling and validation for external responses.
- Use try‑catch blocks and default fallbacks.

---

## 15. INSECURE REDIRECT HANDLING (FOLLOWING 302 TO MALICIOUS SITES)

**Description**  
When consuming APIs follow HTTP redirects, an attacker could cause the external API to return a 302 redirect to a malicious site, leading to SSRF or data exfiltration.

**What to Look For**
- HTTP client configured to follow redirects automatically.
- No validation of redirect targets.

**What to Ignore**
- Redirects disabled or validated against a whitelist.

**How to Test with Burp Suite**
1. Set up a mock external API that returns `302 Location: http://169.254.169.254/`.
2. Make the consuming API call this mock.
3. If the server follows the redirect and fetches the internal metadata, vulnerable.

**Tools**
- Burp Suite (with custom redirect server)

**Risk Rating**  
High

**Remediation**
- Disable automatic redirect following for external API calls.
- Validate redirect targets against a whitelist.

---

## 16. EXPOSURE OF INTERNAL DATA TO THIRD‑PARTY APIS (OVER‑SHARING)

**Description**  
When consuming APIs send data to external services, they may inadvertently include internal identifiers, tokens, or PII in request parameters or headers, which the third‑party could log or misuse.

**What to Look For**
- Requests to external APIs containing internal user IDs, session tokens, or database keys.
- No filtering of sensitive data.

**What to Ignore**
- Only necessary, non‑sensitive data sent.

**How to Test with Burp Suite**
1. Intercept a request to an external API.
2. Examine the request body and headers for sensitive fields (e.g., `user_id`, `session_token`, `internal_ip`).

**Example**
```http
POST https://analytics.external.com/track
{"user_id": 123, "internal_visitor_id": "xyz789"}
```

**Tools**
- Burp Proxy

**Risk Rating**  
High

**Remediation**
- Minimise data sent to third parties.
- Anonymise or hash sensitive identifiers.

---

## 17. NO CERTIFICATE PINNING FOR EXTERNAL API CALLS

**Description**  
Without certificate pinning, the consuming API may accept any certificate trusted by the system, allowing MITM attacks if a trusted CA is compromised.

**What to Look For**
- No certificate pinning for critical external APIs (e.g., payment gateways).
- Use of default system trust store.

**What to Ignore**
- Certificate pinning implemented.

**How to Test with Burp Suite**
1. Configure Burp as a MITM proxy.
2. If the consuming API does not reject Burp’s self‑signed certificate, pinning is missing.

**Tools**
- Burp Suite (as MITM)

**Risk Rating**  
High

**Remediation**
- Implement certificate pinning for high‑value external APIs.
- Use public key pinning or certificate hashes.

---

## 18. RACE CONDITIONS WHEN CALLING EXTERNAL IDEMPOTENT APIS

**Description**  
If the consuming API makes multiple concurrent calls to an external idempotent API (e.g., payment capture), race conditions can cause duplicate charges or actions.

**What to Look For**
- No idempotency keys used.
- Multiple identical requests sent concurrently.

**What to Ignore**
- Idempotency keys and transaction locking.

**How to Test with Burp Suite**
1. Use Turbo Intruder to send the same request to an external API endpoint multiple times concurrently.
2. Observe if the external API processes the same action twice.

**Example**
```http
POST /api/charge HTTP/1.1
{"amount":100,"card":"1234"}
```
Concurrent requests may double charge.

**Tools**
- Burp Turbo Intruder

**Risk Rating**  
High

**Remediation**
- Use idempotency keys (e.g., UUID) for external API calls.
- Implement server‑side deduplication.

---

## 19. LOGGING SENSITIVE DATA FROM EXTERNAL API RESPONSES

**Description**  
Logging full external API responses can inadvertently store sensitive data (e.g., credit card numbers, tokens, PII) in logs, violating compliance.

**What to Look For**
- Logs containing raw external API responses.
- No redaction of sensitive fields.

**What to Ignore**
- Logs sanitised before storage.

**How to Test with Burp Suite**
1. If logs are accessible (e.g., via debug endpoint), search for sensitive patterns.
2. Trigger an external API call and check log files.

**Example**
Log entry: `2024-01-01 External API response: {"card_number": "4111111111111111"}`

**Tools**
- Log review

**Risk Rating**  
High

**Remediation**
- Do not log sensitive data from external APIs.
- Redact or mask sensitive fields.

---

## 20. INSECURE HANDLING OF API VERSIONING FROM DEPENDENCIES

**Description**  
Consuming APIs often depend on specific versions of third‑party APIs. If versioning is not managed, a breaking change in the external API can cause the consuming API to fail or behave unexpectedly.

**What to Look For**
- No version pinning in API calls (e.g., `/v1/` not specified).
- No handling of version deprecation.

**What to Ignore**
- Version pinned and deprecation policy followed.

**How to Test with Burp Suite**
1. Identify external API calls without explicit version.
2. Test if a newer version of the external API would break the integration (requires knowledge).

**Tools**
- Manual code review

**Risk Rating**  
Medium

**Remediation**
- Pin API versions in requests (e.g., `/v1/`).
- Monitor deprecation notices and plan upgrades.

---

## 21. NO VALIDATION OF WEBHOOK RETRY LOGIC (REPLAY ATTACKS)

**Description**  
If webhook endpoints do not track request IDs or idempotency keys, an attacker can replay a valid webhook event to trigger duplicate actions (e.g., refund twice, mark order paid again).

**What to Look For**
- No idempotency key or request ID in webhook processing.
- Same webhook accepted multiple times.

**What to Ignore**
- Webhook ID stored and deduplicated.

**How to Test with Burp Suite**
1. Capture a legitimate webhook request.
2. Replay the same request multiple times.
3. If the action is performed each time, replay protection is missing.

**Example**
```http
POST /webhook/payment-success
{"orderId":123,"transactionId":"txn_abc"}
```
Replayed → order marked paid again.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Store and check `X-Request-Id` or `Idempotency-Key` headers.
- Deduplicate requests within a time window.

---

## 22. MISSING HMAC OR SIGNATURE VERIFICATION ON CALLBACKS

**Description**  
Webhook callbacks often include a signature header (e.g., `X-Signature`). If the consuming API does not verify it, attackers can forge events.

**What to Look For**
- Webhook endpoint that does not verify signature.
- Signature header present but ignored.

**What to Ignore**
- Signature verified using shared secret.

**How to Test with Burp Suite**
1. Send a forged webhook request without a signature.
2. If it is processed, verification is missing.

**Example**
```http
POST /webhook/stripe
{"event":"charge.succeeded"}
```
No signature header.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Verify webhook signatures using the provider’s documented method.
- Reject unsigned requests.

---

## 23. INSECURE CONSUMPTION OF GRAPHQL APIS (DEEP QUERIES)

**Description**  
When a consuming API makes GraphQL requests to an external service, it may be vulnerable to the same issues as direct GraphQL (e.g., depth attacks). If the external API is untrusted, the consuming API could be DoSed.

**What to Look For**
- GraphQL queries that allow deep nesting or aliases.
- No query cost limits.

**What to Ignore**
- Queries with depth and complexity limits.

**How to Test with Burp Suite**
1. If the consuming API builds GraphQL queries from user input, try to inject deep nesting.
2. Observe response time.

**Example**
```graphql
query {
  user {
    friends { friends { friends { ... } } }
  }
}
```

**Tools**
- GraphQL Raider

**Risk Rating**  
Medium

**Remediation**
- Set depth and complexity limits on GraphQL queries.
- Use persistent queries (allowlist).

---

## 24. NO HANDLING OF LARGE API RESPONSES (MEMORY EXHAUSTION)

**Description**  
If the consuming API does not limit the size of responses from external APIs, an attacker could cause the external API to return a huge response (e.g., 100MB JSON), exhausting server memory.

**What to Look For**
- No response size limit.
- Streaming not used for large data.

**What to Ignore**
- Response size limits and streaming.

**How to Test with Burp Suite**
1. If you can control the external API, make it return a very large JSON.
2. Observe if the consuming API crashes or becomes slow.

**Tools**
- Custom external API

**Risk Rating**  
Medium

**Remediation**
- Set maximum response size limits.
- Use streaming parsers for large responses.

---

## 25. CONSUMING APIS WITHOUT PROPER AUTHENTICATION (MISSING API KEYS)

**Description**  
The consuming API may call external APIs without providing the required authentication (e.g., API key, OAuth token), leading to failed requests or, if the external API is public, exposing internal calls.

**What to Look For**
- No authentication headers in requests to external APIs.
- Using default or test keys in production.

**What to Ignore**
- Proper authentication configured.

**How to Test with Burp Suite**
1. Intercept requests to external APIs.
2. Check if authentication headers (e.g., `Authorization`, `X-API-Key`) are present.
3. If missing, the integration may be misconfigured.

**Example**
```http
GET http://api.example.com/data
```
No API key.

**Tools**
- Burp Proxy

**Risk Rating**  
High

**Remediation**
- Always include required authentication for external API calls.
- Use environment‑specific keys.

---

## 26. INSECURE CACHING OF EXTERNAL API RESPONSES (SENSITIVE DATA)

**Description**  
Caching external API responses that contain user‑specific data can lead to one user seeing another user’s data.

**What to Look For**
- Cache headers (`Cache-Control`) set on external API responses that are stored and reused across users.
- No user context in cache keys.

**What to Ignore**
- Private caching or cache keys include user ID.

**How to Test with Burp Suite**
1. As User A, trigger an external API call that returns user‑specific data.
2. As User B, trigger the same call.
3. If User B receives User A’s data, caching is insecure.

**Tools**
- Burp Proxy
- Multiple user sessions

**Risk Rating**  
High

**Remediation**
- Include user context in cache keys (e.g., `cache-key: user:123`).
- Set `Cache-Control: private, no-store` for sensitive data.

---

## 27. NO VALIDATION OF WEBHOOK EVENT TYPES (UNAUTHORISED ACTIONS)

**Description**  
Webhook endpoints that accept any event type without validating the event type can be abused to trigger actions not intended for the webhook.

**What to Look For**
- Webhook endpoint processes any event without checking `type` or `event` field.
- No whitelist of allowed events.

**What to Ignore**
- Event type validation.

**How to Test with Burp Suite**
1. Send a webhook request with an event type that should not be processed (e.g., `user.deleted` instead of `order.paid`).
2. If the action is still performed, validation is missing.

**Example**
```http
POST /webhook/payment
{"type":"user.delete","userId":123}
```
User 123 is deleted.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Whitelist allowed event types for each webhook endpoint.
- Reject unknown events.

---

## 28. EXPOSING INTERNAL ERROR DETAILS WHEN EXTERNAL API FAILS

**Description**  
When an external API call fails, the consuming API may return internal error details (e.g., `Connection refused`, `No route to host`) to the client, aiding network reconnaissance.

**What to Look For**
- Error messages revealing network topology (IP addresses, port numbers, service names).
- Stack traces from HTTP client libraries.

**What to Ignore**
- Generic error messages.

**How to Test with Burp Suite**
1. Cause an external API call to fail (e.g., by pointing to a non‑existent host).
2. Observe the error response.

**Example**
```json
{"error": "Connection refused to 10.0.0.5:8080"}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Return generic error messages (e.g., `External service unavailable`).
- Log detailed errors internally.

---

## 29. CONSUMING DEPRECATED OR UNMAINTAINED THIRD‑PARTY APIS

**Description**  
Using deprecated or unmaintained external APIs increases the risk of security vulnerabilities, as patches are no longer released.

**What to Look For**
- API version that is no longer supported (e.g., Twilio API v1, old Stripe API).
- No migration to newer versions.

**What to Ignore**
- Up‑to‑date, actively maintained APIs.

**How to Test with Burp Suite**
1. Check request URLs for version numbers (e.g., `/v1/`, `/api/2010-04-01/`).
2. Research if that version is deprecated.

**Example**
```http
GET https://api.twilio.com/2010-04-01/Accounts
```
2010-04-01 is still supported, but older versions may be deprecated.

**Tools**
- Manual research
- API documentation

**Risk Rating**  
High

**Remediation**
- Regularly update to supported API versions.
- Monitor deprecation announcements.

---

## 30. LACK OF FALLBACK OR CIRCUIT BREAKER FOR EXTERNAL API FAILURES

**Description**  
If an external API becomes unavailable, the consuming API may repeatedly attempt to call it, causing cascading failures and thread exhaustion.

**What to Look For**
- No circuit breaker pattern.
- No fallback response or degraded mode.

**What to Ignore**
- Circuit breaker implemented (e.g., fail fast after X failures).

**How to Test with Burp Suite**
1. Point the external API URL to a non‑responsive server.
2. Send many concurrent requests to the consuming API.
3. Observe if the consuming API becomes unresponsive.

**Tools**
- Burp Intruder
- Custom slow server

**Risk Rating**  
High

**Remediation**
- Implement a circuit breaker (e.g., Hystrix, Resilience4j).
- Provide fallback responses (e.g., cached data or default values).

---

## ✅ **SUMMARY**

Unsafe Consumption of APIs (API10) occurs when an API calls external services without proper security controls, leading to injection, SSRF, data leakage, replay attacks, and denial of service. This guide covers 30 test cases.

### **Key Testing Areas Summary**

| Failure Type | Key Indicators | Risk |
|--------------|----------------|------|
| Trusting External Responses | No validation, data injection | High-Critical |
| No Sanitisation | XSS, SQLi from external data | Critical |
| Webhook Signature Missing | Unsigned webhooks | Critical |
| SSRF via Consumed API | User‑controlled URL | Critical |
| JWT Validation Bypass | Unsigned/modified tokens | Critical |
| Insecure Deserialisation | Pickle, YAML, Java | Critical |
| No Schema Validation | Extra fields accepted | High |
| Error Leakage | Stack traces from external failures | Medium |
| No Timeout | DoS via slow external API | High |
| Missing Rate Limiting | Quota exhaustion | High |
| Hardcoded Secrets | API keys in code | Critical |
| No IP Validation | Webhook from any IP | High |
| HTTP Calls | Unencrypted external calls | Critical |
| Malformed Response Handling | Crash on invalid JSON | Medium |
| Insecure Redirects | Following 302 to internal IP | High |
| Over‑sharing Data | Sending internal IDs | High |
| No Certificate Pinning | MITM possible | High |
| Race Conditions | Duplicate charges | High |
| Logging Sensitive Data | Credit cards in logs | High |
| Versioning Issues | No version pinning | Medium |
| Webhook Replay | No idempotency | High |
| HMAC Missing | Forged webhooks | Critical |
| GraphQL Depth | Deep queries | Medium |
| Large Responses | Memory exhaustion | Medium |
| Missing Auth | No API key | High |
| Insecure Caching | Cross‑user data leak | High |
| Event Type Validation | Unauthorised actions | High |
| Internal Error Exposure | Network topology leak | Medium |
| Deprecated APIs | Unpatched vulnerabilities | High |
| No Circuit Breaker | Cascading failures | High |

### **Pro Tips for Testing Unsafe Consumption of APIs**
1. **Identify all external API calls** – use network monitoring, code review, or proxy logs.
2. **Check for user‑controlled URLs** – test SSRF by pointing to internal services.
3. **Verify webhook signatures** – send unsigned requests and see if they are accepted.
4. **Inject malicious data** – if you can control the external API response, test XSS, SQLi, etc.
5. **Test timeouts and large responses** – cause the external API to hang or send huge payloads.
6. **Review logs** – look for sensitive data from external APIs.
7. **Check for idempotency** – replay webhook requests to see if duplicate actions occur.

---

*This guide is for professional security testing purposes only. Unauthorised testing is illegal.*
