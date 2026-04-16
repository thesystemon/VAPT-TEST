# 📦 **API9: IMPROPER INVENTORY MANAGEMENT TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into API Asset & Version Control Weaknesses*

---

## 📋 **TABLE OF CONTENTS**

1. [Exposed Deprecated API Endpoints (v1, old, test)](#1-exposed-deprecated-api-endpoints)
2. [API Versioning Differences (V1 vs V2 Authorization Gaps)](#2-api-versioning-differences)
3. [Unmanaged API Staging or Development Endpoints in Production](#3-unmanaged-api-staging-or-development-endpoints)
4. [API Documentation (Swagger, OpenAPI) Exposing Hidden Endpoints](#4-api-documentation-swagger-openapi-exposing-hidden-endpoints)
5. [API Endpoints Not Properly Decommissioned (Still Accessible)](#5-api-endpoints-not-properly-decommissioned)
6. [Internal APIs Exposed to External Clients (No Network Isolation)](#6-internal-apis-exposed-to-external-clients)
7. [Unsecured GraphQL Endpoint with Introspection Enabled in Production](#7-unsecured-graphql-endpoint-with-introspection-enabled)
8. [Exposed Administrative API Endpoints (`/admin`, `/manage`) Without Authentication](#8-exposed-administrative-api-endpoints)
9. [Outdated API Gateway or Reverse Proxy Configuration](#9-outdated-api-gateway-or-reverse-proxy-configuration)
10. [Unused or Orphaned API Keys Still Active](#10-unused-or-orphaned-api-keys-still-active)
11. [Non‑Production API Keys or Secrets Leaked in Client‑Side Code](#11-non-production-api-keys-or-secrets-leaked-in-client-side-code)
12. [Debug Endpoints (`/debug`, `/test`, `/cron`) Accessible in Production](#12-debug-endpoints-debug-test-cron-accessible-in-production)
13. [API Hosting on Non‑Standard Ports Without Security Controls](#13-api-hosting-on-non-standard-ports-without-security-controls)
14. [Incomplete Asset Inventory (Shadow APIs)](#14-incomplete-asset-inventory-shadow-apis)
15. [Outdated Third‑Party API Integrations (Unpatched SDKs)](#15-outdated-third-party-api-integrations-unpatched-sdks)
16. [Unmanaged Webhooks or Callback URLs (Old Endpoints Still Active)](#16-unmanaged-webhooks-or-callback-urls)
17. [API Subdomain Takeover (DNS Misconfiguration)](#17-api-subdomain-takeover-dns-misconfiguration)
18. [Insecure Cloud Storage for API Assets (Public Buckets)](#18-insecure-cloud-storage-for-api-assets-public-buckets)
19. [Lack of API Lifecycle Management (No Deprecation Policy)](#19-lack-of-api-lifecycle-management-no-deprecation-policy)
20. [Exposed Internal Service Endpoints via API Gateway Misconfiguration](#20-exposed-internal-service-endpoints-via-api-gateway-misconfiguration)
21. [Missing Rate Limiting on Legacy API Versions](#21-missing-rate-limiting-on-legacy-api-versions)
22. [Unprotected API Health or Metrics Endpoints (`/health`, `/metrics`)](#22-unprotected-api-health-or-metrics-endpoints)
23. [Old API Keys Not Rotated After Employee Departure](#23-old-api-keys-not-rotated-after-employee-departure)
24. [Exposed API Build or Deployment Information (`.git`, `Jenkinsfile`)](#24-exposed-api-build-or-deployment-information)
25. [Misconfigured API Gateway Routing (Wildcard Paths)](#25-misconfigured-api-gateway-routing-wildcard-paths)
26. [Insecure API Mock or Stub Endpoints Left in Production](#26-insecure-api-mock-or-stub-endpoints-left-in-production)
27. [Exposed API Analytics or Usage Dashboards Without Authentication](#27-exposed-api-analytics-or-usage-dashboards-without-authentication)
28. [Lack of API Version Deprecation Headers (`Deprecation`, `Sunset`)](#28-lack-of-api-version-deprecation-headers)
29. [Internal API Documentation Leaked via Search Engines (Google dork)](#29-internal-api-documentation-leaked-via-search-engines)
30. [Missing API Lifecycle Automation (Manual Decommissioning Only)](#30-missing-api-lifecycle-automation-manual-decommissioning-only)

---

## 1. EXPOSED DEPRECATED API ENDPOINTS (V1, OLD, TEST)

**Description**  
Deprecated API endpoints (e.g., `/api/v1/`, `/api/old/`, `/test/`) often lack the same security controls as current versions. Attackers can target them to exploit older, vulnerable code.

**What to Look For**
- API paths containing `v1`, `old`, `deprecated`, `legacy`, `test`, `dev`.
- Different behaviour or weaker authentication compared to newer versions.

**What to Ignore**
- Deprecated endpoints that have been properly removed or return `410 Gone`.

**How to Test with Burp Suite**
1. Identify current API version (e.g., `/api/v3/users`).
2. Try older versions: `/api/v1/users`, `/api/v2/users`, `/api/old/users`.
3. Compare responses for sensitive data or weaker access control.

**Example**
```http
GET /api/v1/admin/users HTTP/1.1
```
V1 endpoint returns all users without authentication, while V3 requires admin token.

**Tools**
- Burp Repeater
- API version wordlists
- Dirb/Gobuster

**Risk Rating**  
Critical

**Remediation**
- Remove deprecated endpoints from production.
- Return `410 Gone` for old versions.
- Implement consistent authentication across all versions.

---

## 2. API VERSIONING DIFFERENCES (V1 VS V2 AUTHORIZATION GAPS)

**Description**  
Newer API versions may have proper authorization, but older versions (still accessible) may lack checks, allowing attackers to bypass controls.

**What to Look For**
- Multiple API versions exposed (e.g., `/api/v1/`, `/api/v2/`, `/api/v3/`).
- Older version returns data without proper authentication.

**What to Ignore**
- Consistent authorization across all versions.

**How to Test with Burp Suite**
1. Call the same sensitive endpoint on different versions (e.g., `/v1/user/123`, `/v2/user/123`).
2. Use a low‑privilege token.
3. If the older version returns data, vulnerable.

**Example**
```http
GET /api/v1/user/124 HTTP/1.1
Authorization: Bearer USER_TOKEN
```
V1 returns user data; V2 returns `403`.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Apply the same authorization logic across all versions.
- Deprecate and remove vulnerable versions.

---

## 3. UNMANAGED API STAGING OR DEVELOPMENT ENDPOINTS IN PRODUCTION

**Description**  
Staging or development endpoints (e.g., `/staging/`, `/dev/`, `/qa/`) accidentally deployed to production may have weak authentication and expose sensitive data.

**What to Look For**
- Paths like `/staging`, `/dev`, `/qa`, `/test`, `/sandbox`, `/beta`.
- Endpoints that bypass normal authentication.

**What to Ignore**
- No such endpoints present.

**How to Test with Burp Suite**
1. Use forced browsing wordlist to discover staging paths.
2. Access them with a regular session or no token.
3. Check for data leakage.

**Example**
```http
GET /staging/api/users HTTP/1.1
```
Returns all users without authentication.

**Tools**
- Dirb/Gobuster
- Burp Intruder

**Risk Rating**  
Critical

**Remediation**
- Do not deploy staging endpoints to production.
- Use network isolation for non‑production environments.

---

## 4. API DOCUMENTATION (SWAGGER, OPENAPI) EXPOSING HIDDEN ENDPOINTS

**Description**  
Exposed OpenAPI/Swagger documentation may list internal or administrative endpoints not intended for public use, giving attackers a roadmap.

**What to Look For**
- Swagger UI or JSON at `/swagger`, `/api-docs`, `/openapi.json`.
- Endpoints listed that are not used by the public API (e.g., `/internal/`, `/admin/`).

**What to Ignore**
- Documentation that is authenticated or only lists public endpoints.

**How to Test with Burp Suite**
1. Access `/swagger/index.html`, `/api-docs`, `/v3/api-docs`.
2. Review the specification for hidden endpoints.
3. Try to call those endpoints with a regular user token.

**Example**
```json
"/internal/user/delete/{id}": {
  "post": { "summary": "Delete user (admin only)" }
}
```

**Tools**
- Burp Repeater
- Swagger UI

**Risk Rating**  
High

**Remediation**
- Protect API documentation with authentication.
- Remove internal endpoints from public documentation.

---

## 5. API ENDPOINTS NOT PROPERLY DECOMMISSIONED (STILL ACCESSIBLE)

**Description**  
Endpoints that were marked for removal may still be accessible because they were only hidden from UI, not removed from the server.

**What to Look For**
- Old endpoints that are no longer used by the frontend but still respond to requests.
- No `410 Gone` or redirect.

**What to Ignore**
- Endpoints that return `410 Gone` or `404 Not Found`.

**How to Test with Burp Suite**
1. Review old API documentation or mobile app binaries for deprecated endpoints.
2. Send requests to those endpoints.
3. If they return data or perform actions, they are not properly decommissioned.

**Example**
```http
POST /api/v1/order/cancel HTTP/1.1
```
Still works even though frontend uses `/api/v3/orders/cancel`.

**Tools**
- Burp Repeater
- Mobile app reverse engineering

**Risk Rating**  
High

**Remediation**
- Remove deprecated endpoints from code.
- Return `410 Gone` with a message.

---

## 6. INTERNAL APIS EXPOSED TO EXTERNAL CLIENTS (NO NETWORK ISOLATION)

**Description**  
APIs intended only for internal microservices are accidentally exposed to the internet without proper authentication.

**What to Look For**
- Endpoints with paths like `/internal/`, `/service/`, `/rpc/`, `/grpc/`.
- No authentication required.

**What to Ignore**
- Internal APIs protected by network ACLs or mTLS.

**How to Test with Burp Suite**
1. Use forced browsing to discover internal‑looking paths.
2. Access them from an external network.
3. If they return data, they are exposed.

**Example**
```http
GET /internal/metrics HTTP/1.1
```
Returns system metrics without authentication.

**Tools**
- Dirb/Gobuster
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Do not expose internal APIs to the internet.
- Use API gateways to filter traffic.
- Implement mutual TLS (mTLS) for service‑to‑service communication.

---

## 7. UNSECURED GRAPHQL ENDPOINT WITH INTROSPECTION ENABLED IN PRODUCTION

**Description**  
GraphQL endpoints with introspection enabled in production allow attackers to discover all queries, mutations, and types, including administrative functions.

**What to Look For**
- GraphQL endpoint (e.g., `/graphql`) accessible without authentication.
- Introspection query returns schema.

**What to Ignore**
- Introspection disabled or endpoint authenticated.

**How to Test with Burp Suite**
1. Send introspection query:
```graphql
query { __schema { types { name fields { name } } } }
```
2. If schema is returned, introspection is enabled.
3. Look for mutations like `deleteUser`, `makeAdmin`.

**Example**
```graphql
mutation { deleteUser(id: 123) }
```
If mutation works, admin function exposed.

**Tools**
- GraphQL Raider
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Disable introspection in production.
- Require authentication for GraphQL endpoints.

---

## 8. EXPOSED ADMINISTRATIVE API ENDPOINTS (`/ADMIN`, `/MANAGE`) WITHOUT AUTHENTICATION

**Description**  
Admin‑only API endpoints (e.g., `/api/admin`, `/manage`, `/system`) are often left unprotected, allowing regular users to perform privileged actions.

**What to Look For**
- Paths containing `admin`, `manage`, `system`, `control`, `operator`.
- No authentication or weak authentication.

**What to Ignore**
- Admin endpoints protected by strong authentication and IP whitelisting.

**How to Test with Burp Suite**
1. Use forced browsing to find admin paths.
2. Access them with a regular user token.
3. If the endpoint performs privileged actions, vulnerable.

**Example**
```http
GET /api/admin/users HTTP/1.1
Cookie: session=REGULAR_USER_SESSION
```
Returns user list.

**Tools**
- Dirb/Gobuster
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Protect admin endpoints with strong authentication (MFA) and role checks.

---

## 9. OUTDATED API GATEWAY OR REVERSE PROXY CONFIGURATION

**Description**  
Outdated API gateway or reverse proxy configurations may have security vulnerabilities (e.g., request smuggling, header injection) or route requests to wrong backends.

**What to Look For**
- Unusual behaviour when sending malformed requests.
- Response headers revealing old software versions (e.g., `Server: Apache/2.2.22`).

**What to Ignore**
- Up‑to‑date gateways.

**How to Test with Burp Suite**
1. Check version headers from the gateway.
2. Test for request smuggling using `Transfer-Encoding` and `Content-Length` conflicts.
3. Attempt to access backend endpoints via path traversal.

**Example**
```http
POST /admin HTTP/1.1
Host: target.com
Content-Length: 0
Transfer-Encoding: chunked

0
```

**Tools**
- Burp Repeater
- Request smuggling tools

**Risk Rating**  
High

**Remediation**
- Keep API gateway and reverse proxy updated.
- Harden configurations (disable unused methods, enforce timeouts).

---

## 10. UNUSED OR ORPHANED API KEYS STILL ACTIVE

**Description**  
API keys that are no longer used (e.g., for old integrations, former employees) may still be active, increasing the risk of unauthorised access.

**What to Look For**
- API keys in source code, documentation, or logs that are not referenced in current use.
- Keys with no rotation policy.

**What to Ignore**
- Keys regularly rotated and revoked when unused.

**How to Test with Burp Suite**
1. Identify API keys from old documentation or client code.
2. Attempt to use them with current API endpoints.
3. If they work, they are still active.

**Example**
```http
GET /api/data?api_key=OLD_KEY_123 HTTP/1.1
```
Returns valid data.

**Tools**
- Burp Repeater
- Code search

**Risk Rating**  
High

**Remediation**
- Implement key rotation and revocation policies.
- Regularly audit and remove unused keys.

---

## 11. NON‑PRODUCTION API KEYS OR SECRETS LEAKED IN CLIENT‑SIDE CODE

**Description**  
Development, staging, or test API keys embedded in client‑side code (JavaScript, mobile apps) can be used to access production‑like environments.

**What to Look For**
- Keys with words like `test`, `dev`, `staging`, `sandbox` in client‑side code.
- Keys that work on production endpoints.

**What to Ignore**
- Keys that are invalid in production.

**How to Test with Burp Suite**
1. Search page source and JS files for `api_key`, `secret`, `token`.
2. Test those keys against production API endpoints.

**Example**
```javascript
const API_KEY = "test_sk_abc123";
```
Test on production endpoint: `GET /api/data?api_key=test_sk_abc123`.

**Tools**
- Browser DevTools
- Burp search

**Risk Rating**  
High

**Remediation**
- Do not embed any keys in client‑side code.
- Use backend proxies to forward requests.

---

## 12. DEBUG ENDPOINTS (`/DEBUG`, `/TEST`, `/CRON`) ACCESSIBLE IN PRODUCTION

**Description**  
Debug endpoints (`/debug`, `/test`, `/cron`, `/flush`, `/clear-cache`) left in production can be used to trigger expensive operations or leak information.

**What to Look For**
- Paths like `/debug`, `/test`, `/cron`, `/phpinfo`, `/health`.
- No authentication.

**What to Ignore**
- Debug endpoints removed or protected.

**How to Test with Burp Suite**
1. Use forced browsing to find debug paths.
2. Access them and observe behaviour.

**Example**
```http
POST /debug/flush-cache HTTP/1.1
```
Cache is cleared without authentication.

**Tools**
- Dirb/Gobuster
- Burp Intruder

**Risk Rating**  
High

**Remediation**
- Remove debug endpoints from production.
- If necessary, protect them with authentication and IP whitelisting.

---

## 13. API HOSTING ON NON‑STANDARD PORTS WITHOUT SECURITY CONTROLS

**Description**  
APIs hosted on non‑standard ports (e.g., 8080, 8443, 3000) may bypass security monitoring and firewall rules.

**What to Look For**
- API accessible on ports other than 80/443.
- No additional security controls on those ports.

**What to Ignore**
- Non‑standard ports with same security controls as standard ports.

**How to Test with Burp Suite**
1. Use Nmap to scan for open ports.
2. Attempt to access the API on discovered ports.
3. Check if authentication is required.

**Example**
```http
GET http://api.target.com:8080/users HTTP/1.1
```
Returns data without authentication.

**Tools**
- Nmap
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Use standard ports (443) for all public APIs.
- Apply consistent security controls across all ports.

---

## 14. INCOMPLETE ASSET INVENTORY (SHADOW APIS)

**Description**  
Organisations often lack a complete inventory of all APIs, leading to “shadow APIs” that are unmanaged, unmonitored, and potentially insecure.

**What to Look For**
- API endpoints not documented or known by security team.
- Endpoints discovered via forced browsing that are not linked from any frontend.

**What to Ignore**
- Documented and managed APIs.

**How to Test with Burp Suite**
1. Use aggressive forced browsing (e.g., SecLists API paths).
2. Identify any endpoints that return data but are not part of known documentation.
3. Test them for vulnerabilities.

**Example**
```http
GET /api/v1/analytics/unreleased HTTP/1.1
```
Returns data but no documentation exists.

**Tools**
- Burp Suite (spider + forced browsing)
- FFUF
- Amass

**Risk Rating**  
High

**Remediation**
- Maintain an up‑to‑date API inventory.
- Use API discovery tools to detect shadow APIs.

---

## 15. OUTDATED THIRD‑PARTY API INTEGRATIONS (UNPATCHED SDKS)

**Description**  
APIs that integrate with third‑party services (payment gateways, social login) using outdated SDKs may contain known vulnerabilities.

**What to Look For**
- Version numbers of third‑party SDKs in client‑side code or headers.
- Known CVEs for those SDK versions.

**What to Ignore**
- Up‑to‑date SDKs.

**How to Test with Burp Suite**
1. Identify SDK versions from network traffic (e.g., `Stripe.js` version).
2. Check vulnerability databases for that version.
3. Attempt to exploit known issues (e.g., OAuth redirect_uri bypass).

**Example**
```html
<script src="https://js.stripe.com/v2/"></script>
```
Stripe v2 is deprecated and has known issues.

**Tools**
- Burp Proxy
- Wappalyzer

**Risk Rating**  
High

**Remediation**
- Update all third‑party SDKs to the latest versions.
- Subscribe to security bulletins.

---

## 16. UNMANAGED WEBHOOKS OR CALLBACK URLS (OLD ENDPOINTS STILL ACTIVE)

**Description**  
Webhook or callback URLs that are no longer used may still be active, allowing attackers to trigger them for SSRF or information disclosure.

**What to Look For**
- Webhook registration endpoints that accept URLs.
- Old callback URLs still responding.

**What to Ignore**
- Webhooks that are validated and cleaned up.

**How to Test with Burp Suite**
1. Identify webhook endpoints from documentation or configuration.
2. Attempt to send requests to those URLs.
3. Check if they are still processed.

**Example**
```http
POST /webhook/legacy-payment HTTP/1.1
```
Old webhook still triggers payment updates.

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Remove unused webhook endpoints.
- Implement webhook URL validation and rotation.

---

## 17. API SUBDOMAIN TAKEOVER (DNS MISCONFIGURATION)

**Description**  
API subdomains (e.g., `api-staging.target.com`) that point to cloud services (AWS, Azure, GitHub) may be vulnerable to takeover if the cloud resource is deleted but the DNS record remains.

**What to Look For**
- DNS `CNAME` records pointing to cloud services.
- The target cloud resource returns `404` or does not exist.

**What to Ignore**
- Subdomains with valid, active resources.

**How to Test with Burp Suite**
1. Enumerate subdomains (e.g., `api-staging.target.com`).
2. Check if the CNAME points to a cloud service (e.g., `*.cloudfront.net`, `*.azurewebsites.net`).
3. Visit the subdomain; if it returns a `404` or `NoSuchBucket`, it may be takable.

**Example**
```bash
dig api-staging.target.com
```
Returns `CNAME old-bucket.s3.amazonaws.com`. The bucket no longer exists.

**Tools**
- Dig
- Subdomain enumeration tools
- subjack

**Risk Rating**  
Critical

**Remediation**
- Remove DNS records for deleted resources.
- Monitor for dangling DNS entries.

---

## 18. INSECURE CLOUD STORAGE FOR API ASSETS (PUBLIC BUCKETS)

**Description**  
API configuration files, schemas, or logs stored in public cloud buckets (S3, Azure Blob) can be accessed by attackers.

**What to Look For**
- Publicly accessible S3 buckets containing API documentation, configs, or backups.
- Bucket listing enabled.

**What to Ignore**
- Private buckets with proper IAM policies.

**How to Test with Burp Suite**
1. Guess bucket names based on company name and common patterns.
2. Attempt to list bucket contents: `https://company-api-configs.s3.amazonaws.com/`.
3. If listing is enabled, download files.

**Example**
```http
GET https://target-api-docs.s3.amazonaws.com/swagger.json
```
Returns OpenAPI spec.

**Tools**
- AWS CLI
- S3Scanner
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Restrict bucket permissions to private.
- Use signed URLs for temporary access.

---

## 19. LACK OF API LIFECYCLE MANAGEMENT (NO DEPRECATION POLICY)

**Description**  
Without a formal API deprecation policy, old endpoints may remain active indefinitely, accumulating security debt.

**What to Look For**
- No `Deprecation` or `Sunset` headers in API responses.
- Old API versions still supported without notice.

**What to Ignore**
- Clear deprecation policy with sunset dates.

**How to Test with Burp Suite**
1. Check responses for `Deprecation: true` or `Sunset: date` headers.
2. If no headers and old versions exist, lifecycle management may be missing.

**Example**
```http
HTTP/1.1 200 OK
```
No deprecation headers for a deprecated endpoint.

**Tools**
- Burp Proxy

**Risk Rating**  
Medium

**Remediation**
- Implement `Deprecation` and `Sunset` headers.
- Establish a deprecation policy (e.g., 6 months notice, then removal).

---

## 20. EXPOSED INTERNAL SERVICE ENDPOINTS VIA API GATEWAY MISCONFIGURATION

**Description**  
API gateways may inadvertently expose internal service endpoints (e.g., `/internal/prometheus`, `/actuator`) to the public.

**What to Look For**
- Gateway routes that map internal paths to public endpoints.
- No authentication on those routes.

**What to Ignore**
- Properly secured gateway routes.

**How to Test with Burp Suite**
1. Review gateway configuration if accessible.
2. Fuzz for common internal paths: `/actuator`, `/metrics`, `/env`, `/health`.
3. Access them externally.

**Example**
```http
GET /actuator/health HTTP/1.1
```
Returns health status without authentication.

**Tools**
- Dirb/Gobuster
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Restrict internal service endpoints to internal networks.
- Use API gateway filters to block external access.

---

## 21. MISSING RATE LIMITING ON LEGACY API VERSIONS

**Description**  
Legacy API versions may lack rate limiting, making them ideal targets for brute force and DoS attacks.

**What to Look For**
- Older API versions that accept many requests without `429`.
- Newer versions have rate limiting, older do not.

**What to Ignore**
- Consistent rate limiting across all versions.

**How to Test with Burp Suite**
1. Send 100 requests to a legacy endpoint.
2. Observe if any are rate‑limited.

**Example**
```http
GET /api/v1/login HTTP/1.1
```
100 requests, all return `200`.

**Tools**
- Burp Intruder

**Risk Rating**  
High

**Remediation**
- Apply rate limiting to all API versions.
- Deprecate and remove unmaintained versions.

---

## 22. UNPROTECTED API HEALTH OR METRICS ENDPOINTS (`/HEALTH`, `/METRICS`)

**Description**  
Health and metrics endpoints often expose internal system information (memory usage, database status, uptime) and should be protected.

**What to Look For**
- Endpoints like `/health`, `/metrics`, `/prometheus`, `/actuator/health`.
- No authentication.

**What to Ignore**
- Protected endpoints (basic auth, IP whitelist).

**How to Test with Burp Suite**
1. Access common health/metrics paths.
2. If data is returned, they are unprotected.

**Example**
```http
GET /actuator/health HTTP/1.1
```
Returns `{"status":"UP"}`.

**Tools**
- Dirb/Gobuster
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Protect health/metrics endpoints with authentication.
- Restrict access to internal monitoring systems.

---

## 23. OLD API KEYS NOT ROTATED AFTER EMPLOYEE DEPARTURE

**Description**  
API keys associated with former employees may still be active, allowing them to access the API even after leaving.

**What to Look For**
- API keys tied to individuals without rotation policy.
- Keys still working after employee departure (requires internal knowledge).

**What to Ignore**
- Keys revoked upon departure.

**How to Test with Burp Suite**
- This is more of a process review. Test by using a known old key (if available) or verifying with the organisation.

**Tools**
- Policy review
- Access logs analysis

**Risk Rating**  
High

**Remediation**
- Revoke API keys immediately upon employee departure.
- Implement key rotation policies.

---

## 24. EXPOSED API BUILD OR DEPLOYMENT INFORMATION (`.GIT`, `JENKINSFILE`)

**Description**  
Exposed `.git` directories, Jenkinsfiles, or deployment scripts can leak source code, credentials, and internal paths.

**What to Look For**
- Accessible `/.git/config`, `/.git/HEAD`.
- `Jenkinsfile`, `Dockerfile`, `deploy.yml` exposed.

**What to Ignore**
- No such files exposed.

**How to Test with Burp Suite**
1. Request `/.git/config`, `/jenkinsfile`, `/deploy.yaml`.
2. If served, source code or credentials may be exposed.

**Example**
```http
GET /.git/config HTTP/1.1
```
Returns `[core] repositoryformatversion = 0 ...`

**Tools**
- Dirb/Gobuster
- GitTools

**Risk Rating**  
Critical

**Remediation**
- Remove `.git` and build files from production.
- Use `.htaccess` or web server rules to block access.

---

## 25. MISCONFIGURED API GATEWAY ROUTING (WILDCARD PATHS)

**Description**  
API gateway routes with wildcards (e.g., `/api/*`, `/v1/*`) may inadvertently expose internal or admin endpoints if not properly scoped.

**What to Look For**
- Gateway configuration that matches more paths than intended.
- Ability to access `/api/admin` via a wildcard route.

**What to Ignore**
- Explicit route definitions with proper scoping.

**How to Test with Burp Suite**
1. Try to access paths that should not be public (e.g., `/api/internal/secret`).
2. If the gateway forwards the request, misconfigured.

**Example**
```http
GET /api/internal/db_dump HTTP/1.1
```
Returns data.

**Tools**
- Burp Repeater
- Path fuzzing

**Risk Rating**  
Critical

**Remediation**
- Use explicit route definitions.
- Implement deny‑by‑default policies.

---

## 26. INSECURE API MOCK OR STUB ENDPOINTS LEFT IN PRODUCTION

**Description**  
Mock or stub endpoints used during development may still be active in production, returning fake data or executing dangerous actions.

**What to Look For**
- Paths like `/mock/`, `/stub/`, `/fake/`, `/demo/`.
- Endpoints that return placeholder data or bypass business logic.

**What to Ignore**
- Mock endpoints removed before production.

**How to Test with Burp Suite**
1. Look for development‑sounding paths.
2. Access them and see if they respond.

**Example**
```http
GET /mock/payment/approve?amount=0 HTTP/1.1
```
Approves payment without processing.

**Tools**
- Dirb/Gobuster
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Remove mock endpoints from production.
- Use environment‑specific configuration.

---

## 27. EXPOSED API ANALYTICS OR USAGE DASHBOARDS WITHOUT AUTHENTICATION

**Description**  
API analytics dashboards (e.g., Grafana, Kibana, custom dashboards) exposed to the internet can leak usage patterns, error logs, and sensitive data.

**What to Look For**
- Paths like `/grafana`, `/kibana`, `/dashboard`, `/api/analytics`.
- No authentication.

**What to Ignore**
- Dashboards protected by authentication and IP whitelisting.

**How to Test with Burp Suite**
1. Access common dashboard paths.
2. If they load, sensitive data may be exposed.

**Example**
```http
GET /grafana/d/123/api-usage HTTP/1.1
```
Shows API call volumes and error rates.

**Tools**
- Dirb/Gobuster
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Protect dashboards with authentication.
- Restrict access to internal networks.

---

## 28. LACK OF API VERSION DEPRECATION HEADERS (`DEPRECATION`, `SUNSET`)

**Description**  
API responses should include `Deprecation: true` and `Sunset: date` headers for deprecated versions. Their absence leaves clients unaware and the API unmanaged.

**What to Look For**
- Deprecated endpoints without `Deprecation` or `Sunset` headers.
- No documentation of sunset dates.

**What to Ignore**
- Headers present for deprecated versions.

**How to Test with Burp Suite**
1. Access an endpoint known to be deprecated.
2. Check response headers for `Deprecation`, `Sunset`.

**Example**
```http
HTTP/1.1 200 OK
```
No deprecation headers.

**Tools**
- Burp Proxy

**Risk Rating**  
Low

**Remediation**
- Add `Deprecation: true` and `Sunset: <date>` headers.
- Provide migration guides.

---

## 29. INTERNAL API DOCUMENTATION LEAKED VIA SEARCH ENGINES (GOOGLE DORK)

**Description**  
Internal API documentation indexed by search engines can expose sensitive endpoints to external attackers.

**What to Look For**
- Internal docs with phrases like `internal use only`, `do not share`.
- URLs containing `swagger`, `api-docs`, `redoc` that are not protected.

**What to Ignore**
- Properly protected documentation.

**How to Test with Burp Suite**
1. Use Google dorks: `site:target.com "swagger"`, `site:target.com "internal API"`.
2. Access discovered URLs.

**Example**
```http
GET https://target.com/internal/swagger.json HTTP/1.1
```
Returns internal API spec.

**Tools**
- Google search
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Block search engine indexing via `robots.txt` or authentication.
- Use `X-Robots-Tag: noindex`.

---

## 30. MISSING API LIFECYCLE AUTOMATION (MANUAL DECOMMISSIONING ONLY)

**Description**  
Manual decommissioning processes often fail, leaving old API versions active. Automation is needed to enforce deprecation and removal.

**What to Look For**
- No automated process to sunset old versions.
- Deprecated endpoints still responding after announced sunset date.

**What to Ignore**
- Automated deprecation with sunset dates enforced.

**How to Test with Burp Suite**
1. Check if endpoints announced as deprecated are still active.
2. If they work beyond the sunset date, automation is missing.

**Example**
- API v1 deprecated in 2022, but still returns `200 OK`.

**Tools**
- Burp Repeater
- Policy review

**Risk Rating**  
Medium

**Remediation**
- Implement automated sunset enforcement (e.g., return `410` after date).
- Use API gateways to block requests to deprecated versions.

---

## ✅ **SUMMARY**

Improper Inventory Management (API9) refers to the lack of control over API versions, endpoints, assets, and lifecycle. It leads to exposed deprecated endpoints, shadow APIs, versioning gaps, and insecure legacy code. This guide provides 30 testing vectors.

### **Key Testing Areas Summary**

| Failure Type | Key Indicators | Risk |
|--------------|----------------|------|
| Exposed Deprecated Endpoints | `/v1`, `/old` accessible | Critical |
| Versioning Differences | V1 weaker than V2 | Critical |
| Staging Endpoints | `/staging`, `/dev` in production | Critical |
| Exposed API Docs | Swagger without auth | High |
| Not Decommissioned | No `410 Gone` | High |
| Internal APIs Exposed | `/internal` accessible | Critical |
| GraphQL Introspection | Schema queries allowed | Critical |
| Admin Endpoints | `/admin` without auth | Critical |
| Outdated Gateway | Old version headers | High |
| Unused API Keys | Keys still active | High |
| Non‑Prod Keys in Client | Test keys in JS | High |
| Debug Endpoints | `/debug`, `/test` accessible | High |
| Non‑Standard Ports | Port 8080 without auth | High |
| Shadow APIs | Undocumented endpoints | High |
| Outdated SDKs | Old third‑party versions | High |
| Unmanaged Webhooks | Old callbacks active | Medium |
| Subdomain Takeover | Dangling DNS | Critical |
| Public Cloud Buckets | S3 listing | Critical |
| No Deprecation Policy | No sunset headers | Medium |
| Gateway Misrouting | Wildcard routes | Critical |
| Legacy Rate Limiting | Old versions unlimited | High |
| Unprotected Health | `/health` open | Medium |
| Old API Keys | Not rotated | High |
| Exposed Build Files | `.git`, `Jenkinsfile` | Critical |
| Wildcard Routes | Gateway misconfig | Critical |
| Mock Endpoints | `/stub` in production | High |
| Exposed Dashboards | Grafana, Kibana | High |
| Missing Deprecation Headers | No `Sunset` | Low |
| Leaked Internal Docs | Google indexed | High |
| Manual Lifecycle Only | No sunset enforcement | Medium |

### **Pro Tips for Testing Improper Inventory Management**
1. **Enumerate versions** – use wordlists to discover `/v1`, `/v2`, `/old`, `/deprecated`.
2. **Check for staging/dev endpoints** – `/staging`, `/dev`, `/qa`, `/test`.
3. **Review API documentation** – look for Swagger/OpenAPI files.
4. **Test for subdomain takeover** – check CNAME records pointing to cloud services.
5. **Inspect client‑side code** – for old API keys, test endpoints.
6. **Use forced browsing** – SecLists has comprehensive API path wordlists.
7. **Monitor deprecation headers** – if missing, lifecycle management is weak.

---

*This guide is for professional security testing purposes only. Unauthorised testing is illegal.*
