# 🌐 **API7: SERVER-SIDE REQUEST FORGERY (SSRF) TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Forced Server-Side Requests via APIs*

---

## 📋 **TABLE OF CONTENTS**

1. [SSRF via URL Parameters in API Calls (Fetching External Resources)](#1-ssrf-via-url-parameters-in-api-calls)
2. [SSRF via File Upload or Import from URL](#2-ssrf-via-file-upload-or-import-from-url)
3. [SSRF via Image URL Loading (Avatar, Profile Picture)](#3-ssrf-via-image-url-loading-avatar-profile-picture)
4. [SSRF via Webhook or Callback URL Configuration](#4-ssrf-via-webhook-or-callback-url-configuration)
5. [SSRF via PDF or Document Generation from User-Controlled URLs](#5-ssrf-via-pdf-or-document-generation-from-user-controlled-urls)
6. [SSRF via XML External Entity (XXE) Injection](#6-ssrf-via-xml-external-entity-xxe-injection)
7. [SSRF via Open Graph / Link Preview APIs](#7-ssrf-via-open-graph--link-preview-apis)
8. [SSRF via Gopher Protocol (Redis, Memcached, MySQL)](#8-ssrf-via-gopher-protocol-redis-memcached-mysql)
9. [SSRF via Dict / File / SFTP Protocols](#9-ssrf-via-dict--file--sftp-protocols)
10. [SSRF via Blind Out‑of‑Band (DNS/HTTP) Detection](#10-ssrf-via-blind-out-of-band-dnshttp-detection)
11. [SSRF to Cloud Metadata APIs (169.254.169.254)](#11-ssrf-to-cloud-metadata-apis)
12. [SSRF to Internal Network Scanning (Port Scanning via HTTP)](#12-ssrf-to-internal-network-scanning-port-scanning-via-http)
13. [SSRF to Localhost Services (127.0.0.1, ::1, 0.0.0.0)](#13-ssrf-to-localhost-services)
14. [SSRF via IPv6 or Alternative IP Representations (Bypassing Filters)](#14-ssrf-via-ipv6-or-alternative-ip-representations)
15. [SSRF via URL Encoding and Double Encoding](#15-ssrf-via-url-encoding-and-double-encoding)
16. [SSRF via DNS Rebinding Attacks](#16-ssrf-via-dns-rebinding-attacks)
17. [SSRF via Redirect Following (302 to Internal IP)](#17-ssrf-via-redirect-following-302-to-internal-ip)
18. [SSRF via Partially Controlled URLs (Path Injection)](#18-ssrf-via-partially-controlled-urls-path-injection)
19. [SSRF via Template Injection or SSTI (URL Context)](#19-ssrf-via-template-injection-or-ssti-url-context)
20. [SSRF via API Proxying (Internal API Forwarding)](#20-ssrf-via-api-proxying-internal-api-forwarding)
21. [SSRF via WebSocket Messages](#21-ssrf-via-websocket-messages)
22. [SSRF via HTTP Header Injection (Host, X-Forwarded-Host)](#22-ssrf-via-http-header-injection-host-x-forwarded-host)
23. [SSRF via Server‑Side JavaScript (Node.js `fetch`, `axios`)](#23-ssrf-via-server-side-javascript-nodejs-fetch-axios)
24. [SSRF via Image Processing Libraries (ImageMagick, GD)](#24-ssrf-via-image-processing-libraries-imagemagick-gd)
25. [SSRF via PDF Export (External Fonts, Images)](#25-ssrf-via-pdf-export-external-fonts-images)
26. [SSRF via RSS Feed Import or Aggregator](#26-ssrf-via-rss-feed-import-or-aggregator)
27. [SSRF via Third‑Party API Integrations (Inbound Webhooks)](#27-ssrf-via-third-party-api-integrations-inbound-webhooks)
28. [SSRF via GraphQL Batch or Introspection Requests](#28-ssrf-via-graphql-batch-or-introspection-requests)
29. [SSRF via Server‑less Function Invocations (AWS Lambda, Azure Functions)](#29-ssrf-via-server-less-function-invocations)
30. [SSRF via Misconfigured `X-Original-URL` or `X-Rewrite-URL` Headers](#30-ssrf-via-misconfigured-x-original-url-or-x-rewrite-url-headers)

---

## 1. SSRF VIA URL PARAMETERS IN API CALLS

**Description**  
APIs that accept a user‑supplied URL and fetch it server‑side are vulnerable to SSRF. Attackers can change the URL to point to internal resources, metadata endpoints, or localhost.

**What to Look For**
- API parameters like `url=`, `dest=`, `fetch=`, `load=`, `src=`, `source=`, `path=`, `uri=`.
- Endpoints that proxy or download content from a URL.

**What to Ignore**
- URLs validated against a strict allowlist of domains, with no redirection to internal IPs.

**How to Test with Burp Suite**
1. Identify parameters that take a URL.
2. Replace the URL with `http://127.0.0.1:80/admin` or `http://169.254.169.254/latest/meta-data/`.
3. Observe the response for internal content.
4. Use Burp Collaborator for blind detection.

**Example**
```http
POST /api/fetch HTTP/1.1
{"url": "http://169.254.169.254/latest/meta-data/"}
```

**Tools**
- Burp Repeater
- Burp Collaborator

**Risk Rating**  
Critical

**Remediation**
- Whitelist allowed domains or URL patterns.
- Do not follow redirects to internal addresses.
- Use an outbound proxy to filter internal IP ranges.

---

## 2. SSRF VIA FILE UPLOAD OR IMPORT FROM URL

**Description**  
File upload features that support “import from URL” can be abused to fetch internal files or metadata.

**What to Look For**
- Upload endpoints with parameters like `source_url`, `remote_file`, `import_from`.
- Features that say “Import from URL”.

**What to Ignore**
- File uploads that only accept local files.

**How to Test with Burp Suite**
1. Find an upload endpoint that accepts a URL.
2. Provide a URL to an internal service, e.g., `http://localhost/secret`.
3. Check if the response or subsequent behaviour reveals internal data.

**Example**
```http
POST /api/upload-from-url HTTP/1.1
{"url": "http://169.254.169.254/latest/meta-data/"}
```

**Tools**
- Burp Repeater
- Collaborator

**Risk Rating**  
Critical

**Remediation**
- Avoid URL import functionality.
- Validate and whitelist domains.

---

## 3. SSRF VIA IMAGE URL LOADING (AVATAR, PROFILE PICTURE)

**Description**  
APIs that set a user’s avatar by fetching an image from a URL can be abused to probe internal services.

**What to Look For**
- Profile or avatar endpoints with `avatar_url`, `photo_url`, `image_url` parameters.

**What to Ignore**
- Images downloaded and re‑hosted with validation.

**How to Test with Burp Suite**
1. Set avatar URL to `http://169.254.169.254/latest/meta-data/`.
2. Observe if the server fetches the metadata (check logs or Collaborator).

**Example**
```http
PATCH /api/user/profile HTTP/1.1
{"avatar_url": "http://localhost:8080/admin"}
```

**Tools**
- Burp Repeater
- Collaborator

**Risk Rating**  
High

**Remediation**
- Download the image to the server and serve locally.
- Validate URL against a whitelist.

---

## 4. SSRF VIA WEBHOOK OR CALLBACK URL CONFIGURATION

**Description**  
APIs that allow users to configure webhook URLs will send HTTP requests to those URLs. Attackers can set the webhook to an internal address.

**What to Look For**
- Settings endpoints with `webhook_url`, `callback_url`, `notification_url` parameters.
- Event subscriptions.

**What to Ignore**
- Webhook URLs validated against a whitelist.

**How to Test with Burp Suite**
1. Set a webhook URL to `http://169.254.169.254/latest/meta-data/`.
2. Trigger an event that invokes the webhook.
3. Monitor for out‑of‑bound requests (Collaborator) or internal response.

**Example**
```http
POST /api/settings/webhook HTTP/1.1
{"webhook_url": "http://127.0.0.1:8080/admin"}
```

**Tools**
- Burp Collaborator

**Risk Rating**  
Critical

**Remediation**
- Validate webhook URLs against an allowlist.
- Do not allow internal IPs or localhost.

---

## 5. SSRF VIA PDF OR DOCUMENT GENERATION FROM USER-CONTROLLED URLS

**Description**  
APIs that generate PDFs from user‑supplied HTML or URLs (e.g., wkhtmltopdf, Puppeteer) may fetch external resources, enabling SSRF.

**What to Look For**
- Endpoints like `/api/pdf?url=...` or `/api/export?html=...`.
- PDF generation libraries known to make network requests.

**What to Ignore**
- PDF generation with external resource fetching disabled.

**How to Test with Burp Suite**
1. Provide a URL pointing to an internal service (e.g., `http://169.254.169.254/`).
2. Generate the PDF and check if the internal content appears.

**Example**
```http
GET /api/pdf?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Disable external resource fetching in PDF generators.
- Run PDF generation in a sandboxed environment.

---

## 6. SSRF VIA XML EXTERNAL ENTITY (XXE) INJECTION

**Description**  
APIs that accept XML input (e.g., SOAP, RSS) may be vulnerable to XXE, which can be used to make server‑side HTTP requests.

**What to Look For**
- `Content-Type: application/xml` endpoints.
- XML payloads in request bodies.

**What to Ignore**
- XML parsers with external entity processing disabled.

**How to Test with Burp Suite**
1. Inject an XXE payload that defines an external entity pointing to an internal URL.
2. Check response for error or content.

**Example**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

**Tools**
- Burp Repeater
- XXE testing payloads

**Risk Rating**  
Critical

**Remediation**
- Disable external entity processing.
- Use secure XML parser configurations.

---

## 7. SSRF VIA OPEN GRAPH / LINK PREVIEW APIS

**Description**  
APIs that generate link previews (Open Graph, oEmbed) fetch the target page’s metadata, allowing SSRF.

**What to Look For**
- Endpoints like `/api/preview?url=...`, `/api/oembed?url=...`.
- Chat or comment APIs that generate previews.

**What to Ignore**
- Preview APIs that only fetch from trusted domains.

**How to Test with Burp Suite**
1. Call the preview API with a URL pointing to an internal service.
2. Check if the response contains metadata from the internal service.

**Example**
```http
GET /api/preview?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Whitelist allowed domains for link previews.
- Use a proxy that blocks internal IPs.

---

## 8. SSRF VIA GOPHER PROTOCOL (REDIS, MEMCACHED, MYSQL)

**Description**  
If the API supports the `gopher://` protocol, attackers can interact with internal TCP services (Redis, Memcached, MySQL) and execute arbitrary commands.

**What to Look For**
- URL parameters that accept `gopher://` schemes.
- Support for other protocols like `dict://`, `ftp://`.

**What to Ignore**
- Protocol whitelist (only HTTP/HTTPS).

**How to Test with Burp Suite**
1. Inject `gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0ainfo%0d%0a` (Redis command).
2. Observe if the response contains Redis info.

**Example**
```http
POST /api/fetch
{"url": "gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0ainfo%0d%0a"}
```

**Tools**
- Burp Repeater
- Gopher payload generators

**Risk Rating**  
Critical

**Remediation**
- Restrict URL schemes to HTTP/HTTPS only.
- Validate and sanitise the protocol.

---

## 9. SSRF VIA DICT / FILE / SFTP PROTOCOLS

**Description**  
Other protocols like `dict://`, `file://`, `sftp://` can be used to read local files or interact with internal services.

**What to Look For**
- URL parameters accepting schemes other than HTTP/HTTPS.
- Error messages revealing that the server tried to access a file.

**What to Ignore**
- Protocol whitelist (only HTTP/HTTPS).

**How to Test with Burp Suite**
1. Try `file:///etc/passwd` in a URL parameter.
2. Try `dict://127.0.0.1:11211/stat` for Memcached.

**Example**
```http
GET /api/load?url=file:///etc/passwd HTTP/1.1
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Whitelist allowed protocols.
- Reject requests with unsupported schemes.

---

## 10. SSRF VIA BLIND OUT‑OF‑BAND (DNS/HTTP) DETECTION

**Description**  
Blind SSRF occurs when the application makes a request but does not return the content. Attackers can use DNS or HTTP interactions to confirm the vulnerability.

**What to Look For**
- Any feature that might fetch a URL but no output is visible.
- Parameters where you can inject a URL.

**What to Ignore**
- Features that validate the URL before making the request.

**How to Test with Burp Suite**
1. Use Burp Collaborator to generate a unique domain.
2. Inject `http://collaborator.burp/` into the URL parameter.
3. Check Collaborator for any DNS or HTTP interaction.

**Example**
```http
POST /api/import
{"source": "http://collaborator.burp/"}
```

**Tools**
- Burp Collaborator
- Interactsh

**Risk Rating**  
High

**Remediation**
- Same as regular SSRF (whitelist, validation, network restrictions).

---

## 11. SSRF TO CLOUD METADATA APIS (169.254.169.254)

**Description**  
Cloud metadata endpoints (AWS, GCP, Azure, etc.) expose IAM credentials and configuration. SSRF can retrieve these and lead to cloud account compromise.

**What to Look For**
- Any SSRF vector that can reach link‑local addresses.
- Cloud environment (check `Server` header or known cloud IP ranges).

**What to Ignore**
- Applications that block `169.254.169.254` or use IMDSv2 with token protection.

**How to Test with Burp Suite**
1. Try `http://169.254.169.254/latest/meta-data/`.
2. For IMDSv2, you may need to set `X-aws-ec2-metadata-token` header (harder). Test different versions.

**Example**
```http
GET /api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
```

**Tools**
- Burp Repeater
- Cloud metadata enumeration scripts

**Risk Rating**  
Critical

**Remediation**
- Block access to `169.254.169.254` at network level.
- Use IMDSv2 with token requirement.
- Apply strict egress filtering.

---

## 12. SSRF TO INTERNAL NETWORK SCANNING (PORT SCANNING VIA HTTP)

**Description**  
Attackers can use SSRF to scan internal networks for open ports by observing response times or error messages.

**What to Look For**
- SSRF that returns different responses for open vs closed ports.
- Time‑based differences or connection errors.

**What to Ignore**
- Uniform error messages and timeouts.

**How to Test with Burp Suite**
1. Use Intruder to try different ports on an internal IP (e.g., `http://10.0.0.1:PORT`).
2. Compare response status codes, lengths, or times.
3. If a port is open, the response may be different (e.g., 200 vs 500).

**Example**
```http
GET /api/proxy?url=http://10.0.0.1:22 HTTP/1.1
```

**Tools**
- Burp Intruder
- Turbo Intruder

**Risk Rating**  
High

**Remediation**
- Block all internal IP ranges from being accessed.
- Use a single outbound proxy with allowlist.

---

## 13. SSRF TO LOCALHOST SERVICES (127.0.0.1, ::1, 0.0.0.0)

**Description**  
Attackers can target services running on the same server (localhost) such as debug interfaces, databases, or other applications.

**What to Look For**
- Use of `127.0.0.1`, `localhost`, `0.0.0.0`, `[::1]` in URL parameters.
- Common local services: 80, 443, 8080, 3000, 5000, 8000, 9000, 6379 (Redis), 11211 (Memcached).

**What to Ignore**
- Blocked localhost access.

**How to Test with Burp Suite**
1. Try `http://127.0.0.1:80/`, `http://localhost:8080/`.
2. Use Intruder to test common ports.

**Example**
```http
GET /api/fetch?url=http://127.0.0.1:6379/INFO HTTP/1.1
```

**Tools**
- Burp Intruder
- Port wordlist

**Risk Rating**  
Critical

**Remediation**
- Block localhost and loopback addresses.
- Ensure local services are not listening on network interfaces.

---

## 14. SSRF VIA IPV6 OR ALTERNATIVE IP REPRESENTATIONS

**Description**  
Attackers may bypass IP filters by using IPv6 addresses or alternative representations (decimal, octal, hexadecimal).

**What to Look For**
- IPv6 loopback: `[::1]`, `[::]`.
- Decimal representation: `2130706433` for `127.0.0.1`.
- Octal: `0177.0.0.1`.
- Hexadecimal: `0x7f000001`.

**What to Ignore**
- Proper normalisation and validation of IP addresses.

**How to Test with Burp Suite**
1. Try `http://[::1]/` for IPv6.
2. Try `http://2130706433/` for decimal.
3. Try `http://0x7f000001/` for hex.

**Example**
```http
GET /api/load?url=http://2130706433/admin HTTP/1.1
```

**Tools**
- Burp Repeater
- Custom encoding scripts

**Risk Rating**  
High

**Remediation**
- Normalise all IP addresses to a standard form before validation.
- Block all loopback and private IP ranges in all representations.

---

## 15. SSRF VIA URL ENCODING AND DOUBLE ENCODING

**Description**  
Attackers may encode URL characters to bypass weak filters that only check for plaintext patterns.

**What to Look For**
- Filters that block `127.0.0.1` but not `%31%32%37%2e%30%2e%30%2e%31`.
- Double encoding: `%2531%2532%2537%252e...`.

**What to Ignore**
- URL decoding before validation.

**How to Test with Burp Suite**
1. Encode the URL or IP address using Burp Decoder.
2. Send encoded payload.
3. If the server decodes and then makes the request, bypass may succeed.

**Example**
```http
GET /api/fetch?url=http://%31%32%37%2e%30%2e%30%2e%31/admin HTTP/1.1
```

**Tools**
- Burp Decoder
- Custom encoding scripts

**Risk Rating**  
Medium

**Remediation**
- Normalise (decode) the URL before validation.
- Validate after all encodings are resolved.

---

## 16. SSRF VIA DNS REBINDING ATTACKS

**Description**  
DNS rebinding tricks the server into resolving a domain name to a different IP address after the first request, bypassing IP allowlists.

**What to Look For**
- The server performs a DNS lookup for a user‑supplied domain.
- No validation of the resolved IP.

**What to Ignore**
- DNS resolution that blocks responses pointing to private IPs.

**How to Test with Burp Suite**
1. Use a domain you control with a very short TTL.
2. First DNS response points to a public IP (allowed).
3. After the first request, change the DNS record to an internal IP.
4. If the server re‑resolves, it may access internal resources.

**Tools**
- Custom DNS server
- Burp Collaborator (not directly; requires own domain)

**Risk Rating**  
High

**Remediation**
- Validate IP addresses after DNS resolution and reject private IPs.
- Use a DNS resolver that does not allow rebinding.

---

## 17. SSRF VIA REDIRECT FOLLOWING (302 TO INTERNAL IP)

**Description**  
If the API follows HTTP redirects (302), an attacker can provide a URL that redirects to an internal IP, bypassing a superficial filter.

**What to Look For**
- The server follows redirects.
- Initial URL passes validation (e.g., allowed domain), but final destination is internal.

**What to Ignore**
- Redirects that are not followed, or validation that checks final destination.

**How to Test with Burp Suite**
1. Host a malicious server that responds with `302 Location: http://127.0.0.1/admin`.
2. Provide the malicious URL to the API endpoint.
3. If the server follows the redirect and fetches internal content, SSRF exists.

**Example**
```http
GET /api/fetch?url=http://evil.com/redirect HTTP/1.1
```

**Tools**
- Burp Repeater
- Custom redirect server

**Risk Rating**  
High

**Remediation**
- Do not follow redirects, or validate the final URL before making the request.

---

## 18. SSRF VIA PARTIALLY CONTROLLED URLS (PATH INJECTION)

**Description**  
When only part of the URL is user‑controlled (e.g., a path), attackers can inject `../` or `@` to redirect the request.

**What to Look For**
- URL like `https://trusted.com/` + user_path.
- User can control the path and query parameters.

**What to Ignore**
- Hardcoded hostname with no user influence.

**How to Test with Burp Suite**
1. Try to inject `@` to change the host: `https://trusted.com@evil.com/`.
2. Use `../` to escape the path and access parent directories.

**Example**
```http
GET /api/proxy?path=../admin HTTP/1.1
```

**Tools**
- Burp Repeater
- Manual injection

**Risk Rating**  
High

**Remediation**
- Sanitise user‑controlled path components.
- Use URL parsing and rebuild from trusted parts.

---

## 19. SSRF VIA TEMPLATE INJECTION OR SSTI (URL CONTEXT)

**Description**  
Server‑side template injection (SSTI) can be used to construct arbitrary URLs and make server‑side requests.

**What to Look For**
- SSTI vulnerability where an expression can generate a URL.
- Ability to call functions like `curl`, `http.get`.

**What to Ignore**
- No SSTI or SSTI in a sandboxed environment.

**How to Test with Burp Suite**
1. Identify SSTI.
2. Use it to generate a request to an internal service.
3. For example, in Jinja2: `{{ config.items() }}` might not directly fetch, but you can use `{{ ''.__class__.__mro__[2].__subclasses__() }}` to find a method to make HTTP requests.

**Tools**
- Burp Repeater
- SSTI exploitation tools

**Risk Rating**  
Critical

**Remediation**
- Fix SSTI first.
- Network egress filtering as defence in depth.

---

## 20. SSRF VIA API PROXYING (INTERNAL API FORWARDING)

**Description**  
APIs that proxy requests to internal APIs may allow attackers to modify the target endpoint.

**What to Look For**
- API endpoints like `/api/proxy?endpoint=users`.
- Internal API prefix hardcoded but suffix user‑controlled.

**What to Ignore**
- Strict validation of the endpoint parameter (allowlist).

**How to Test with Burp Suite**
1. Change the `endpoint` parameter to point to an internal service (e.g., `http://internal-service/`).
2. Use URL encoding or path traversal.

**Example**
```http
GET /api/proxy?endpoint=http://169.254.169.254/latest/meta-data/ HTTP/1.1
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Whitelist allowed API endpoints.
- Do not allow full URL control.

---

## 21. SSRF VIA WEBSOCKET MESSAGES

**Description**  
WebSocket connections can be used to send messages that trigger server‑side requests to arbitrary URLs.

**What to Look For**
- WebSocket messages that contain a URL field.
- No validation of the URL.

**What to Ignore**
- URL validation on the server side.

**How to Test with Burp Suite**
1. Intercept WebSocket messages using Burp.
2. Modify a URL field to point to an internal service.
3. Observe if the server makes the request.

**Example**
```json
{"action": "fetch", "url": "http://169.254.169.254/latest/meta-data/"}
```

**Tools**
- Burp Suite (WebSocket support)

**Risk Rating**  
High

**Remediation**
- Validate URLs in WebSocket messages.
- Apply same SSRF protections as for REST APIs.

---

## 22. SSRF VIA HTTP HEADER INJECTION (HOST, X-FORWARDED-HOST)

**Description**  
Some APIs use the `Host` or `X-Forwarded-Host` header to construct internal requests. Attackers can manipulate these headers to cause SSRF.

**What to Look For**
- The API makes requests to a URL built from the `Host` header.
- Internal API calls using `X-Forwarded-For` or `X-Forwarded-Host`.

**What to Ignore**
- Headers are ignored or validated.

**How to Test with Burp Suite**
1. Change the `Host` header to an internal IP.
2. Trigger a request that the server makes to that host.
3. Observe if the server connects to your specified host.

**Example**
```http
GET /api/internal HTTP/1.1
Host: 169.254.169.254
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Do not trust `Host` header for internal routing.
- Use configuration files for internal endpoints.

---

## 23. SSRF VIA SERVER‑SIDE JAVASCRIPT (NODE.JS `FETCH`, `AXIOS`)

**Description**  
Node.js APIs that use `fetch`, `axios`, or `http.request` with user‑controlled URLs are vulnerable to SSRF.

**What to Look For**
- API endpoints that call `fetch(req.query.url)` or `axios.get(userUrl)`.
- No URL validation.

**What to Ignore**
- Input validation and URL allowlisting.

**How to Test with Burp Suite**
1. Provide a URL like `http://169.254.169.254/latest/meta-data/`.
2. Check response.

**Example**
```javascript
app.get('/fetch', (req, res) => {
  fetch(req.query.url).then(data => res.send(data));
});
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Validate URL against an allowlist.
- Use `http` module with request filtering.

---

## 24. SSRF VIA IMAGE PROCESSING LIBRARIES (IMAGEMAGICK, GD)

**Description**  
Image processing libraries (ImageMagick, GD) can read from URLs. If an attacker can supply a URL to an image, the server may fetch it.

**What to Look For**
- Image upload that supports URL (remote image).
- Usage of ImageMagick’s `read` with a URL.

**What to Ignore**
- Image processing that only reads local files.

**How to Test with Burp Suite**
1. Provide a URL to an image hosted on an internal service.
2. Use Burp Collaborator to see if the server fetches the image.

**Example**
```http
POST /api/resize HTTP/1.1
{"image_url": "http://169.254.169.254/latest/meta-data/"}
```

**Tools**
- Burp Collaborator

**Risk Rating**  
High

**Remediation**
- Disable URL support in image processing libraries.
- Use local file upload only.

---

## 25. SSRF VIA PDF EXPORT (EXTERNAL FONTS, IMAGES)

**Description**  
PDF export libraries (wkhtmltopdf, Puppeteer) can load external fonts and images. Attackers can embed a URL to an internal resource.

**What to Look For**
- PDF export from user‑supplied HTML.
- Support for external resources in PDF generation.

**What to Ignore**
- PDF generation that blocks external resources.

**How to Test with Burp Suite**
1. Generate PDF with CSS referencing an external font: `@import url('http://internal/font.css')`.
2. Check if the server fetches the font.

**Example**
```html
<style>@import url('http://169.254.169.254/latest/meta-data/');</style>
```

**Tools**
- Burp Collaborator

**Risk Rating**  
High

**Remediation**
- Disable external resource loading in PDF generators.
- Run PDF generation in a sandbox.

---

## 26. SSRF VIA RSS FEED IMPORT OR AGGREGATOR

**Description**  
RSS feed import features fetch the feed from a user‑supplied URL. Attackers can supply an internal URL.

**What to Look For**
- RSS import, feed reader functionality.
- Parameters like `feed_url`, `rss_url`.

**What to Ignore**
- Feed validation against allowed domains.

**How to Test with Burp Suite**
1. Provide an RSS feed URL pointing to an internal service.
2. Check if the API fetches and parses it.

**Example**
```http
POST /api/import-rss HTTP/1.1
{"feed_url": "http://127.0.0.1:8080/internal-feed.xml"}
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Whitelist allowed RSS feed domains.
- Do not follow redirects to internal addresses.

---

## 27. SSRF VIA THIRD‑PARTY API INTEGRATIONS (INBOUND WEBHOOKS)

**Description**  
When an API sends data to a third‑party service (e.g., Slack, Teams), the third‑party may fetch additional resources from URLs provided by the user, leading to SSRF.

**What to Look For**
- Integrations that send messages with user‑supplied URLs (e.g., Slack webhook with image URL).
- Third‑party service makes a request to the provided URL.

**What to Ignore**
- No external resource fetching.

**How to Test with Burp Suite**
1. Send a message to a third‑party service (Slack, Teams) with an image URL pointing to an internal IP.
2. Monitor if the third‑party fetches that URL (may not be directly observable, but could cause logs).

**Example**
- Slack webhook with `"attachments": [{"image_url": "http://169.254.169.254/latest/meta-data/"}]`.

**Tools**
- Burp Collaborator (if third‑party fetches)

**Risk Rating**  
Medium

**Remediation**
- Validate URLs before sending to third‑party services.
- Use a proxy to filter internal IPs.

---

## 28. SSRF VIA GRAPHQL BATCH OR INTROSPECTION REQUESTS

**Description**  
GraphQL batch queries may allow sending multiple requests in one call, one of which could be an SSRF vector. Introspection may reveal internal service URLs.

**What to Look For**
- GraphQL endpoints that support batching.
- Fields that take URLs (e.g., `fetch(url: String)`).

**What to Ignore**
- Input validation and batch size limits.

**How to Test with Burp Suite**
1. Use introspection to find fields that accept URLs.
2. Construct a batch query that includes an SSRF payload.
3. Send and observe.

**Example**
```graphql
query {
  fetch(url: "http://169.254.169.254/latest/meta-data/")
}
```

**Tools**
- GraphQL Raider
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Validate URL inputs in GraphQL resolvers.
- Limit batch size.

---

## 29. SSRF VIA SERVER‑LESS FUNCTION INVOCATIONS (AWS LAMBDA, AZURE FUNCTIONS)

**Description**  
Serverless functions that make HTTP requests to user‑supplied URLs are vulnerable to SSRF, potentially allowing access to internal cloud resources.

**What to Look For**
- Lambda or Azure Function endpoints that accept a URL parameter.
- No URL validation.

**What to Ignore**
- Functions that use allowlists or are placed inside a VPC.

**How to Test with Burp Suite**
1. Call the function with a URL pointing to the cloud metadata service or internal VPC endpoint.
2. Observe response.

**Example**
```http
GET https://lambda-url.execute-api.region.amazonaws.com/prod/fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Validate URL against an allowlist.
- Place functions inside a VPC with egress filtering.

---

## 30. SSRF VIA MISCONFIGURED `X-ORIGINAL-URL` OR `X-REWRITE-URL` HEADERS

**Description**  
Some reverse proxies or frameworks support headers like `X-Original-URL` or `X-Rewrite-URL` to override the effective request URL. Attackers can use these to bypass front‑end access controls and make internal requests.

**What to Look For**
- Support for `X-Original-URL` or `X-Rewrite-URL` headers.
- Application behind a reverse proxy (e.g., Apache mod_proxy, Nginx).

**What to Ignore**
- Headers stripped by the reverse proxy.

**How to Test with Burp Suite**
1. Identify a restricted path (e.g., `/admin`).
2. Send request to a public path (e.g., `/`) with the header `X-Original-URL: /admin`.
3. If the admin panel loads, SSRF via header misconfiguration exists.

**Example**
```http
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Configure reverse proxies to strip such headers.
- Do not rely on front‑end path‑based authorisation.

---

## ✅ **SUMMARY**

Server‑Side Request Forgery (SSRF) in APIs allows attackers to induce the server to make arbitrary requests to internal services, cloud metadata, or localhost. This guide covers 30 distinct SSRF vectors and testing techniques.

### **Key Testing Areas Summary**

| SSRF Vector | Key Indicators | Risk |
|-------------|----------------|------|
| URL Parameters | `url=`, `fetch=`, `src=` | Critical |
| File Upload (URL import) | “Import from URL” | Critical |
| Image URL Loading | Avatar from URL | High |
| Webhook Configuration | Callback URL settings | Critical |
| PDF Generation | wkhtmltopdf, Puppeteer | High |
| XXE with HTTP | XML external entities | Critical |
| Link Preview | Open Graph fetching | High |
| Gopher Protocol | Redis, Memcached interaction | Critical |
| Dict / File Protocols | `dict://`, `file://` | Critical |
| Blind SSRF | Collaborator detection | High |
| Cloud Metadata | `169.254.169.254` | Critical |
| Internal Port Scanning | Response differences | High |
| Localhost Services | `127.0.0.1` | Critical |
| IPv6 / Alternative IPs | Decimal, octal, hex | High |
| URL Encoding | Double encoding bypass | Medium |
| DNS Rebinding | TTL tricks | High |
| Redirect Following | 302 to internal IP | High |
| Path Injection | `@`, `../` in URLs | High |
| SSTI / Template Injection | Constructed URLs | Critical |
| API Proxying | `endpoint` parameter | Critical |
| WebSocket | URL in message | High |
| Host Header Injection | `Host: internal` | High |
| Node.js fetch/axios | User‑controlled URL | Critical |
| ImageMagick / GD | Remote image URL | High |
| PDF Export (fonts) | CSS `@import` | High |
| RSS Feed Import | `feed_url` | High |
| Third‑Party Webhooks | Image URL in attachments | Medium |
| GraphQL Batch | URL fields in queries | High |
| Serverless Functions | Lambda URL parameter | Critical |
| X‑Original‑URL Header | Header override | High |

### **Pro Tips for Testing SSRF in APIs**
1. **Use Burp Collaborator** – essential for blind SSRF detection.
2. **Test all input vectors** – parameters, headers, JSON fields, XML, file uploads.
3. **Try different protocols** – `http://`, `https://`, `gopher://`, `dict://`, `file://`.
4. **Bypass filters** – use decimal/hex IPs, redirects, encoding.
5. **Check for internal services** – metadata APIs (AWS, GCP, Azure), Redis, Memcached, internal admin panels.
6. **Automate port scanning** – use Intruder with common internal ports.
7. **Inspect for header‑based SSRF** – `X-Original-URL`, `Host`, `X-Forwarded-Host`.

---

*This guide is for professional security testing purposes only. Unauthorised testing is illegal.*
