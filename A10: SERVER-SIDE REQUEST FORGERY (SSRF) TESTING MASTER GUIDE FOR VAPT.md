# 🌐 **A10: SERVER-SIDE REQUEST FORGERY (SSRF) TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Forced Server Requests*

---

## 📋 **TABLE OF CONTENTS**

1. [SSRF via URL Parameters (Fetching External Resources)](#1-ssrf-via-url-parameters-fetching-external-resources)
2. [SSRF via File Upload (URL Based Import)](#2-ssrf-via-file-upload-url-based-import)
3. [SSRF via Document Parsing (PDF, DOCX, XLSX)](#3-ssrf-via-document-parsing-pdf-docx-xlsx)
4. [SSRF via Image URL Loading (Avatar, Profile Picture)](#4-ssrf-via-image-url-loading-avatar-profile-picture)
5. [SSRF via XML External Entity (XXE) with HTTP Request](#5-ssrf-via-xml-external-entity-xxe-with-http-request)
6. [SSRF via Webhook / Callback Configuration](#6-ssrf-via-webhook--callback-configuration)
7. [SSRF via Open Graph / Link Preview](#7-ssrf-via-open-graph--link-preview)
8. [SSRF via PDF Generation from HTML (wkhtmltopdf, Puppeteer)](#8-ssrf-via-pdf-generation-from-html-wkhtmltopdf-puppeteer)
9. [SSRF via WebSocket or HTTP Request Smuggling](#9-ssrf-via-websocket-or-http-request-smuggling)
10. [SSRF via Gopher Protocol (Redis, Memcached, MySQL)](#10-ssrf-via-gopher-protocol-redis-memcached-mysql)
11. [SSRF via Dict / File / SFTP Protocols](#11-ssrf-via-dict--file--sftp-protocols)
12. [SSRF via Blind with Out-of-Band (DNS/HTTP) Detection](#12-ssrf-via-blind-with-out-of-band-dnshttp-detection)
13. [SSRF to Internal Services (Metadata APIs - AWS, GCP, Azure)](#13-ssrf-to-internal-services-metadata-apis---aws-gcp-azure)
14. [SSRF to Internal Network Scanning (Port Scanning via HTTP)](#14-ssrf-to-internal-network-scanning-port-scanning-via-http)
15. [SSRF to Bypass Firewall / Access Internal Admin Panels](#15-ssrf-to-bypass-firewall--access-internal-admin-panels)
16. [SSRF to Localhost Services (127.0.0.1, ::1, 0.0.0.0)](#16-ssrf-to-localhost-services-127001-1-0000)
17. [SSRF via IPv6 or Alternative IP Representations](#17-ssrf-via-ipv6-or-alternative-ip-representations)
18. [SSRF via URL Encoding and Double Encoding](#18-ssrf-via-url-encoding-and-double-encoding)
19. [SSRF via DNS Rebinding Attacks](#19-ssrf-via-dns-rebinding-attacks)
20. [SSRF via Redirect Following (302 to Internal IP)](#20-ssrf-via-redirect-following-302-to-internal-ip)
21. [SSRF via Partially Controlled URLs (Path Injection)](#21-ssrf-via-partially-controlled-urls-path-injection)
22. [SSRF via Template Injection or SSTI (URL Context)](#22-ssrf-via-template-injection-or-ssti-url-context)
23. [SSRF via API Proxying (Internal API Forwarding)](#23-ssrf-via-api-proxying-internal-api-forwarding)
24. [SSRF via Web Cache Poisoning (Purge Requests)](#24-ssrf-via-web-cache-poisoning-purge-requests)
25. [SSRF via HTTP Header Injection (Host, X-Forwarded-Host)](#25-ssrf-via-http-header-injection-host-x-forwarded-host)
26. [SSRF via Server‑Side JavaScript (Node.js `fetch`, `axios`)](#26-ssrf-via-server-side-javascript-nodejs-fetch-axios)
27. [SSRF via Image Processing Libraries (ImageMagick, GD)](#27-ssrf-via-image-processing-libraries-imagemagick-gd)
28. [SSRF via PDF Export (External Fonts, Images)](#28-ssrf-via-pdf-export-external-fonts-images)
29. [SSRF via RSS Feed Import or Aggregator](#29-ssrf-via-rss-feed-import-or-aggregator)
30. [SSRF via Third‑Party API Integrations (Inbound Webhooks)](#30-ssrf-via-third-party-api-integrations-inbound-webhooks)

---

## 1. SSRF VIA URL PARAMETERS (FETCHING EXTERNAL RESOURCES)

**Description**  
The application takes a user‑supplied URL and makes a server‑side request to it. Attackers can change the URL to point to internal resources (e.g., `http://169.254.169.254/latest/meta-data/`, `http://localhost/admin`, `file:///etc/passwd`).

**What to Look For**
- Parameters like `url=`, `dest=`, `redirect=`, `fetch=`, `load=`, `src=`, `source=`, `path=`.
- Features that fetch external resources: “Import from URL”, “Link preview”, “Avatar from URL”.

**What to Ignore**
- URLs that are validated against a whitelist of allowed domains, and the application does not follow redirects to internal addresses.

**How to Test with Burp Suite**
1. Identify any parameter that accepts a URL.
2. Replace the URL with `http://127.0.0.1:80/admin` or `http://169.254.169.254/latest/meta-data/`.
3. Observe the response: if you see content from internal service, SSRF exists.
4. Use Burp Repeater to test different internal IPs and ports.

**Example**
```http
POST /api/fetch HTTP/1.1
{"url": "http://127.0.0.1:8080/admin"}
```
Response contains admin panel HTML.

**Tools**
- Burp Repeater
- Burp Intruder (for port scanning)
- Collaborator (for blind detection)

**Risk Rating**  
Critical

**Remediation**
- Whitelist allowed domains or URL patterns.
- Do not follow redirects to internal addresses.
- Use a dedicated allowlist of IP addresses.

---

## 2. SSRF VIA FILE UPLOAD (URL BASED IMPORT)

**Description**  
File upload features that accept a URL to import a file (e.g., import CSV from URL, fetch remote image) can be abused to make internal requests.

**What to Look For**
- Upload functionality that offers “Import from URL” or “Fetch remote file”.
- Parameters like `source_url`, `remote_file`, `import_from`.

**What to Ignore**
- File uploads that only accept local files and do not support URL import.

**How to Test with Burp Suite**
1. Find an upload endpoint that supports a URL.
2. Provide a URL pointing to an internal service, e.g., `http://localhost/secret`.
3. Check if the response or subsequent behaviour reveals internal data.

**Example**
```http
POST /upload-from-url
Content-Type: application/x-www-form-urlencoded

url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Tools**
- Burp Repeater
- Collaborator

**Risk Rating**  
Critical

**Remediation**
- Do not support URL import unless absolutely necessary.
- Validate and whitelist domains.

---

## 3. SSRF VIA DOCUMENT PARSING (PDF, DOCX, XLSX)

**Description**  
Documents (PDF, Word, Excel) can contain external references (images, fonts, hyperlinks). When the server parses the document, it may fetch those resources, leading to SSRF.

**What to Look For**
- Document upload features that parse or render documents.
- PDF generation from user input.

**What to Ignore**
- Document processing that does not fetch external resources (disables network access).

**How to Test with Burp Suite**
1. Create a malicious PDF that includes an image from `http://169.254.169.254/latest/meta-data/`.
2. Upload the PDF.
3. Monitor for out‑of‑bound requests using Burp Collaborator or internal logs.

**Example**
- PDF with `<img src="http://internal-server/secret">`.

**Tools**
- Burp Collaborator
- Custom PDF generation (e.g., using Python `reportlab` with external image)

**Risk Rating**  
High

**Remediation**
- Disable external resource fetching in document parsers.
- Use a sandboxed environment with no network access.

---

## 4. SSRF VIA IMAGE URL LOADING (AVATAR, PROFILE PICTURE)

**Description**  
Applications that allow users to set an avatar by providing a URL will fetch that image from the server. Attackers can change the URL to an internal endpoint.

**What to Look For**
- Profile picture or avatar settings with “Use URL” option.
- Parameters like `avatar_url`, `photo_url`, `image_url`.

**What to Ignore**
- Images that are uploaded directly, not via URL.

**How to Test with Burp Suite**
1. Set avatar URL to `http://169.254.169.254/latest/meta-data/`.
2. Observe if the application fetches the metadata (check response or logs).

**Example**
```http
POST /profile
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

## 5. SSRF VIA XML EXTERNAL ENTITY (XXE) WITH HTTP REQUEST

**Description**  
XXE vulnerabilities allow attackers to make HTTP requests via external entities. This is a classic SSRF vector.

**What to Look For**
- Endpoints that accept XML input (e.g., SOAP, RSS, SVG upload).
- XXE vulnerability already present.

**What to Ignore**
- XML parsers that disable external entities.

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
- Disable external entity processing in XML parsers.
- Use secure parser configurations.

---

## 6. SSRF VIA WEBHOOK / CALLBACK CONFIGURATION

**Description**  
Applications allow users to configure webhook URLs (e.g., for events, notifications). The server sends HTTP requests to those URLs. Attackers can set the webhook to an internal address.

**What to Look For**
- Settings pages with webhook URL fields (e.g., “Notification URL”, “Callback URL”).
- Integrations with external services.

**What to Ignore**
- Webhook URLs validated against a whitelist or restricted to HTTPS only.

**How to Test with Burp Suite**
1. Set a webhook URL to `http://169.254.169.254/latest/meta-data/`.
2. Trigger an event that invokes the webhook.
3. Monitor if the internal metadata is sent to the webhook (you may not see it directly, but you could use out‑of‑band detection).

**Example**
```http
POST /settings/webhook
{"webhook_url": "http://127.0.0.1:8080/admin"}
```

**Tools**
- Burp Collaborator
- Manual event triggering

**Risk Rating**  
Critical

**Remediation**
- Validate webhook URLs against an allowlist.
- Do not allow internal IPs or localhost.

---

## 7. SSRF VIA OPEN GRAPH / LINK PREVIEW

**Description**  
When users share a link, the application fetches the page to generate a preview (Open Graph). Attackers can make the server fetch internal URLs.

**What to Look For**
- Chat, comment, or messaging features that generate link previews.
- Any feature that fetches a page’s metadata.

**What to Ignore**
- Link previews that only fetch from trusted domains.

**How to Test with Burp Suite**
1. Share a link that points to an internal IP (e.g., `http://169.254.169.254/`).
2. Check if the application makes a request and returns metadata.

**Example**
- Send message with link `http://localhost:8080/admin`.

**Tools**
- Burp Collaborator (to confirm fetch)
- Internal test server

**Risk Rating**  
High

**Remediation**
- Whitelist domains for link previews.
- Use a dedicated proxy that filters internal addresses.

---

## 8. SSRF VIA PDF GENERATION FROM HTML (WKHTMLTOPDF, PUPPETEER)

**Description**  
HTML‑to‑PDF converters (wkhtmltopdf, Puppeteer) may load external resources (images, CSS, JavaScript) and can be used to make server‑side requests.

**What to Look For**
- PDF generation from user‑supplied HTML.
- Features like “Save as PDF”, “Export to PDF”.

**What to Ignore**
- PDF generation that disables external network access.

**How to Test with Burp Suite**
1. Provide HTML that includes an image from `http://169.254.169.254/latest/meta-data/`.
2. Generate the PDF and see if the image is embedded (or check server logs).

**Example**
```html
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

**Tools**
- Burp Repeater
- Custom HTML payloads

**Risk Rating**  
High

**Remediation**
- Disable external resource loading in PDF generators.
- Run the generator in a sandboxed environment.

---

## 9. SSRF VIA WEBSOCKET OR HTTP REQUEST SMUGGLING

**Description**  
WebSocket connections or HTTP request smuggling can be used to send crafted requests to internal services.

**What to Look For**
- WebSocket endpoints that accept user‑controlled URLs.
- Request smuggling vulnerabilities that allow sending requests to internal IPs.

**What to Ignore**
- Properly validated WebSocket origins and smuggling protections.

**How to Test with Burp Suite**
1. For WebSocket, try to connect to an internal address via a crafted message.
2. For smuggling, use request smuggling payloads to make the backend request internal resources.

**Tools**
- Burp Suite (WebSocket, Request Smuggling extension)

**Risk Rating**  
High

**Remediation**
- Validate all WebSocket connections and messages.
- Fix request smuggling vulnerabilities.

---

## 10. SSRF VIA GOPHER PROTOCOL (REDIS, MEMCACHED, MYSQL)

**Description**  
Some libraries support the `gopher://` protocol, which allows attackers to interact with TCP services (Redis, Memcached, MySQL) and execute arbitrary commands.

**What to Look For**
- URL parameters that allow `gopher://` scheme.
- Support for other protocols like `dict://`, `ftp://`, `file://`.

**What to Ignore**
- Whitelisted protocols (only HTTP/HTTPS) and disabled dangerous schemes.

**How to Test with Burp Suite**
1. Inject `gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0ainfo%0d%0a` (Redis command).
2. Observe if the response includes Redis info.

**Example**
```http
POST /fetch
{"url": "gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0ainfo%0d%0a"}
```

**Tools**
- Burp Repeater
- Custom gopher payload generators

**Risk Rating**  
Critical

**Remediation**
- Restrict URL schemes to HTTP/HTTPS only.
- Validate and sanitize the protocol.

---

## 11. SSRF VIA DICT / FILE / SFTP PROTOCOLS

**Description**  
Other protocols like `dict://`, `file://`, `sftp://` can be used to read local files or interact with internal services.

**What to Look For**
- URL parameters accepting schemes other than HTTP/HTTPS.
- Error messages revealing that the server tried to access a file or dictionary.

**What to Ignore**
- Protocol whitelist (only HTTP/HTTPS).

**How to Test with Burp Suite**
1. Try `file:///etc/passwd` in a URL parameter.
2. Try `dict://127.0.0.1:11211/stat` for Memcached.

**Example**
```http
GET /load?url=file:///etc/passwd
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Whitelist allowed protocols.
- Reject requests with unsupported schemes.

---

## 12. SSRF VIA BLIND WITH OUT-OF-BAND (DNS/HTTP) DETECTION

**Description**  
Blind SSRF occurs when the application makes a request but does not return the content. Attackers can use DNS or HTTP interactions to confirm the vulnerability.

**What to Look For**
- Any feature that might fetch a URL but does not return the response.
- Parameters where you can inject a URL but no output is visible.

**What to Ignore**
- Features that validate the URL before making the request.

**How to Test with Burp Suite**
1. Use Burp Collaborator to generate a unique domain.
2. Inject `http://collaborator.burp/` into the URL parameter.
3. Check Collaborator for any DNS or HTTP interaction.
4. If interaction occurs, blind SSRF is present.

**Example**
```http
POST /import
{"source": "http://collaborator.burp/"}
```

**Tools**
- Burp Collaborator
- DNSBin / Interactsh

**Risk Rating**  
High

**Remediation**
- Same as regular SSRF (whitelist, validation, network restrictions).

---

## 13. SSRF TO INTERNAL SERVICES (METADATA APIS - AWS, GCP, AZURE)

**Description**  
Cloud metadata endpoints (e.g., `169.254.169.254`) expose IAM credentials and configuration. SSRF can retrieve these and lead to cloud account compromise.

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
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
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

## 14. SSRF TO INTERNAL NETWORK SCANNING (PORT SCANNING VIA HTTP)

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
GET /proxy?url=http://10.0.0.1:22
```
Connection refused vs timeout.

**Tools**
- Burp Intruder
- Turbo Intruder for speed

**Risk Rating**  
High

**Remediation**
- Block all internal IP ranges from being accessed.
- Use a single outbound proxy with allowlist.

---

## 15. SSRF TO BYPASS FIREWALL / ACCESS INTERNAL ADMIN PANELS

**Description**  
SSRF can be used to reach internal admin panels, databases, or other services that are not exposed to the internet.

**What to Look For**
- Internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
- Common internal service ports (8080, 8443, 5000, 7000).

**What to Ignore**
- Proper egress filtering that blocks all internal IPs.

**How to Test with Burp Suite**
1. Attempt to access `http://10.0.0.1/admin`.
2. Try known internal hostnames (`intranet.company.com`, `internal-api`).

**Example**
```http
POST /api/proxy
{"url": "http://internal-admin-panel.company.com/"}
```

**Tools**
- Burp Repeater
- Internal hostname wordlist

**Risk Rating**  
Critical

**Remediation**
- Block outbound requests to internal IP ranges.
- Use separate network segmentation.

---

## 16. SSRF TO LOCALHOST SERVICES (127.0.0.1, ::1, 0.0.0.0)

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
GET /fetch?url=http://127.0.0.1:6379/INFO
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

## 17. SSRF VIA IPV6 OR ALTERNATIVE IP REPRESENTATIONS

**Description**  
Attackers may bypass IP filters by using IPv6 addresses or alternative representations (decimal, octal, hexadecimal).

**What to Look For**
- IPv6 loopback: `[::1]`, `[::]`.
- Decimal representation: `2130706433` for `127.0.0.1`.
- Octal: `0177.0.0.1`.
- Hexadecimal: `0x7f000001`.

**What to Ignore**
- Proper normalization and validation of IP addresses.

**How to Test with Burp Suite**
1. Try `http://[::1]/` for IPv6.
2. Try `http://2130706433/` for decimal.
3. Try `http://0x7f000001/` for hex.

**Example**
```http
GET /load?url=http://2130706433/admin
```

**Tools**
- Burp Repeater
- Custom encoding scripts

**Risk Rating**  
High

**Remediation**
- Normalize all IP addresses to a standard form before validation.
- Block all loopback and private IP ranges in all representations.

---

## 18. SSRF VIA URL ENCODING AND DOUBLE ENCODING

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
GET /fetch?url=http://%31%32%37%2e%30%2e%30%2e%31/admin
```

**Tools**
- Burp Decoder
- Custom encoding scripts

**Risk Rating**  
Medium

**Remediation**
- Normalize (decode) the URL before validation.
- Validate after all encodings are resolved.

---

## 19. SSRF VIA DNS REBINDING ATTACKS

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

## 20. SSRF VIA REDIRECT FOLLOWING (302 TO INTERNAL IP)

**Description**  
If the application follows HTTP redirects (302), an attacker can provide a URL that redirects to an internal IP, bypassing a superficial filter.

**What to Look For**
- The server follows redirects.
- Initial URL passes validation (e.g., allowed domain), but final destination is internal.

**What to Ignore**
- Redirects that are not followed, or validation that checks final destination.

**How to Test with Burp Suite**
1. Host a malicious server that responds with `302 Location: http://127.0.0.1/admin`.
2. Provide the malicious URL to the vulnerable endpoint.
3. If the server follows the redirect and fetches internal content, SSRF exists.

**Example**
```http
GET /fetch?url=http://evil.com/redirect
```
`evil.com` responds with `302` to `http://169.254.169.254/`.

**Tools**
- Burp Repeater
- Custom redirect server

**Risk Rating**  
High

**Remediation**
- Do not follow redirects, or validate the final URL before making the request.

---

## 21. SSRF VIA PARTIALLY CONTROLLED URLS (PATH INJECTION)

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
GET /proxy?path=../admin HTTP/1.1
```
If the backend constructs `http://internal/api/../admin`, it may access `http://internal/admin`.

**Tools**
- Burp Repeater
- Manual injection

**Risk Rating**  
High

**Remediation**
- Sanitize user‑controlled path components.
- Use URL parsing and rebuild from trusted parts.

---

## 22. SSRF VIA TEMPLATE INJECTION OR SSTI (URL CONTEXT)

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
- Network egress filtering as defense in depth.

---

## 23. SSRF VIA API PROXYING (INTERNAL API FORWARDING)

**Description**  
Applications that proxy requests to internal APIs may allow attackers to modify the target endpoint.

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
GET /api/proxy?endpoint=http://169.254.169.254/latest/meta-data/
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Whitelist allowed API endpoints.
- Do not allow full URL control.

---

## 24. SSRF VIA WEB CACHE POISONING (PURGE REQUESTS)

**Description**  
Some caching systems allow cache purge requests via HTTP. An attacker can use SSRF to send a purge request to the cache, removing legitimate content.

**What to Look For**
- Cache purge endpoints (`/purge`, `/cache/clear`).
- Application that makes requests to internal cache servers.

**What to Ignore**
- No cache or purge functionality.

**How to Test with Burp Suite**
1. Identify a URL that triggers a request to the cache system (e.g., `http://cache.local/purge?url=...`).
2. Use SSRF to call that endpoint.

**Example**
```http
POST /admin/purge
{"cache_url": "http://cache.internal/purge?url=/popular-page"}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Do not expose cache purge APIs.
- Validate origin of purge requests.

---

## 25. SSRF VIA HTTP HEADER INJECTION (HOST, X-FORWARDED-HOST)

**Description**  
Some applications use the `Host` or `X-Forwarded-Host` header to construct internal requests. Attackers can manipulate these headers to cause SSRF.

**What to Look For**
- The application makes requests to a URL built from the `Host` header.
- Internal API calls using `X-Forwarded-For` or `X-Forwarded-Host`.

**What to Ignore**
- Headers are ignored or validated.

**How to Test with Burp Suite**
1. Change the `Host` header to an internal IP.
2. Trigger a request that the server makes to that host.
3. Observe if the server connects to your specified host.

**Example**
```http
GET /internal-api HTTP/1.1
Host: 169.254.169.254
```
If the server uses `Host` to build a request, it may hit the metadata service.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Do not trust `Host` header for internal routing.
- Use configuration files for internal endpoints.

---

## 26. SSRF VIA SERVER‑SIDE JAVASCRIPT (NODE.JS `FETCH`, `AXIOS`)

**Description**  
Node.js applications using `fetch`, `axios`, or `http.request` with user‑controlled URLs are vulnerable to SSRF.

**What to Look For**
- Server‑side JavaScript endpoints that accept a URL.
- Usage of `fetch(req.query.url)` or `axios.get(userUrl)`.

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

## 27. SSRF VIA IMAGE PROCESSING LIBRARIES (IMAGEMAGICK, GD)

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
POST /resize
{"image_url": "http://169.254.169.254/latest/meta-data/"}
```

**Tools**
- Burp Collaborator
- Custom image payloads

**Risk Rating**  
High

**Remediation**
- Disable URL support in image processing libraries.
- Use local file upload only.

---

## 28. SSRF VIA PDF EXPORT (EXTERNAL FONTS, IMAGES)

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

## 29. SSRF VIA RSS FEED IMPORT OR AGGREGATOR

**Description**  
RSS feed import features fetch the feed from a user‑supplied URL. Attackers can supply an internal URL.

**What to Look For**
- RSS import, feed reader functionality.
- Parameters like `feed_url`, `rss_url`.

**What to Ignore**
- Feed validation against allowed domains.

**How to Test with Burp Suite**
1. Provide an RSS feed URL pointing to an internal service.
2. Check if the application fetches and parses it.

**Example**
```http
POST /import-rss
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

## 30. SSRF VIA THIRD‑PARTY API INTEGRATIONS (INBOUND WEBHOOKS)

**Description**  
When an application sends data to a third‑party API (e.g., Slack, Teams), the third‑party may fetch additional resources from URLs provided by the user, leading to SSRF.

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

## ✅ **SUMMARY**

Server‑Side Request Forgery (SSRF) allows attackers to induce the server to make requests to arbitrary destinations, leading to internal network scanning, data theft, metadata API compromise, and even remote code execution. This guide covers 30 distinct SSRF vectors and testing techniques.

### **Key Testing Areas Summary**

| SSRF Vector | Key Indicators | Risk |
|-------------|----------------|------|
| URL Parameters | `url=`, `src=`, `dest=` | Critical |
| File Upload (URL import) | “Import from URL” | Critical |
| Document Parsing | PDF, DOCX with external references | High |
| Image URL Loading | Avatar from URL | High |
| XXE with HTTP | XML external entities | Critical |
| Webhook Configuration | Callback URL settings | Critical |
| Link Preview | Open Graph fetching | High |
| PDF Generation | wkhtmltopdf, Puppeteer | High |
| Gopher Protocol | Redis, Memcached interaction | Critical |
| Dict / File Protocols | `dict://`, `file://` | Critical |
| Blind SSRF | Collaborator detection | High |
| Cloud Metadata | `169.254.169.254` | Critical |
| Internal Port Scanning | Response differences | High |
| Internal Admin Panels | Internal IP access | Critical |
| Localhost Services | `127.0.0.1` | Critical |
| IPv6 / Alternative IPs | Decimal, octal, hex | High |
| URL Encoding | Double encoding bypass | Medium |
| DNS Rebinding | TTL tricks | High |
| Redirect Following | 302 to internal IP | High |
| Path Injection | `@`, `../` in URLs | High |
| SSTI / Template Injection | Constructed URLs | Critical |
| API Proxying | `endpoint` parameter | Critical |
| Cache Purge | Internal cache requests | Medium |
| Host Header Injection | `Host: internal` | High |
| Node.js fetch/axios | User‑controlled URL | Critical |
| ImageMagick / GD | Remote image URL | High |
| PDF Export (fonts) | CSS `@import` | High |
| RSS Feed Import | `feed_url` | High |
| Third‑Party Webhooks | Image URL in attachments | Medium |

### **Pro Tips for Testing SSRF**
1. **Use Burp Collaborator** – essential for blind SSRF detection.
2. **Test all input vectors** – headers, parameters, JSON fields, XML, file uploads.
3. **Try different protocols** – `http://`, `https://`, `gopher://`, `dict://`, `file://`.
4. **Bypass filters** – use decimal/hex IPs, redirects, encoding.
5. **Check for internal services** – metadata APIs (AWS, GCP, Azure), Redis, Memcached, internal admin panels.
6. **Automate port scanning** – use Intruder with common internal ports.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
