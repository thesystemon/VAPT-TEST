# 🔐 **SESSION MANAGEMENT TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive*

---

## 📋 **TABLE OF CONTENTS**

1. [Session Token Predictability Analysis](#1-session-token-predictability-analysis)
2. [Session Fixation](#2-session-fixation)
3. [Insecure Cookie Attributes (HttpOnly, Secure, SameSite)](#3-insecure-cookie-attributes-httponly-secure-samesite)
4. [Session Expiration & Timeout Issues](#4-session-expiration--timeout-issues)
5. [Logout & Session Termination Flaws](#5-logout--session-termination-flaws)
6. [Session ID Exposure in URLs](#6-session-id-exposure-in-urls)
7. [Cross-Site Request Forgery (CSRF)](#7-cross-site-request-forgery-csrf)
8. [Session Concurrency Issues](#8-session-concurrency-issues)
9. [Session Puzzling / Session Variable Overloading](#9-session-puzzling--session-variable-overloading)
10. [Session Token Transmission Over Unencrypted Channel](#10-session-token-transmission-over-unencrypted-channel)
11. [Session Token Not Regenerated After Privilege Change](#11-session-token-not-regenerated-after-privilege-change)
12. [Session Token Not Regenerated After Password Change](#12-session-token-not-regenerated-after-password-change)
13. [Session Storage Security (Client-Side)](#13-session-storage-security-client-side)
14. [Session Token Brute Force Protection](#14-session-token-brute-force-protection)
15. [Session Token in Logs / Debug Information](#15-session-token-in-logs--debug-information)
16. [Session Token Not Invalidated on Server](#16-session-token-not-invalidated-on-server)
17. [Session Token Reuse After Logout](#17-session-token-reuse-after-logout)
18. [Session Token Not Tied to User Attributes](#18-session-token-not-tied-to-user-attributes)
19. [Session Management with JWTs (Stateless Sessions)](#19-session-management-with-jwts-stateless-sessions)
20. [Automated Session Handling for Testing (Burp Macros)](#20-automated-session-handling-for-testing-burp-macros)

---

## 1. SESSION TOKEN PREDICTABILITY ANALYSIS

**Description**  
Session tokens must be generated in a way that makes them unpredictable. Predictable session tokens can expose websites to session hijacking attacks, where an attacker accesses another user's active session . If this is an authenticated session, the attacker could access the user's data and potentially perform malicious operations on behalf of the user .

**What to Look For**
- Session tokens that appear sequential (e.g., 1001, 1002, 1003)
- Tokens based on timestamps (e.g., 20250216123045)
- Tokens that are base64-encoded user IDs or emails
- Tokens with low entropy (short length, limited character set)
- No changes in token structure across multiple sessions 

**What to Ignore**
- Cryptographically random tokens (UUIDv4, securely generated random strings)
- Tokens with high entropy (long, mixed alphanumeric + special chars)

**How to Test with Burp Suite**

1. **Collect Session Tokens :**
   - Log in to the target site multiple times to generate authenticated session cookies
   - In Burp, go to **Proxy > HTTP history** and look for responses that issue session cookies
   - Select a session cookie, right-click and select **Send to Sequencer** 

2. **Live Token Capture :**
   - In the Sequencer tab, click **Start live capture** to harvest session tokens
   - Let it collect a sufficient number of tokens (recommended: 100+)
   - When complete, click **Analyze now**

3. **Analyze Results :**
   - The **Summary** tab gives an overall randomness assessment
   - Use other tabs for deeper analysis (Character-level analysis, Bit-level analysis)
   - Look for "Significant bias" warnings indicating predictability 

4. **Manual Token Analysis :**
   - Examine token structure: look for static vs dynamic parts
   - Check if token contains user information (base64 decode if needed)
   - Test if token reuses values across different users

**Example (Predictable Token)**
```
Session tokens captured:
1001
1002
1003
1004
```
An attacker can guess that the next token will be 1005 and potentially hijack that session.

**Tools**
- Burp Sequencer 
- OWASP ZAP
- Foundstone CookieDigger 
- JHijack (for numeric session hijacking) 

**Risk Rating**  
High to Critical (if tokens are highly predictable)

**Remediation**
- Use cryptographically secure random number generators (entropy ≥128 bits) 
- Generate tokens with sufficient length (at least 128 bits)
- Avoid using user data or timestamps in token generation
- Implement token rotation on authentication and privilege changes 

---

## 2. SESSION FIXATION

**Description**  
When an application does not renew its session cookie(s) after a successful user authentication, it could be possible to find a session fixation vulnerability and force a user to utilize a cookie known by the attacker . In that case, an attacker could steal the user session (session hijacking) .

Session fixation vulnerabilities occur when:
- A web application authenticates a user without first invalidating the existing session ID, thereby continuing to use the session ID already associated with the user 
- An attacker is able to force a known session ID on a user so that, once the user authenticates, the attacker has access to the authenticated session 

**What to Look For**
- Session ID remains the same before and after login
- Application accepts session IDs from URL parameters
- Session ID sent over HTTP before redirecting to HTTPS login 
- No session regeneration on authentication

**What to Ignore**
- Session ID changes after successful login
- Session IDs accepted only via cookies, not URL parameters

**How to Test with Burp Suite**

1. **Capture Pre-Login Session :**
   - Visit the application without logging in
   - Note the session cookie set (e.g., `JSESSIONID=abc123`)

2. **Log In to Application :**
   - Authenticate with valid credentials
   - Observe if the session cookie changes

3. **Compare Session IDs :**
   - If the cookie value remains the same → vulnerable to session fixation
   - If it changes → properly implemented

4. **Test Session Fixation Attack Vector :**
   - Capture a session ID from the application (e.g., `xyz789`)
   - Send a link to victim with that session ID: `https://target.com/?SESSIONID=xyz789`
   - Victim clicks link, logs in
   - Attacker uses the same session ID (`xyz789`) to access victim's account

**Example**
```http
GET / HTTP/1.1
Host: target.com

Response:
Set-Cookie: JSESSIONID=0000d8eyYq3L0z2fgq10m4v-rt4:-1; Path=/; secure

POST /login HTTP/1.1
Host: target.com
Cookie: JSESSIONID=0000d8eyYq3L0z2fgq10m4v-rt4:-1
...

Response: (no new Set-Cookie)
```
If no new cookie is issued upon successful authentication, session fixation is possible .

**Tools**
- Burp Suite (manual testing)
- OWASP WebScarab 
- JHijack 

**Risk Rating**  
High

**Remediation**
- Generate a new session ID after successful authentication 
- Invalidate the old session ID on the server
- Never accept session IDs from URL parameters (use cookies only) 
- Configure `tracking-mode` to `COOKIE` in web.xml 

---

## 3. INSECURE COOKIE ATTRIBUTES (HTTPONLY, SECURE, SAMESITE)

**Description**  
Cookies that hold session tokens should be configured with multiple security flags to mitigate risks of theft and misuse . The `Secure` flag ensures the cookie is only transmitted over HTTPS. The `HttpOnly` flag prevents access via client-side scripts, mitigating XSS attacks. The `SameSite` attribute helps prevent CSRF .

**What to Look For **
- Missing `HttpOnly` flag (cookie accessible via JavaScript)
- Missing `Secure` flag (cookie sent over HTTP)
- Missing `SameSite` attribute (or set to `None` without proper justification)
- `Domain` attribute too broad (e.g., `.domain.com` allows all subdomains)
- `Path` attribute not set or too broad

**What to Ignore**
- Cookies with all security flags properly configured
- First-party cookies with appropriate `SameSite=Lax` or `Strict`

**How to Test with Burp Suite**

1. **Inspect Response Headers :**
   - In Burp Proxy > HTTP history, find responses that set cookies
   - Look for `Set-Cookie` headers

2. **Check Cookie Attributes :**
   - `Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict` → Secure
   - `Set-Cookie: sessionid=abc123;` → Insecure (missing all flags)

3. **Verify `HttpOnly` Protection:**
   - In browser console, try `document.cookie`
   - If session cookie appears, `HttpOnly` is missing

4. **Verify `Secure` Flag Enforcement:**
   - Try accessing site over HTTP (if available)
   - Check if session cookie is sent

5. **Test `SameSite` Behavior:**
   - Create a simple HTML page on another domain with a form POST to target
   - Check if session cookie is sent with the request

**Example**
```http
Set-Cookie: sessionid=abc123; Path=/
```
Missing `HttpOnly`, `Secure`, and `SameSite` flags.

**Tools**
- Burp Suite (passive scanner alerts on missing flags)
- Browser DevTools (Application > Cookies)
- OWASP ZAP

**Risk Rating**  
Medium to High (depending on other vulnerabilities present)

**Remediation **
- Set `HttpOnly` flag to prevent JavaScript access
- Set `Secure` flag to ensure HTTPS-only transmission
- Configure `SameSite` attribute to `Lax` or `Strict`
- Restrict `Domain` and `Path` attributes to minimum necessary
- Example secure configuration :
```xml
<cookie-config>
  <secure>true</secure>
  <http-only>true</http-only>
</cookie-config>
```

---

## 4. SESSION EXPIRATION & TIMEOUT ISSUES

**Description**  
Proper session expiration is crucial to minimizing the window of opportunity for attackers . Sessions should have reasonable idle timeouts and absolute expiration limits to ensure that stale sessions do not remain valid indefinitely .

**What to Look For **
- No idle timeout configured (session never expires)
- Extremely long timeouts (days, weeks, "remember me forever")
- Server does not enforce timeout (only client-side)
- Timeout can be bypassed by client-side manipulation
- Absolute timeout missing (session valid indefinitely)

**What to Ignore**
- Reasonable timeouts (15-30 minutes for sensitive apps, longer for low-risk)
- Server-side enforcement of timeouts

**How to Test with Burp Suite**

1. **Identify Timeout Behavior:**
   - Log in to application
   - Note session cookie
   - Wait for expected timeout period (check application documentation)

2. **Test Idle Timeout :**
   - After waiting, try to access authenticated page
   - If still accessible, timeout may be too long or not enforced

3. **Test Absolute Timeout:**
   - Log in and note time
   - Come back after 24 hours (or reasonable period)
   - Check if session still valid

4. **Check Server-Side Enforcement :**
   - Capture a request with valid session cookie
   - Replay it after timeout period using Repeater
   - If server accepts it, timeout not properly enforced server-side

**Example**
- Application sets cookie with `Expires=2030-01-01` (10+ years)
- Session never expires → high risk if cookie stolen

**Tools**
- Burp Repeater
- Custom scripts with time delays

**Risk Rating**  
Medium to High

**Remediation **
- Implement idle timeout (recommended: 15-30 minutes for sensitive apps)
- Implement absolute session timeout
- Enforce timeouts on server-side, not just client-side
- Configure session timeout in web.xml :
```xml
<session-config>
  <session-timeout>10</session-timeout> <!-- minutes -->
</session-config>
```

---

## 5. LOGOUT & SESSION TERMINATION FLAWS

**Description**  
When a user logs out, the application should invalidate the session on the server side, not just remove client-side tokens . Improper session termination allows token reuse and session hijacking .

**What to Look For **
- Logout button does not actually terminate server-side session
- Session cookie still valid after logout (can be replayed)
- Browser back button allows access to authenticated pages after logout
- No client-side cookie clearing

**What to Ignore**
- Proper server-side invalidation and client-side cookie clearing

**How to Test with Burp Suite**

1. **Capture Pre-Logout Session:**
   - Log in and capture a request with session cookie
   - Log out normally

2. **Replay Captured Request :**
   - In Repeater, send the captured authenticated request
   - If server returns authenticated content, session was not properly invalidated

3. **Test Logout Functionality:**
   - After logout, try to access authenticated pages directly
   - Use browser back button, refresh, or direct URL access

4. **Check Multiple Logout Scenarios:**
   - Logout from one tab, check session in another tab
   - Logout, then use old session cookie in new browser/incognito

**Example**
```http
POST /logout HTTP/1.1
Cookie: sessionid=abc123

Response: 200 OK (logout successful)

Later:
GET /dashboard HTTP/1.1
Cookie: sessionid=abc123

Response: 200 OK with dashboard content
```
Session still valid after logout → vulnerable.

**Tools**
- Burp Repeater
- Burp Proxy

**Risk Rating**  
High

**Remediation **
- Invalidate session on server-side upon logout
- Clear session cookie on client (set cookie with expired date) 
- Remove all session data from server storage
- Implement proper logout functionality that destroys session completely

---

## 6. SESSION ID EXPOSURE IN URLS

**Description**  
Session IDs should never appear in URLs. URLs can be cached, bookmarked, shared, or leaked via Referer headers . When session IDs are in URLs, they can be exposed to third parties .

**What to Look For **
- Session ID in query parameters: `?sessionid=abc123`
- Session ID in URL path: `/shop/sale;jsessionid=2P0OC2JDPXM0OQSNDLPSKHCJUN2JV` 
- URLs with `JSESSIONID`, `PHPSESSID`, or similar parameters

**What to Ignore**
- Session IDs only in cookies (never in URLs)

**How to Test with Burp Suite**

1. **Browse Application :**
   - Navigate through the application
   - Check the URL bar for session ID parameters

2. **Check HTTP History:**
   - In Burp Proxy, examine all requests
   - Look for session tokens in URL parameters

3. **Check for URL Rewriting:**
   - Some applications rewrite URLs to include session ID when cookies are disabled
   - Test by disabling cookies in browser and see if URLs change

4. **Check Referer Headers :**
   - If session ID is in URL, it will appear in Referer headers when navigating to external sites

**Example **
```
http://example.com/sale/saleitems;jsessionid=2P0OC2JDPXM0OQSNDLPSKHCJUN2JV?dest=Hawaii
```
If user shares this link, recipients can access their session.

**Tools**
- Burp Proxy
- Browser DevTools

**Risk Rating**  
High

**Remediation **
- Never put session IDs in URLs (use cookies only)
- Configure application to use cookie-based tracking only:
```xml
<tracking-mode>COOKIE</tracking-mode>
```
- Disable URL rewriting
- Use `Secure` cookies over HTTPS

---

## 7. CROSS-SITE REQUEST FORGERY (CSRF)

**Description**  
CSRF tricks users into executing unintended actions (e.g., fund transfers) via authenticated sessions . The attack relies on applications using cookies for session identification and browsers automatically sending those cookies .

**CSRF depends on :**
- Session handling via cookies
- Attacker's knowledge of web request structure
- Victim's active authenticated session
- Ability to trigger browser requests (e.g., via `<img>` tag)

**What to Look For **
- State-changing requests (POST, PUT, DELETE) without anti-CSRF tokens
- Forms without hidden CSRF tokens
- API endpoints that accept requests without tokens
- Missing `SameSite` cookie attribute
- GET requests that modify state (should be POST)

**What to Ignore**
- Requests with proper CSRF tokens validated server-side
- Idempotent GET requests (should not modify state anyway)

**How to Test with Burp Suite**

1. **Identify State-Changing Requests:**
   - Look for POST requests that change data (profile update, transfer, delete)

2. **Check for CSRF Tokens:**
   - Examine form for hidden CSRF token field
   - Check if token is validated server-side

3. **Craft CSRF PoC :**
   - Create HTML page with auto-submitting form or `<img>` tag
   - Example:
```html
<img src="http://target.com/transfer?amount=1000&to=attacker" width="0" height="0">
```

4. **Test with Victim Session:**
   - Log in as victim in one browser
   - Open PoC page in another tab/window
   - Check if action executed

5. **Test CSRF Token Bypass:**
   - Remove token from request, see if accepted
   - Reuse old token, see if accepted
   - Change token to arbitrary value, see if accepted

**Tools**
- Burp Suite (CSRF PoC generator in Engagement tools)
- CSRFTester 
- Pinata-csrf-tool 

**Risk Rating**  
High

**Remediation **
- Use anti-CSRF tokens in all state-changing forms
- Implement `SameSite=Strict` or `Lax` cookie attribute
- Use double-submit cookies pattern
- Consider requiring re-authentication for sensitive actions
- Add custom headers for AJAX requests

---

## 8. SESSION CONCURRENCY ISSUES

**Description**  
Session concurrency testing checks how the application handles multiple simultaneous sessions for the same user. Improper handling can lead to security issues or account takeover opportunities.

**What to Look For**
- No limit on concurrent sessions (attacker can maintain session alongside victim)
- Old sessions not invalidated when new session created (unless intended)
- Ability to bypass concurrent session limits using multiple IPs/user agents
- No notification of concurrent logins to user

**What to Ignore**
- Reasonable concurrency limits (e.g., 5 concurrent sessions)
- Proper invalidation of oldest session when limit reached

**How to Test with Burp Suite**

1. **Create Multiple Sessions:**
   - Log in from Browser A, capture session cookie
   - Log in from Browser B (or different browser profile)
   - Note both session cookies

2. **Test Session Validity:**
   - Use both sessions to access authenticated pages
   - Check if both remain valid

3. **Test Session Limits:**
   - Continue logging in from multiple browsers
   - Determine if there's a concurrency limit

4. **Test Session Invalidation:**
   - Log in from new session
   - Check if old session is invalidated (if application claims one session per user)

**Example**
- User logs in from phone and laptop simultaneously
- Both sessions remain active
- If user loses phone, attacker can maintain access alongside legitimate user

**Tools**
- Burp Suite
- Multiple browsers/browser profiles

**Risk Rating**  
Medium

**Remediation**
- Implement reasonable concurrent session limits
- Provide users with view of active sessions
- Allow users to terminate remote sessions
- Send notifications of new logins

---

## 9. SESSION PUZZLING / SESSION VARIABLE OVERLOADING

**Description**  
Session puzzling occurs when session tokens or variables are misused for multiple purposes (e.g., authentication and password reset), leading to authorization flaws . Attackers can manipulate session variables to gain unauthorized access.

**What to Look For **
- Same session variable used for different contexts
- Session variables not properly isolated by functionality
- Ability to set session variables via user input
- Session state persisting across different application modules

**What to Ignore**
- Properly isolated session variables with clear purposes

**How to Test with Burp Suite**

1. **Map Session Variables:**
   - Log in and note all session-related data
   - Perform different actions and observe session changes

2. **Test Variable Overloading:**
   - Try to set session variables via user input (profile fields, etc.)
   - Check if those variables affect other parts of the application

3. **Test Cross-Module Contamination:**
   - Perform action in Module A (e.g., shopping cart)
   - Check if session state affects Module B (e.g., admin panel)

**Example**
- Application uses `role` session variable for both authentication and feature access
- Attacker manipulates input to change `role` to "admin"
- Gains unauthorized admin access

**Tools**
- Burp Suite
- Custom scripts

**Risk Rating**  
Medium to High

**Remediation **
- Isolate session tokens by functionality
- Avoid token reuse across different workflows
- Use separate session variables for different contexts
- Validate session data on each request

---

## 10. SESSION TOKEN TRANSMISSION OVER UNENCRYPTED CHANNEL

**Description**  
Session tokens should only be transmitted over encrypted channels (HTTPS) to prevent interception via network sniffing .

**What to Look For **
- Session cookies sent over HTTP connections
- Mixed content (HTTPS page loading HTTP resources that send cookies)
- Login page served over HTTP (even if form submits to HTTPS)
- Application accessible over HTTP with same session cookies

**What to Ignore**
- Strict HTTPS-only applications with HSTS

**How to Test with Burp Suite**

1. **Check HTTP Usage:**
   - Try accessing site over HTTP (if available)
   - Check if session cookies are transmitted

2. **Monitor HTTP History:**
   - In Burp Proxy, filter to show only HTTP traffic
   - Look for requests containing session cookies

3. **Check Mixed Content:**
   - Load page over HTTPS
   - Check if any resources (images, scripts) are loaded over HTTP
   - Those HTTP requests will send cookies in plaintext

4. **Verify HSTS Implementation:**
   - Check for `Strict-Transport-Security` header
   - Test if HTTP redirects to HTTPS

**Example**
```http
GET http://target.com/dashboard HTTP/1.1
Cookie: sessionid=abc123
```
Session token transmitted in plaintext → easily intercepted.

**Tools**
- Burp Proxy
- Wireshark (for network-level verification)

**Risk Rating**  
Critical

**Remediation **
- Enforce HTTPS site-wide
- Set `Secure` flag on all cookies 
- Implement HSTS (HTTP Strict Transport Security)
- Redirect all HTTP traffic to HTTPS
- Use `Cache-Control: no-cache` for sensitive pages

---

## 11. SESSION TOKEN NOT REGENERATED AFTER PRIVILEGE CHANGE

**Description**  
When a user's privileges change (e.g., from regular user to admin), the session token should be regenerated to prevent session hijacking of elevated privileges .

**What to Look For**
- Session token remains same before and after privilege escalation
- No session regeneration when admin privileges granted
- Ability to use old session token after privilege change

**What to Ignore**
- Session token changes after any privilege change

**How to Test with Burp Suite**

1. **Log in as Regular User:**
   - Note session cookie value

2. **Escalate Privileges:**
   - Perform action that grants admin privileges (if possible)
   - Or test with account that has privilege change capability

3. **Check Session Token:**
   - After privilege change, check if session cookie value changed
   - If same → vulnerable

4. **Test with Old Session:**
   - If session token changed, try using old token
   - Should be invalid or have old privileges

**Example**
- User logs in with session token `abc123`
- User becomes admin (via approval, etc.)
- Session token remains `abc123`
- Attacker who stole `abc123` before escalation now has admin access

**Tools**
- Burp Proxy
- Repeater for testing old tokens

**Risk Rating**  
High

**Remediation **
- Regenerate session ID after any privilege change
- Invalidate old session on server
- Use short session lifetimes for sensitive operations

---

## 12. SESSION TOKEN NOT REGENERATED AFTER PASSWORD CHANGE

**Description**  
When a user changes their password, all existing sessions should be invalidated to prevent an attacker with a stolen session from maintaining access after the password is changed .

**What to Look For**
- Session remains valid after password change
- No option to "log out other devices"
- Old session token can still access account

**What to Ignore**
- All sessions invalidated on password change (except current session if configured)
- Proper notification of password change sent to user

**How to Test with Burp Suite**

1. **Capture Current Session:**
   - Log in, note session cookie

2. **Change Password:**
   - Perform password change

3. **Test Old Session:**
   - Use Repeater to send authenticated request with old session cookie
   - If still accepted → vulnerable

4. **Test Other Browsers:**
   - Log in from two different browsers
   - Change password from one
   - Check if other browser session remains valid

**Example**
- User changes password after suspected compromise
- Attacker's stolen session cookie still works
- Attacker maintains access despite password change

**Tools**
- Burp Repeater
- Multiple browsers

**Risk Rating**  
High

**Remediation **
- Invalidate all sessions on password change
- Provide option to "log out all other devices"
- Send notification of password change
- Require re-authentication for sensitive actions after password change

---

## 13. SESSION STORAGE SECURITY (CLIENT-SIDE)

**Description**  
Applications sometimes store session-related data in client-side storage mechanisms like `localStorage` or `sessionStorage`, which are accessible via JavaScript and persist beyond browser sessions .

**What to Look For **
- Session tokens stored in `localStorage` (persists until cleared)
- Session tokens stored in `sessionStorage` (accessible via JS)
- Sensitive data stored in client-side storage without encryption
- JWTs stored in `localStorage` (cannot be protected with `HttpOnly`)

**What to Ignore**
- Session tokens stored only in `HttpOnly` cookies
- Non-sensitive data stored in client-side storage

**How to Test with Browser DevTools**

1. **Inspect Storage:**
   - Open DevTools (F12)
   - Go to Application tab
   - Check `localStorage` and `sessionStorage`

2. **Look for Session Tokens:**
   - Search for keys like `token`, `session`, `jwt`, `auth`
   - If found, these are accessible to any JavaScript on the page

3. **Test XSS Impact:**
   - If XSS exists, attacker can steal tokens from `localStorage`
   - Compare with `HttpOnly` cookies (not accessible)

**Example**
```javascript
localStorage.setItem('auth_token', 'eyJhbGciOiJIUzI1NiIs...');
```
Any XSS vulnerability can steal this token.

**Tools**
- Browser DevTools
- Burp (passively check for client-side storage usage)

**Risk Rating**  
Medium to High

**Remediation **
- Use `HttpOnly` cookies for session tokens (not accessible via JS)
- Avoid storing sensitive data in client-side storage
- If JWT must be used, consider storing in memory only, not persistent storage
- Implement robust XSS protection

---

## 14. SESSION TOKEN BRUTE FORCE PROTECTION

**Description**  
Session tokens should have sufficient entropy to prevent brute force attacks. Attackers should not be able to guess valid session IDs by enumerating possible values .

**What to Look For **
- Session tokens with small keyspace (e.g., 4-digit numbers)
- No rate limiting on session validation endpoints
- Ability to test many session IDs quickly
- Sequential or predictable tokens (covered in Section 1)

**What to Ignore**
- High-entropy tokens with rate limiting on validation

**How to Test with Burp Suite**

1. **Assess Token Entropy:**
   - Collect sample of tokens
   - Analyze with Sequencer (as in Section 1)

2. **Check Rate Limiting:**
   - Identify endpoints that validate sessions (profile pages, API endpoints)
   - Attempt to send many requests with invalid session IDs
   - Check for rate limiting or account lockout

3. **Estimate Keyspace:**
   - Calculate possible combinations based on token format
   - Example: 6-digit numeric = 1 million possibilities
   - If no rate limiting, can brute force in minutes

**Example**
- Session token format: `SESSION-123456` (6 digits)
- 1 million possible tokens
- Without rate limiting, can test all in hours

**Tools**
- Burp Intruder
- Custom scripts

**Risk Rating**  
High

**Remediation **
- Use high-entropy session tokens (128+ bits)
- Implement rate limiting on session validation
- Invalidate sessions after reasonable inactivity
- Monitor for brute force attempts

---

## 15. SESSION TOKEN IN LOGS / DEBUG INFORMATION

**Description**  
Session tokens should never appear in server logs, error messages, or debug output. They can be exposed to administrators, support staff, or attackers who gain access to logs .

**What to Look For **
- Session IDs in URL parameters (likely logged)
- Session tokens in error messages displayed to users
- Debug pages that output session information
- Session data in stack traces

**What to Ignore**
- No session information in logs or error messages

**How to Test**

1. **Check Error Messages:**
   - Trigger errors (invalid input, 404 pages)
   - Look for session tokens in error output

2. **Check Debug Endpoints:**
   - Look for `/debug`, `/phpinfo`, `/status` pages
   - Check if they expose session information

3. **Review Application Behavior:**
   - If session IDs are in URLs, they will be in server logs
   - Check `Referer` headers for session ID leakage

**Example**
```
Error: Invalid session ID: SESSION-abc123
```
Session token exposed in error message.

**Tools**
- Burp (search for session patterns in responses)
- Manual inspection

**Risk Rating**  
Medium

**Remediation **
- Never include session IDs in URLs
- Sanitize error messages (remove sensitive data)
- Disable debug mode in production
- Ensure logs do not contain session tokens

---

## 16. SESSION TOKEN NOT INVALIDATED ON SERVER

**Description**  
Session tokens should be stored and validated server-side. Simply checking client-side existence is insufficient; the server must verify that the session exists and is valid .

**What to Look For**
- Application accepts any session token (no server-side validation)
- Session persists even after server restart (if stored only in memory)
- No session storage on server (pure client-side sessions)

**What to Ignore**
- Proper server-side session storage and validation

**How to Test**

1. **Test Arbitrary Session Token:**
   - Modify session cookie to arbitrary value (e.g., `abc123`)
   - Send request to authenticated page
   - If accepted, no server-side validation

2. **Test After Server Restart:**
   - If possible, trigger server restart (not typical in testing)
   - Check if session remains valid

3. **Test Session Invalidation:**
   - Log in, then have server invalidate session (via admin action)
   - Check if token still works

**Example**
```http
GET /dashboard HTTP/1.1
Cookie: sessionid=anything123
```
If server returns authenticated content, no validation.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
Critical

**Remediation **
- Store session data server-side
- Validate session existence on every request
- Implement proper session lifecycle management
- Use secure session management libraries

---

## 17. SESSION TOKEN REUSE AFTER LOGOUT

**Description**  
When a user logs out, the session token should be permanently invalidated. Attackers should not be able to reuse a previously valid session token .

**What to Look For**
- Session token works after logout (as tested in Section 5)
- Token can be reused within certain time window
- Token works from different IP/user agent after logout

**What to Ignore**
- Token properly invalidated server-side

**How to Test with Burp Suite**

1. **Capture Authenticated Request:**
   - Log in and capture a request with session cookie

2. **Log Out:**
   - Perform logout

3. **Replay Captured Request:**
   - In Repeater, send the captured authenticated request
   - Check response

4. **Test Multiple Scenarios:**
   - Immediate replay after logout
   - Replay after waiting some time
   - Replay from different IP (using VPN/proxy)

**Example**
- User logs out of banking application
- Attacker captures session token from network traffic
- Attacker replays token after logout and accesses account

**Tools**
- Burp Repeater
- Burp Proxy

**Risk Rating**  
Critical

**Remediation **
- Invalidate session server-side on logout
- Remove session data from server storage
- Set short session expiration
- Implement token blacklist if using stateless JWTs

---

## 18. SESSION TOKEN NOT TIED TO USER ATTRIBUTES

**Description**  
Session tokens should be bound to specific user attributes (IP address, user agent, etc.) to make hijacking more difficult . Tokens that work from any location/device are easier to steal and reuse.

**What to Look For**
- Session works from different IP address
- Session works with different user agent
- No binding to any client characteristics
- Token can be used from any geographical location

**What to Ignore**
- Sessions bound to IP (with consideration for legitimate IP changes)
- Sessions bound to user agent

**How to Test with Burp Suite**

1. **Capture Session Token:**
   - Log in and capture session cookie

2. **Change IP:**
   - Use VPN, proxy, or Burp's **Match and Replace** to modify `X-Forwarded-For`
   - Replay request with new IP

3. **Change User Agent:**
   - Modify `User-Agent` header
   - Replay request

4. **Check if Session Still Valid:**
   - If yes, session not bound to these attributes

**Example**
- Attacker steals session token via XSS
- Token works from attacker's different IP and browser
- Immediate session hijacking possible

**Tools**
- Burp Repeater
- Burp Proxy with header modifications

**Risk Rating**  
Medium

**Remediation **
- Bind sessions to IP address (with consideration for mobile users)
- Bind to user agent string
- Use fingerprinting techniques
- Implement additional verification for sensitive actions

---

## 19. SESSION MANAGEMENT WITH JWTS (STATELESS SESSIONS)

**Description**  
JSON Web Tokens (JWTs) are often used for stateless authentication. They introduce unique security considerations compared to traditional server-side sessions .

**What to Look For **
- JWTs stored insecurely (localStorage, sessionStorage)
- No token expiration or excessively long expiration
- Weak signing keys (covered in Authentication guide, Section 13)
- No token revocation mechanism
- Tokens contain sensitive data
- Missing signature validation

**What to Ignore**
- Properly implemented JWTs with short expiration and secure storage

**How to Test with Burp Suite**

1. **Examine JWT Structure:**
   - Decode JWT at jwt.io
   - Check payload for sensitive data
   - Check expiration (`exp`) claim

2. **Test Token Storage:**
   - Check if JWT stored in `HttpOnly` cookie or localStorage

3. **Test Token Revocation:**
   - Log out, see if token still works
   - Change password, see if old token works

4. **Test Token Replay:**
   - Capture valid JWT
   - Replay after logout (should fail)

5. **Check for JWT Vulnerabilities:**
   - None algorithm, weak secret, etc. (see Authentication guide, Section 13)

**Example**
```javascript
localStorage.setItem('access_token', 'eyJhbGciOiJIUzI1NiIs...');
```
Token accessible to any JavaScript; if XSS exists, token stolen.

**Tools**
- jwt.io
- jwt_tool
- Burp extension: JSON Web Tokens

**Risk Rating**  
High

**Remediation **
- Store JWTs in `HttpOnly` cookies when possible
- Use short expiration times (minutes, not hours/days)
- Implement token refresh mechanism
- Consider token revocation strategies (blacklist)
- Avoid storing sensitive data in JWT payload
- Use strong signing keys

---

## 20. AUTOMATED SESSION HANDLING FOR TESTING (BURP MACROS)

**Description**  
When testing, some actions may result in an application terminating your session . For example, an application may automatically log you out if you submit suspicious input. This may prevent you from performing actions such as fuzzing with Burp Intruder .

Burp enables you to configure a session handling rule to automatically log back into an application .

**What to Look For**
- Applications that terminate sessions during testing
- Need to automate re-authentication for long-running tests

**How to Configure in Burp Suite **

1. **Identify Invalid Session Behavior :**
   - Log in, then log out
   - Try to access authenticated page without login
   - Note the behavior (e.g., 302 redirect to `/login`)

2. **Configure Session Handling Rule :**
   - Go to **Settings > Sessions > Session handling rules**
   - Click **Add**
   - Set **Scope** (tools and URLs to apply)

3. **Add Check Session Action :**
   - In **Details** tab, add rule description
   - Click **Add > Check session is valid**
   - Specify expression found in invalid login response
   - Example: redirect to `/login`

4. **Add Macro for Login :**
   - Select **If session is invalid, run a macro**
   - Click **Add**, record login sequence
   - Select the login requests (GET /login, POST credentials)

5. **Test the Rule :**
   - Log out in browser
   - Send authenticated request to Repeater
   - Send request; cookies should auto-update
   - Verify successful login in response

**Example **
- For `ginandjuice.shop`, credentials are `carlos:hunter2`
- Invalid session detected by redirect to `/login`
- Macro replays login sequence automatically

**Tools**
- Burp Suite Professional (Session Handling Rules, Macros)
- Session Handling Tracer (for troubleshooting) 

**Risk Rating**  
N/A (Testing Technique)

**Purpose**
- Maintain authenticated session during long-running tests
- Automate re-authentication for fuzzing and scanning
- Enable continuous testing without manual intervention

---

## ✅ **SUMMARY**

Session management is critical because it controls how users maintain an authenticated state after login . A secure session management implementation ensures that a user's session cannot be hijacked, predicted, or fixed by an attacker . Weaknesses in session handling can allow attackers to impersonate other users, gain unauthorized access, or escalate privileges .

**Key Testing Areas :**
- Session token generation (randomness, predictability)
- Session lifecycle (creation, maintenance, termination)
- Cookie security attributes (HttpOnly, Secure, SameSite)
- Session fixation protection
- Logout and timeout enforcement
- CSRF protection
- Session concurrency controls

**Pro Tip:** Use Burp Sequencer for token analysis , session handling rules for automated testing , and always verify server-side enforcement of session controls .

**Remember:** Always obtain proper authorization before testing. Session management flaws can lead to complete account takeover and data breach.

--- 

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
