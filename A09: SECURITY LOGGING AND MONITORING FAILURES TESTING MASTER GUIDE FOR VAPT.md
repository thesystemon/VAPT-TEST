# 📜 **A09: SECURITY LOGGING AND MONITORING FAILURES TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Detection & Visibility Gaps*

---

## 📋 **TABLE OF CONTENTS**

1. [Insufficient Logging of Authentication Events](#1-insufficient-logging-of-authentication-events)
2. [No Logging of Privilege Changes (Role Escalation, User Creation)](#2-no-logging-of-privilege-changes-role-escalation-user-creation)
3. [Missing Logging of Sensitive Data Access (PII, Financial, Medical)](#3-missing-logging-of-sensitive-data-access-pii-financial-medical)
4. [No Logging of Configuration Changes](#4-no-logging-of-configuration-changes)
5. [Absence of Audit Trails for Administrative Actions](#5-absence-of-audit-trails-for-administrative-actions)
6. [Logs Stored Locally Without Centralized Aggregation](#6-logs-stored-locally-without-centralized-aggregation)
7. [No Integrity Protection for Logs (Tampering Possible)](#7-no-integrity-protection-for-logs-tampering-possible)
8. [Insufficient Log Retention (Logs Deleted Too Early)](#8-insufficient-log-retention-logs-deleted-too-early)
9. [No Real‑Time Alerting for Critical Events](#9-no-real-time-alerting-for-critical-events)
10. [Missing Monitoring for Failed Login Thresholds (Brute Force)](#10-missing-monitoring-for-failed-login-thresholds-brute-force)
11. [No Detection of Credential Stuffing Patterns](#11-no-detection-of-credential-stuffing-patterns)
12. [No Monitoring for Unusual Geographic Access](#12-no-monitoring-for-unusual-geographic-access)
13. [No Alerts for Concurrent Sessions from Multiple IPs](#13-no-alerts-for-concurrent-sessions-from-multiple-ips)
14. [Logs Exposed or Accessible to Unauthorized Users](#14-logs-exposed-or-accessible-to-unauthorized-users)
15. [Sensitive Data Logged in Plaintext (Passwords, Tokens)](#15-sensitive-data-logged-in-plaintext-passwords-tokens)
16. [No Logging of API Access (Rate Limit Exceeded, Unauthorized Attempts)](#16-no-logging-of-api-access-rate-limit-exceeded-unauthorized-attempts)
17. [Missing Logging for File Uploads and Downloads](#17-missing-logging-for-file-uploads-and-downloads)
18. [No Monitoring for Abnormal Traffic Patterns (DDoS, Scraping)](#18-no-monitoring-for-abnormal-traffic-patterns-ddos-scraping)
19. [Logs Without Timestamps or Accurate Time Synchronization (NTP)](#19-logs-without-timestamps-or-accurate-time-synchronization-ntp)
20. [No Logging of Password Change and Password Reset Events](#20-no-logging-of-password-change-and-password-reset-events)
21. [No Monitoring for Failed MFA Attempts](#21-no-monitoring-for-failed-mfa-attempts)
22. [No Alerting for Suspicious User Agent Strings](#22-no-alerting-for-suspicious-user-agent-strings)
23. [No Monitoring for API Abuse (High Volume, Malformed Requests)](#23-no-monitoring-for-api-abuse-high-volume-malformed-requests)
24. [Insufficient Logging of Third-Party Integrations](#24-insufficient-logging-of-third-party-integrations)
25. [No Logging of Data Exports or Bulk Operations](#25-no-logging-of-data-exports-or-bulk-operations)
26. [Logs Not Monitored or Reviewed (No SIEM / SOC)](#26-logs-not-monitored-or-reviewed-no-siem--soc)
27. [No Correlation of Events Across Different Systems](#27-no-correlation-of-events-across-different-systems)
28. [Missing Logs for Session Management Events (Login, Logout, Timeout)](#28-missing-logs-for-session-management-events-login-logout-timeout)
29. [No Logging of Database Query Execution (Especially DELETE, UPDATE without WHERE)](#29-no-logging-of-database-query-execution-especially-delete-update-without-where)
30. [Lack of Incident Response Plan Based on Log Analysis](#30-lack-of-incident-response-plan-based-on-log-analysis)

---

## 1. INSUFFICIENT LOGGING OF AUTHENTICATION EVENTS

**Description**  
Authentication events (successful and failed logins) must be logged to detect brute force attacks, credential stuffing, and account takeovers. Insufficient logging makes these attacks invisible.

**What to Look For**
- No logs for failed login attempts.
- Successful logins not logged (especially for privileged accounts).
- Logs missing source IP, timestamp, username.

**What to Ignore**
- Comprehensive authentication logging with all required fields.

**How to Test with Burp Suite**
1. Perform a few login attempts (both success and failure) from a specific IP.
2. Request log access (if possible) or check if the application has a log viewing endpoint.
3. If logs are not accessible, check for any response that indicates logging (e.g., no error about logging). However, this test often requires access to server logs or admin interface.

**Example**
- Server logs show no entries for login attempts.

**Tools**
- Access to log files (via admin panel or server)
- Manual review of logging configuration

**Risk Rating**  
High

**Remediation**
- Log all login events (success, failure, lockout) with timestamp, username, source IP, user agent.
- Send logs to a centralized, secure logging system.

---

## 2. NO LOGGING OF PRIVILEGE CHANGES (ROLE ESCALATION, USER CREATION)

**Description**  
Changes to user privileges (e.g., granting admin role, creating new privileged accounts) must be logged to detect insider threats or compromised admin accounts.

**What to Look For**
- No audit trail for role changes, user creation, or deletion.
- No logs for permission modifications.

**What to Ignore**
- Detailed logs with who made the change, what was changed, timestamp, and source IP.

**How to Test with Burp Suite**
1. As an admin, create a new admin user or change a role.
2. Check if the action is logged (accessible via admin logs).
3. If no logs exist, vulnerable.

**Example**
- Admin panel creates new user but no record of who created it.

**Tools**
- Admin log review
- Manual testing

**Risk Rating**  
High

**Remediation**
- Log all privilege changes, including old and new values.
- Store logs securely and monitor for unusual changes.

---

## 3. MISSING LOGGING OF SENSITIVE DATA ACCESS (PII, FINANCIAL, MEDICAL)

**Description**  
Access to sensitive data (PII, credit cards, medical records) should be logged to detect unauthorized access or data breaches.

**What to Look For**
- No logs when users view their own or others' sensitive data.
- No alerting for bulk access.

**What to Ignore**
- Granular logging of data access with user identification.

**How to Test with Burp Suite**
1. Access sensitive data (e.g., profile, order history).
2. Check if the action is logged (via log review).
3. If not, logging is insufficient.

**Example**
- User views another user’s medical record, but no log entry.

**Tools**
- Log review
- Manual testing

**Risk Rating**  
High

**Remediation**
- Log access to sensitive data with user ID, resource ID, timestamp, and IP.
- Implement alerts for unusual access patterns.

---

## 4. NO LOGGING OF CONFIGURATION CHANGES

**Description**  
Changes to security-relevant configuration (e.g., firewall rules, authentication settings) must be logged for audit and incident response.

**What to Look For**
- No logs for changes to security settings, rate limits, or allowed origins.
- Configuration changes not tied to a specific administrator.

**What to Ignore**
- Comprehensive configuration change logs with rollback capability.

**How to Test with Burp Suite**
1. If you have admin access, change a security setting.
2. Check logs for the change.
3. If absent, vulnerable.

**Example**
- Admin disables MFA globally; no log entry.

**Tools**
- Admin panel log review

**Risk Rating**  
High

**Remediation**
- Log all configuration changes, including who, what, when, and old/new values.

---

## 5. ABSENCE OF AUDIT TRAILS FOR ADMINISTRATIVE ACTIONS

**Description**  
All administrative actions (user deletion, system updates, data exports) should be audited. Without audit trails, malicious insiders or compromised accounts can operate undetected.

**What to Look For**
- No audit trail for sensitive admin actions.
- Logs that are easily deleted or tampered.

**What to Ignore**
- Immutable audit trails with tamper protection.

**How to Test with Burp Suite**
1. Perform an admin action (e.g., delete a user).
2. Check if the action appears in an audit log.
3. If not, audit trail missing.

**Example**
- Admin deletes a user; no record of who did it or when.

**Tools**
- Admin log review

**Risk Rating**  
Critical

**Remediation**
- Implement immutable audit logs (e.g., write-once storage, blockchain, or AWS CloudTrail).
- Include all relevant details.

---

## 6. LOGS STORED LOCALLY WITHOUT CENTRALIZED AGGREGATION

**Description**  
Storing logs only on local servers makes them vulnerable to deletion by attackers who compromise the server, and prevents centralized monitoring.

**What to Look For**
- Logs stored only on the local filesystem.
- No forwarding to a SIEM or central log server.

**What to Ignore**
- Centralized log management with redundancy and tamper protection.

**How to Test with Burp Suite**
1. Check if logs are sent to an external system (e.g., via network monitoring or configuration review).
2. If logs are only on the local disk, vulnerable.

**Example**
- Application logs written to `/var/log/app.log` but not shipped elsewhere.

**Tools**
- Configuration review
- Network monitoring (if logs are sent via syslog)

**Risk Rating**  
High

**Remediation**
- Send logs to a centralized, secure log management system (SIEM).
- Use standards like syslog, Fluentd, or cloud-native log services.

---

## 7. NO INTEGRITY PROTECTION FOR LOGS (TAMPERING POSSIBLE)

**Description**  
Logs without integrity protection (e.g., HMAC, write‑once storage) can be modified or deleted by attackers to cover their tracks.

**What to Look For**
- Logs stored in plaintext, writable by the application user.
- No cryptographic hash chaining or digital signatures.

**What to Ignore**
- Logs with hash chaining, write‑once media, or blockchain.

**How to Test with Burp Suite**
1. If you have access, modify a log file (e.g., delete an entry).
2. If the system does not detect tampering, vulnerable.

**Example**
- Attacker compromises server, deletes failed login entries; no alert.

**Tools**
- File system access (if available)
- Log integrity checking tools

**Risk Rating**  
High

**Remediation**
- Use hash chaining or HMAC for log entries.
- Store logs on write‑once media (e.g., AWS S3 Object Lock).
- Monitor for log deletion or tampering.

---

## 8. INSUFFICIENT LOG RETENTION (LOGS DELETED TOO EARLY)

**Description**  
Logs retained for too short a period make incident investigation impossible after a breach is discovered.

**What to Look For**
- Logs deleted daily or weekly.
- Retention policy less than required by regulations (e.g., 90 days, 1 year).

**What to Ignore**
- Retention meeting legal and business requirements (typically 1 year for security logs).

**How to Test with Burp Suite**
1. Review log rotation configuration or ask administrators.
2. Check if logs older than a certain period are unavailable.

**Example**
- Logs kept for only 7 days; a breach discovered after 30 days cannot be investigated.

**Tools**
- Configuration review
- Policy review

**Risk Rating**  
Medium

**Remediation**
- Establish and enforce log retention policies (e.g., 1 year).
- Archive logs to long‑term storage.

---

## 9. NO REAL‑TIME ALERTING FOR CRITICAL EVENTS

**Description**  
Critical events (e.g., successful admin login from a new IP, multiple failed logins, privilege change) should trigger immediate alerts. Without alerting, attacks may go unnoticed.

**What to Look For**
- No alerts configured for high‑risk events.
- Alerts sent to logs only, not to security team.

**What to Ignore**
- Real‑time alerts via email, Slack, SIEM, or PagerDuty.

**How to Test with Burp Suite**
1. Trigger a critical event (e.g., failed admin login, privilege escalation).
2. Check if an alert is generated (email, ticket, etc.).
3. If not, missing alerting.

**Example**
- 10 failed logins on admin account, no notification.

**Tools**
- Manual trigger and observation
- Alert configuration review

**Risk Rating**  
Critical

**Remediation**
- Configure real‑time alerts for critical events.
- Integrate with incident response systems.

---

## 10. MISSING MONITORING FOR FAILED LOGIN THRESHOLDS (BRUTE FORCE)

**Description**  
Monitoring for multiple failed logins can detect brute force attacks. Without it, attacks may succeed before detection.

**What to Look For**
- No detection or alert when a user exceeds failed login threshold.
- No automatic response (e.g., temporary lockout or CAPTCHA).

**What to Ignore**
- Monitoring with alerting and automated response.

**How to Test with Burp Suite**
1. Send many failed login attempts for a single user (e.g., 10+).
2. Check if any alert is generated or if the incident is logged as suspicious.

**Example**
- 50 failed logins to admin account; no alert.

**Tools**
- Burp Intruder
- SIEM alert verification

**Risk Rating**  
High

**Remediation**
- Monitor for failed login thresholds (e.g., 5 failures in 5 minutes).
- Send alerts to security team.

---

## 11. NO DETECTION OF CREDENTIAL STUFFING PATTERNS

**Description**  
Credential stuffing attacks involve many login attempts with different usernames but a small set of passwords. Without detection, these attacks may succeed.

**What to Look For**
- No monitoring for multiple login attempts from the same IP across many accounts.
- No alert for successful logins from new IPs after many failures.

**What to Ignore**
- Anomaly detection for credential stuffing patterns.

**How to Test with Burp Suite**
1. Use a list of 20 usernames and one common password.
2. Attempt login from a single IP.
3. Check if any alert or rate limiting is triggered.

**Example**
- 20 login attempts with `Password123!`, no detection.

**Tools**
- Burp Intruder
- SIEM rule testing

**Risk Rating**  
High

**Remediation**
- Implement monitoring for credential stuffing patterns (e.g., high number of unique usernames from one IP).
- Use CAPTCHA after a threshold.

---

## 12. NO MONITORING FOR UNUSUAL GEOGRAPHIC ACCESS

**Description**  
Logins from unexpected geographic locations may indicate compromised accounts. Without monitoring, such incidents go unnoticed.

**What to Look For**
- No logging of source IP geolocation.
- No alert for logins from countries where the user never logs in.

**What to Ignore**
- Geolocation tracking and risk‑based alerts.

**How to Test with Burp Suite**
1. Use a VPN to simulate login from a different country.
2. Check if any alert or challenge (e.g., MFA) is triggered.
3. If not, vulnerable.

**Example**
- User logs in from Russia (usual location is US); no alert.

**Tools**
- VPN
- SIEM alert verification

**Risk Rating**  
High

**Remediation**
- Log and monitor geolocation of logins.
- Trigger alerts for anomalous locations.

---

## 13. NO ALERTS FOR CONCURRENT SESSIONS FROM MULTIPLE IPS

**Description**  
Concurrent sessions from multiple IPs (especially different geographies) may indicate session hijacking or credential sharing.

**What to Look For**
- No detection of a user being logged in from two different IPs simultaneously.
- No termination of old sessions or alert.

**What to Ignore**
- Monitoring and automated session termination.

**How to Test with Burp Suite**
1. Log in from two different browsers or devices.
2. Check if any alert is generated.
3. If not, vulnerable.

**Example**
- User’s session active from IP A and IP B simultaneously; no alert.

**Tools**
- Multiple browsers
- SIEM alert verification

**Risk Rating**  
High

**Remediation**
- Monitor for concurrent sessions.
- Terminate previous sessions or alert the user.

---

## 14. LOGS EXPOSED OR ACCESSIBLE TO UNAUTHORIZED USERS

**Description**  
Logs that are accessible to regular users or exposed via web endpoints can leak sensitive information and help attackers.

**What to Look For**
- Accessible log files (e.g., `/logs/`, `/debug.log`, `/var/log/`).
- Log viewing functionality available to low‑privileged users.

**What to Ignore**
- Logs stored securely, not web‑accessible, and access restricted.

**How to Test with Burp Suite**
1. Probe for common log paths: `/logs/`, `/log/`, `/debug.log`, `/error.log`, `/var/log/`.
2. If any log file is accessible, vulnerable.

**Example**
```http
GET /logs/application.log HTTP/1.1
```
Returns log contents.

**Tools**
- Dirb/Gobuster
- Burp Intruder with log file wordlist

**Risk Rating**  
Critical

**Remediation**
- Store logs outside the web root.
- Restrict access to log files via permissions and authentication.

---

## 15. SENSITIVE DATA LOGGED IN PLAINTEXT (PASSWORDS, TOKENS)

**Description**  
Logging passwords, session tokens, API keys, or PII in plaintext violates compliance and gives attackers valuable data if logs are compromised.

**What to Look For**
- Passwords or tokens appearing in log files.
- Logs that include credit card numbers or personal information.

**What to Ignore**
- Logs sanitized of sensitive data (e.g., redaction, masking).

**How to Test with Burp Suite**
1. If you have access to logs, search for `password`, `token`, `Authorization`, `credit_card`.
2. Trigger a login or API call and examine logs for credentials.

**Example**
```
2024-01-01 12:00:00 Login attempt: user=admin, password=secret123
```

**Tools**
- Log file review
- Manual search

**Risk Rating**  
Critical

**Remediation**
- Never log passwords, tokens, or sensitive data.
- Sanitize logs (e.g., mask passwords as `***`).

---

## 16. NO LOGGING OF API ACCESS (RATE LIMIT EXCEEDED, UNAUTHORIZED ATTEMPTS)

**Description**  
API endpoints should log access, especially unauthorized attempts, rate limit exceedances, and errors, to detect abuse.

**What to Look For**
- No logs for API calls.
- Unauthorized (401/403) requests not logged.
- Rate limit violations not logged.

**What to Ignore**
- Comprehensive API logging with request ID, user, endpoint, status, and timestamp.

**How to Test with Burp Suite**
1. Make several API calls, including some with invalid tokens.
2. Check logs (if accessible) for entries.
3. If no logs, vulnerable.

**Example**
- 401 errors are not recorded.

**Tools**
- Burp Repeater
- Log review

**Risk Rating**  
High

**Remediation**
- Log all API requests, especially failures.
- Include source IP, user, endpoint, method, status code.

---

## 17. MISSING LOGGING FOR FILE UPLOADS AND DOWNLOADS

**Description**  
File operations (upload, download, delete) should be logged to detect data exfiltration or malware uploads.

**What to Look For**
- No logs for file uploads (who, when, filename, size).
- No logs for file downloads (sensitive documents).

**What to Ignore**
- Detailed file operation logs with integrity checks.

**How to Test with Burp Suite**
1. Upload a file and note the details.
2. Check logs for the upload event.
3. If missing, vulnerable.

**Example**
- User uploads malicious file, no record.

**Tools**
- Burp Proxy
- Log review

**Risk Rating**  
High

**Remediation**
- Log all file operations with user, filename, timestamp, IP.

---

## 18. NO MONITORING FOR ABNORMAL TRAFFIC PATTERNS (DDOS, SCRAPING)

**Description**  
Abnormal traffic patterns (e.g., request bursts, high volume from a single IP) indicate DDoS, scraping, or brute force.

**What to Look For**
- No detection of request rate anomalies.
- No alert when traffic exceeds normal baseline.

**What to Ignore**
- Anomaly detection and automated rate limiting.

**How to Test with Burp Suite**
1. Use Turbo Intruder to send many requests quickly.
2. Check if any alert is triggered (e.g., email, log entry).
3. If not, monitoring missing.

**Example**
- 10,000 requests per minute from one IP; no alert.

**Tools**
- Turbo Intruder
- SIEM rule verification

**Risk Rating**  
High

**Remediation**
- Implement traffic anomaly detection.
- Alert on abnormal volume, burst rates.

---

## 19. LOGS WITHOUT TIMESTAMPS OR ACCURATE TIME SYNCHRONIZATION (NTP)

**Description**  
Logs without accurate timestamps make forensic analysis impossible. Inconsistent time across servers complicates correlation.

**What to Look For**
- Logs missing timestamps or using local time without timezone.
- Servers not synchronized via NTP.
- Timestamp drift across different systems.

**What to Ignore**
- Logs with UTC timestamps and NTP synchronization.

**How to Test with Burp Suite**
1. Check a log entry for timestamp.
2. Compare timestamps across different servers (if accessible).
3. Use `ntpdate` or check NTP configuration.

**Example**
- Log entry: `2024-01-01 12:00:00` without timezone.

**Tools**
- Log review
- NTP check command: `ntpq -p`

**Risk Rating**  
Medium

**Remediation**
- Use UTC timestamps in logs.
- Synchronize all systems with NTP.

---

## 20. NO LOGGING OF PASSWORD CHANGE AND PASSWORD RESET EVENTS

**Description**  
Password changes and resets should be logged to detect unauthorized modifications.

**What to Look For**
- No log when a user changes their password.
- No log when a password reset is requested or completed.

**What to Ignore**
- Detailed logs with user, timestamp, IP, and method (change vs reset).

**How to Test with Burp Suite**
1. Perform a password change and reset.
2. Check logs for these events.
3. If absent, vulnerable.

**Example**
- Attacker resets user’s password, no log entry.

**Tools**
- Log review

**Risk Rating**  
High

**Remediation**
- Log all password change and reset events with user, IP, timestamp.

---

## 21. NO MONITORING FOR FAILED MFA ATTEMPTS

**Description**  
Failed MFA attempts (e.g., wrong TOTP code) can indicate an attacker trying to bypass MFA.

**What to Look For**
- No logging of failed MFA attempts.
- No alert for multiple MFA failures.

**What to Ignore**
- Detailed MFA logs and threshold alerts.

**How to Test with Burp Suite**
1. Attempt MFA with wrong codes several times.
2. Check logs for entries.
3. If not, vulnerable.

**Example**
- 10 wrong TOTP codes for an account; no log.

**Tools**
- Burp Repeater
- Log review

**Risk Rating**  
High

**Remediation**
- Log all MFA attempts (success, failure, lockout).
- Alert on multiple failures.

---

## 22. NO ALERTING FOR SUSPICIOUS USER AGENT STRINGS

**Description**  
Unusual user agents (e.g., scanning tools, old browsers) can indicate automated attacks.

**What to Look For**
- No detection of known malicious user agents.
- No alert when requests from scanning tools (sqlmap, nuclei) are detected.

**What to Ignore**
- User agent analysis and alerting.

**How to Test with Burp Suite**
1. Set a suspicious user agent (e.g., `sqlmap/1.6`, `Nuclei/3.0`).
2. Send a request.
3. Check if any alert is triggered.

**Example**
- Request with `sqlmap/1.6` user agent is not logged as suspicious.

**Tools**
- Burp Repeater
- SIEM rule testing

**Risk Rating**  
Medium

**Remediation**
- Monitor and alert on known malicious user agents.
- Use behavioral detection, not just user agent.

---

## 23. NO MONITORING FOR API ABUSE (HIGH VOLUME, MALFORMED REQUESTS)

**Description**  
API abuse (e.g., parameter fuzzing, high volume of errors) should be detected to prevent exploitation.

**What to Look For**
- No monitoring for high error rates from a single IP.
- No alert for many requests with malformed parameters.

**What to Ignore**
- API abuse detection with rate limiting and alerting.

**How to Test with Burp Suite**
1. Send many malformed API requests (e.g., invalid JSON).
2. Check if an alert is generated.
3. If not, vulnerable.

**Example**
- 1000 requests with SQLi payloads, no alert.

**Tools**
- Burp Intruder
- SIEM log review

**Risk Rating**  
High

**Remediation**
- Monitor API endpoints for abnormal error rates, high volume, and payload patterns.
- Send alerts to security team.

---

## 24. INSUFFICIENT LOGGING OF THIRD-PARTY INTEGRATIONS

**Description**  
Third‑party services (payment gateways, SSO providers, webhooks) can be attack vectors. Lack of logging of their requests makes incidents hard to trace.

**What to Look For**
- No logging of requests received from third‑party APIs.
- No logging of responses sent to third parties.

**What to Ignore**
- Detailed logs of third‑party interactions, including signature validation.

**How to Test with Burp Suite**
1. Trigger a third‑party callback (e.g., payment webhook).
2. Check if the application logs the event.
3. If not, vulnerable.

**Example**
- Payment webhook with tampered amount is processed but not logged.

**Tools**
- Manual testing
- Log review

**Risk Rating**  
High

**Remediation**
- Log all requests from third‑party services (source IP, payload, result).

---

## 25. NO LOGGING OF DATA EXPORTS OR BULK OPERATIONS

**Description**  
Bulk data exports (e.g., CSV downloads, database dumps) should be logged to detect data exfiltration.

**What to Look For**
- No logs when a user exports data.
- No alert for large exports.

**What to Ignore**
- Detailed logs with user, number of records, timestamp, IP.

**How to Test with Burp Suite**
1. Perform a data export (e.g., report download).
2. Check logs for the event.
3. If absent, vulnerable.

**Example**
- User exports all customer records; no log entry.

**Tools**
- Log review

**Risk Rating**  
High

**Remediation**
- Log all data exports, including record count.
- Alert on unusually large exports.

---

## 26. LOGS NOT MONITORED OR REVIEWED (NO SIEM / SOC)

**Description**  
Even if logs are collected, without active monitoring (SIEM, SOC), attacks may go unnoticed for long periods.

**What to Look For**
- No security team reviewing logs.
- No automated correlation or alerting.

**What to Ignore**
- Active log monitoring with defined use cases and response.

**How to Test with Burp Suite**
1. Perform a malicious action (e.g., failed admin login).
2. Wait to see if any response occurs (e.g., email to security team).
3. If no response, logs likely not monitored.

**Example**
- Brute force attack succeeds, no investigation.

**Tools**
- Manual test
- Interviews

**Risk Rating**  
Critical

**Remediation**
- Implement a SIEM solution.
- Define monitoring rules and incident response procedures.

---

## 27. NO CORRELATION OF EVENTS ACROSS DIFFERENT SYSTEMS

**Description**  
Attackers often move across multiple systems. Without correlation, it is difficult to track the full attack chain.

**What to Look For**
- Logs stored in silos (web server, database, auth server).
- No common request ID or session ID across logs.

**What to Ignore**
- Centralized logging with correlation IDs.

**How to Test with Burp Suite**
1. Perform a multi‑step attack (e.g., login, then sensitive action).
2. Check if logs from different components can be correlated (e.g., via same session ID).
3. If not, correlation missing.

**Example**
- Web server log shows login; database log shows query; no way to link them.

**Tools**
- Log analysis
- Configuration review

**Risk Rating**  
High

**Remediation**
- Use correlation IDs (e.g., request ID) across all components.
- Centralize logs and enable correlation.

---

## 28. MISSING LOGS FOR SESSION MANAGEMENT EVENTS (LOGIN, LOGOUT, TIMEOUT)

**Description**  
Session events (login, logout, session expiry) help detect unusual activity patterns.

**What to Look For**
- No logs for logout events.
- No logs for session timeout.
- No logs for session token invalidation.

**What to Ignore**
- Comprehensive session event logging.

**How to Test with Burp Suite**
1. Log in, then log out.
2. Check logs for both events.
3. Wait for session timeout and check for log entry.

**Example**
- Logout action not recorded.

**Tools**
- Log review

**Risk Rating**  
Medium

**Remediation**
- Log all session events (create, destroy, timeout, logout) with user, IP, session ID.

---

## 29. NO LOGGING OF DATABASE QUERY EXECUTION (ESPECIALLY DELETE, UPDATE WITHOUT WHERE)

**Description**  
Dangerous database queries (e.g., `DELETE FROM users` without `WHERE`) should be logged to detect data loss or insider threats.

**What to Look For**
- No logging of SQL queries.
- No alert for queries affecting many rows.

**What to Ignore**
- Database audit logging for sensitive operations.

**How to Test with Burp Suite**
1. If you have SQL injection, execute a dangerous query (e.g., `UPDATE` without `WHERE`).
2. Check if the query is logged.
3. If not, vulnerable.

**Example**
- `DELETE FROM users` executed, no log.

**Tools**
- Database audit log review
- SQL injection testing

**Risk Rating**  
High

**Remediation**
- Enable database audit logging for DML (INSERT, UPDATE, DELETE) and DDL.
- Log queries that affect many rows.

---

## 30. LACK OF INCIDENT RESPONSE PLAN BASED ON LOG ANALYSIS

**Description**  
Even with logging, without a defined incident response plan, alerts may be ignored or mishandled.

**What to Look For**
- No documented incident response plan.
- No assigned team to respond to alerts.
- No playbooks for common attack patterns.

**What to Ignore**
- Documented, tested, and practiced incident response.

**How to Test with Burp Suite**
1. Trigger an alert (e.g., multiple failed logins).
2. Observe if any response occurs (ticket creation, callout).
3. If no action, IR plan likely missing.

**Example**
- Brute force alert generated but no one investigates.

**Tools**
- Manual test
- Policy review

**Risk Rating**  
Critical

**Remediation**
- Develop and test an incident response plan.
- Assign responsibilities and run tabletop exercises.

---

## ✅ **SUMMARY**

Security Logging and Monitoring Failures (A09) prevent organisations from detecting, investigating, and responding to attacks. Without adequate logs and monitoring, breaches may go unnoticed for months. This guide covers 30 logging and monitoring deficiencies.

### **Key Testing Areas Summary**

| Failure Type | Key Indicators | Risk |
|--------------|----------------|------|
| Auth Event Logging | No failed login logs | High |
| Privilege Change Logging | No audit trail | High |
| Sensitive Data Access Logging | No record of data views | High |
| Config Change Logging | No logs | High |
| Admin Action Audit | No audit trail | Critical |
| Local Logs Only | No central aggregation | High |
| Log Integrity | Logs can be tampered | High |
| Log Retention | Logs deleted too soon | Medium |
| Real‑time Alerting | No alerts for critical events | Critical |
| Brute Force Monitoring | No threshold alerts | High |
| Credential Stuffing Detection | No pattern detection | High |
| Geographic Monitoring | No location alerts | High |
| Concurrent Sessions | No multi‑IP detection | High |
| Exposed Logs | Log files accessible | Critical |
| Sensitive Data in Logs | Passwords logged | Critical |
| API Logging | No API call logs | High |
| File Operation Logging | No upload/download logs | High |
| Traffic Anomaly Detection | No DDoS monitoring | High |
| Timestamps | Missing or unsynchronized | Medium |
| Password Change Logging | No logs | High |
| MFA Failure Monitoring | No MFA logs | High |
| Suspicious User Agents | No detection | Medium |
| API Abuse Monitoring | No anomaly detection | High |
| Third‑Party Integration Logging | No webhook logs | High |
| Data Export Logging | No bulk export logs | High |
| Log Monitoring (SIEM) | No active review | Critical |
| Event Correlation | No cross‑system IDs | High |
| Session Event Logging | Missing logout logs | Medium |
| Database Query Logging | No dangerous query logs | High |
| Incident Response Plan | No response process | Critical |

### **Pro Tips for Testing Logging & Monitoring**
1. **Think like an attacker** – what actions would you want to hide? Test if those are logged.
2. **Attempt to evade detection** – after malicious actions, check if any alert or log entry exists.
3. **Review log retention** – ask how long logs are kept and if they are backed up.
4. **Check for sensitive data in logs** – search for keywords like `password`, `token`, `credit_card`.
5. **Simulate attacks** – brute force, privilege escalation, data exfiltration – and see if they trigger alerts.
6. **Interview operations team** – understand their monitoring and incident response process.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
