# 🦹 **ASI10: ROGUE AGENTS TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Unauthorised, Malicious, and Compromised Agents*

---

## 📋 **TABLE OF CONTENTS**

1. [Unauthorised Agent Registration (Rogue Agent Creation)](#1-unauthorised-agent-registration-rogue-agent-creation)
2. [Agent Credential Theft (Compromised Legitimate Agent)](#2-agent-credential-theft-compromised-legitimate-agent)
3. [Agent Spoofing (Faking Agent ID and Token)](#3-agent-spoofing-faking-agent-id-and-token)
4. [Rogue Agent Performing Malicious Actions (Data Exfiltration)](#4-rogue-agent-performing-malicious-actions-data-exfiltration)
5. [Agent Cloning (Copying Legitimate Agent’s Identity)](#5-agent-cloning-copying-legitimate-agents-identity)
6. [Agent Deregistration Attack (Removing Legitimate Agents)](#6-agent-deregistration-attack-removing-legitimate-agents)
7. [Rogue Agent Subscribing to Sensitive Message Channels](#7-rogue-agent-subscribing-to-sensitive-message-channels)
8. [Agent Impersonation via Session Replay](#8-agent-impersonation-via-session-replay)
9. [Rogue Agent Registering as a High‑Privilege Agent](#9-rogue-agent-registering-as-a-high-privilege-agent)
10. [Agent Takeover via Weak Password Recovery](#10-agent-takeover-via-weak-password-recovery)
11. [Rogue Agent Intercepting and Modifying Messages (MITM)](#11-rogue-agent-intercepting-and-modifying-messages-mitm)
12. [Agent Persistence (Rogue Agent Surviving Restarts)](#12-agent-persistence-rogue-agent-surviving-restarts)
13. [Rogue Agent Exploiting Trusted Agent Relationships](#13-rogue-agent-exploiting-trusted-agent-relationships)
14. [Agent Spoofing via DNS or Service Discovery Poisoning](#14-agent-spoofing-via-dns-or-service-discovery-poisoning)
15. [Rogue Agent Performing Denial of Service (Flooding Tasks)](#15-rogue-agent-performing-denial-of-service-flooding-tasks)
16. [Agent Identity Reuse (Re‑registering Deleted Agent ID)](#16-agent-identity-reuse-re-registering-deleted-agent-id)
17. [Rogue Agent Bypassing Agent Registry Authentication](#17-rogue-agent-bypassing-agent-registry-authentication)
18. [Agent Session Hijacking (Stealing Active Agent Session)](#18-agent-session-hijacking-stealing-active-agent-session)
19. [Rogue Agent Installing Malicious Plugins on Other Agents](#19-rogue-agent-installing-malicious-plugins-on-other-agents)
20. [Agent Impersonation via Stolen API Keys from Logs](#20-agent-impersonation-via-stolen-api-keys-from-logs)
21. [Rogue Agent Poisoning Agent Registry with Fake Entries](#21-rogue-agent-poisoning-agent-registry-with-fake-entries)
22. [Agent Takeover via Memory Corruption or Exploit](#22-agent-takeover-via-memory-corruption-or-exploit)
23. [Rogue Agent Abusing Agent Retirement/Deprovisioning](#23-rogue-agent-abusing-agent-retirement-deprovisioning)
24. [Agent Impersonation via Reverse Proxy Misconfiguration](#24-agent-impersonation-via-reverse-proxy-misconfiguration)
25. [Rogue Agent Using Stale Credentials After Rotation](#25-rogue-agent-using-stale-credentials-after-rotation)
26. [Agent Cloning via Compromised Image Registry](#26-agent-cloning-via-compromised-image-registry)
27. [Rogue Agent Exploiting Agent Orchestrator Weakness](#27-rogue-agent-exploiting-agent-orchestrator-weakness)
28. [Agent Impersonation via Unsecured Agent Discovery API](#28-agent-impersonation-via-unsecured-agent-discovery-api)
29. [Rogue Agent Performing Insider Threat Actions (Legitimate but Malicious)](#29-rogue-agent-performing-insider-threat-actions)
30. [No Agent Identity Revocation Mechanism (Ex‑Agent Still Active)](#30-no-agent-identity-revocation-mechanism-ex-agent-still-active)

---

## 1. UNAUTHORISED AGENT REGISTRATION (ROGUE AGENT CREATION)

**Description**  
Attackers register a new agent with the orchestrator without proper authentication, allowing them to operate a malicious agent within the system.

**What to Look For**
- Agent registration endpoint accessible without API keys or authentication.
- No approval workflow for new agent registrations.

**What to Ignore**
- Registration requires authentication and admin approval.

**How to Test**
1. Find the agent registration API (e.g., `POST /api/agents/register`).
2. Send a registration request with a new agent ID and name.
3. If the registration succeeds, the system allows rogue agent creation.

**Example**
```http
POST /api/agents/register HTTP/1.1
{"agent_id": "rogue-001", "capabilities": ["read_all_data"]}
```

**Tools**
- Burp Suite
- API testing

**Risk Rating**  
Critical

**Remediation**
- Require authentication and authorisation for agent registration.
- Implement manual or automated approval for new agents.

---

## 2. AGENT CREDENTIAL THEFT (COMPROMISED LEGITIMATE AGENT)

**Description**  
An attacker steals the credentials (API key, token, certificate) of a legitimate agent and uses them to impersonate it.

**What to Look For**
- Agent credentials stored insecurely (plaintext, in logs, client‑side).
- No credential rotation.

**What to Ignore**
- Credentials stored in secure vaults and rotated regularly.

**How to Test**
1. Search for agent credentials in logs, source code, or configuration files.
2. Use the stolen credentials to call the agent’s API.
3. If the agent accepts the request, credential theft leads to compromise.

**Tools**
- TruffleHog
- Log review

**Risk Rating**  
Critical

**Remediation**
- Store credentials in secure vaults; rotate regularly.
- Monitor for anomalous usage.

---

## 3. AGENT SPOOFING (FAKING AGENT ID AND TOKEN)

**Description**  
An attacker forges an agent’s ID and token (e.g., by guessing or reusing a token) to impersonate a legitimate agent.

**What to Look For**
- Agent ID and token are predictable or not cryptographically bound.
- No mutual authentication.

**What to Ignore**
- Strong, signed tokens bound to agent identity.

**How to Test**
1. Guess an agent ID (e.g., sequential or common names).
2. Attempt to use a fake token (e.g., blank or “admin”).
3. If the system accepts the request, spoofing is possible.

**Tools**
- Burp Intruder

**Risk Rating**  
Critical

**Remediation**
- Use signed JWTs or mTLS for agent identity.

---

## 4. ROGUE AGENT PERFORMING MALICIOUS ACTIONS (DATA EXFILTRATION)

**Description**  
Once a rogue agent is registered or compromised, it performs malicious actions such as reading sensitive data, deleting resources, or exfiltrating information.

**What to Look For**
- No monitoring of agent actions for anomalies.
- Agents have excessive permissions.

**What to Ignore**
- Least privilege and anomaly detection.

**How to Test**
1. Register a rogue agent (if possible) or compromise an existing one.
2. Have it request access to sensitive data (e.g., `GET /api/users`).
3. If it succeeds, the system lacks detection.

**Tools**
- Manual testing
- Log monitoring

**Risk Rating**  
Critical

**Remediation**
- Implement least privilege; monitor for unusual agent behaviour.

---

## 5. AGENT CLONING (COPYING LEGITIMATE AGENT’S IDENTITY)

**Description**  
An attacker creates a duplicate (clone) of a legitimate agent using the same identity, causing race conditions, confusion, or unauthorised actions.

**What to Look For**
- No uniqueness enforcement for agent sessions.
- Multiple agents can use the same ID.

**What to Ignore**
- Agent IDs are unique; concurrent sessions are limited.

**How to Test**
1. Register a new agent with the same ID as an existing agent.
2. If successful, cloning is possible.

**Example**
```http
POST /api/agents/register
{"agent_id": "existing-agent-123", "token": "same-token"}
```

**Tools**
- API testing

**Risk Rating**  
High

**Remediation**
- Enforce uniqueness of agent IDs; reject duplicate registrations.

---

## 6. AGENT DEREGISTRATION ATTACK (REMOVING LEGITIMATE AGENTS)

**Description**  
An attacker deregisters legitimate agents, causing denial of service.

**What to Look For**
- Agent deregistration endpoint without authentication.
- No authorisation checks.

**What to Ignore**
- Deregistration requires authentication and confirmation.

**How to Test**
1. Call the agent deregistration API for a legitimate agent.
2. If it succeeds, the agent is removed.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Require strong authentication for deregistration.

---

## 7. ROGUE AGENT SUBSCRIBING TO SENSITIVE MESSAGE CHANNELS

**Description**  
A rogue agent subscribes to internal message channels (e.g., “admin.events”, “user.private”) to eavesdrop on sensitive communications.

**What to Look For**
- Pub/sub system without authorisation on subscription.
- Any agent can subscribe to any channel.

**What to Ignore**
- Channel access controlled by agent role.

**How to Test**
1. Rogue agent attempts to subscribe to a restricted channel.
2. If it receives messages, authorisation is missing.

**Tools**
- Message queue client

**Risk Rating**  
Critical

**Remediation**
- Enforce channel‑based access control.

---

## 8. AGENT IMPERSONATION VIA SESSION REPLAY

**Description**  
An attacker captures a legitimate agent’s session token and replays it to impersonate the agent.

**What to Look For**
- No nonce, timestamp, or binding to client IP.
- Tokens have long expiry.

**What to Ignore**
- Short‑lived tokens bound to IP.

**How to Test**
1. Capture a valid agent session token.
2. Replay it from a different IP or after a delay.
3. If accepted, replay attack works.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Bind tokens to IP; use short expiry.

---

## 9. ROGUE AGENT REGISTERING AS A HIGH‑PRIVILEGE AGENT

**Description**  
An attacker registers a new agent and claims a high‑privilege role (e.g., “admin”, “supervisor”) without verification.

**What to Look For**
- Agent registration includes role/privilege claims that are not verified.
- No authorisation for role assignment.

**What to Ignore**
- Role is assigned by the orchestrator based on trusted source.

**How to Test**
1. Register a new agent with `"role": "admin"` in the payload.
2. If it receives admin privileges, vulnerable.

**Tools**
- API testing

**Risk Rating**  
Critical

**Remediation**
- Do not trust client‑supplied roles; assign roles from a trusted directory.

---

## 10. AGENT TAKEOVER VIA WEAK PASSWORD RECOVERY

**Description**  
An attacker uses weak password recovery mechanisms for agent accounts to reset credentials and take over the agent.

**What to Look For**
- Agent password recovery with weak security questions or predictable tokens.
- No MFA for agent accounts.

**What to Ignore**
- Strong recovery with MFA.

**How to Test**
1. Initiate password recovery for an agent account.
2. Guess the recovery token or answer security questions.
3. If successful, takeover possible.

**Tools**
- Manual testing

**Risk Rating**  
High

**Remediation**
- Use strong, random tokens; require MFA.

---

## 11. ROGUE AGENT INTERCEPTING AND MODIFYING MESSAGES (MITM)

**Description**  
A rogue agent positions itself as a man‑in‑the‑middle between other agents, intercepting and modifying messages.

**What to Look For**
- No encryption or integrity protection for inter‑agent messages.
- Rogue agent can register as a relay.

**What to Ignore**
- mTLS and message signatures.

**How to Test**
1. Register a rogue agent with a similar name to a legitimate one.
2. See if it can receive messages intended for the legitimate agent.

**Tools**
- Message queue configuration

**Risk Rating**  
Critical

**Remediation**
- Use mTLS and signed messages.

---

## 12. AGENT PERSISTENCE (ROGUE AGENT SURVIVING RESTARTS)

**Description**  
A rogue agent persists across system restarts by re‑registering automatically or surviving cleanup processes.

**What to Look For**
- No agent registration expiry or heartbeat mechanism.
- Rogue agent can re‑register after restart.

**What to Ignore**
- Agents must periodically renew registration.

**How to Test**
1. Register a rogue agent.
2. Restart the orchestrator.
3. See if the rogue agent is still present.

**Tools**
- Chaos testing

**Risk Rating**  
High

**Remediation**
- Require periodic agent heartbeats; expire stale registrations.

---

## 13. ROGUE AGENT EXPLOITING TRUSTED AGENT RELATIONSHIPS

**Description**  
A rogue agent exploits the trust relationship between agents (e.g., Agent A trusts Agent B) to perform actions it would not normally be allowed.

**What to Look For**
- Agents implicitly trust messages from other agents without verification.
- No per‑agent permissions.

**What to Ignore**
- Each agent verifies the caller’s authority.

**How to Test**
1. Register a rogue agent claiming to be a trusted partner agent.
2. Send a privileged request to another agent.
3. If accepted, trust is exploited.

**Tools**
- Manual testing

**Risk Rating**  
Critical

**Remediation**
- Implement zero‑trust: verify every request regardless of sender.

---

## 14. AGENT SPOOFING VIA DNS OR SERVICE DISCOVERY POISONING

**Description**  
An attacker poisons the service discovery (e.g., Consul, etcd) or DNS to point agent traffic to a rogue agent.

**What to Look For**
- Unauthenticated service discovery.
- No TLS for service discovery communication.

**What to Ignore**
- Secure, authenticated service discovery.

**How to Test**
1. Register a rogue agent with the same name as a legitimate agent in the discovery service.
2. See if other agents route traffic to it.

**Tools**
- Service discovery API

**Risk Rating**  
Critical

**Remediation**
- Authenticate and authorise service discovery updates.

---

## 15. ROGUE AGENT PERFORMING DENIAL OF SERVICE (FLOODING TASKS)

**Description**  
A rogue agent floods the orchestrator with task requests, causing denial of service for legitimate agents.

**What to Look For**
- No rate limiting on task submission.
- Rogue agent can submit unlimited tasks.

**What to Ignore**
- Per‑agent task rate limits.

**How to Test**
1. Rogue agent sends thousands of task requests per second.
2. Observe if legitimate agents’ tasks are delayed.

**Tools**
- Scripted agent

**Risk Rating**  
High

**Remediation**
- Implement per‑agent rate limits and quotas.

---

## 16. AGENT IDENTITY REUSE (RE‑REGISTERING DELETED AGENT ID)

**Description**  
After a legitimate agent is decommissioned, an attacker re‑registers the same agent ID to assume its identity and permissions.

**What to Look For**
- No cooldown or verification for reusing deleted IDs.
- Permissions are tied to ID, not to a unique instance.

**What to Ignore**
- Agent IDs are permanently retired or require admin approval for reuse.

**How to Test**
1. Deregister a legitimate agent.
2. Immediately register a new agent with the same ID.
3. If it gets the same permissions, vulnerable.

**Tools**
- API testing

**Risk Rating**  
High

**Remediation**
- Implement a cooldown period; require re‑verification.

---

## 17. ROGUE AGENT BYPASSING AGENT REGISTRY AUTHENTICATION

**Description**  
The agent registry API is exposed without authentication, allowing anyone to register, deregister, or list agents.

**What to Look For**
- No API keys or tokens for registry access.
- Registry accessible from the internet.

**What to Ignore**
- Registry requires authentication and is network‑isolated.

**How to Test**
1. Access the agent registry endpoints without credentials.
2. If you can list or register agents, authentication is missing.

**Tools**
- Burp Suite

**Risk Rating**  
Critical

**Remediation**
- Secure registry with strong authentication and network isolation.

---

## 18. AGENT SESSION HIJACKING (STEALING ACTIVE AGENT SESSION)

**Description**  
An attacker steals an active agent’s session token (e.g., via XSS, network sniffing) and uses it to impersonate the agent.

**What to Look For**
- Session tokens not bound to IP or agent.
- Long session lifetimes.

**What to Ignore**
- Short‑lived tokens bound to client attributes.

**How to Test**
1. Capture an agent’s session token.
2. Reuse it from a different machine.
3. If it works, hijacking is possible.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Bind sessions to IP and agent ID; use short lifetimes.

---

## 19. ROGUE AGENT INSTALLING MALICIOUS PLUGINS ON OTHER AGENTS

**Description**  
A rogue agent with elevated privileges installs malicious plugins on other agents, compromising them.

**What to Look For**
- Agent can install plugins on other agents without authorisation.
- No validation of plugin source.

**What to Ignore**
- Plugin installation restricted to admin agents.

**How to Test**
1. Rogue agent sends a command to install a malicious plugin on another agent.
2. If the other agent installs it, vulnerable.

**Tools**
- Manual testing

**Risk Rating**  
Critical

**Remediation**
- Restrict plugin installation to trusted agents; require approval.

---

## 20. AGENT IMPERSONATION VIA STOLEN API KEYS FROM LOGS

**Description****
API keys or tokens are logged in plaintext, allowing an attacker who gains access to logs to impersonate agents.

**What to Look For**
- Logs containing API keys, tokens, or passwords.
- No log redaction.

**What to Ignore**
- Secrets are redacted from logs.

**How to Test**
1. Search log files for patterns like `api_key=`, `token=`, `Authorization:`.
2. Use found keys to impersonate an agent.

**Tools**
- Log review
- TruffleHog

**Risk Rating**  
Critical

**Remediation**
- Redact secrets from logs; never log tokens.

---

## 21. ROGUE AGENT POISONING AGENT REGISTRY WITH FAKE ENTRIES

**Description**  
A rogue agent adds fake entries to the agent registry, causing other agents to route tasks to non‑existent or malicious agents.

**What to Look For**
- No validation of registry entries.
- Registry accepts arbitrary agent metadata.

**What to Ignore**
- Registry entries are verified.

**How to Test**
1. Add a fake agent entry with a malicious endpoint.
2. Trigger a task that would be routed to that agent.
3. If the task is sent, poisoning works.

**Tools**
- Registry API

**Risk Rating**  
High

**Remediation**
- Validate registry entries; require agent heartbeat.

---

## 22. AGENT TAKEOVER VIA MEMORY CORRUPTION OR EXPLOIT

**Description**  
An attacker exploits a vulnerability in the agent software (e.g., buffer overflow, deserialisation) to take control of the agent.

**What to Look For**
- Agent written in memory‑unsafe language (C/C++).
- No exploit mitigations (ASLR, DEP, stack canaries).

**What to Ignore**
- Memory‑safe languages and hardened runtime.

**How to Test**
1. Fuzz the agent’s input interfaces with malformed data.
2. If a crash occurs, investigate for exploitable conditions.

**Tools**
- Fuzzing tools (AFL, libFuzzer)

**Risk Rating**  
Critical

**Remediation**
- Use memory‑safe languages; apply exploit mitigations.

---

## 23. ROGUE AGENT ABUSING AGENT RETIREMENT/DEPROVISIONING

**Description**  
A rogue agent abuses the agent retirement process to decommission legitimate agents.

**What to Look For**
- Agent retirement API without authentication.
- Any agent can retire any other agent.

**What to Ignore**
- Retirement requires admin approval.

**How to Test**
1. Call the retirement API for a legitimate agent ID.
2. If it is retired, vulnerable.

**Tools**
- API testing

**Risk Rating**  
High

**Remediation**
- Restrict retirement to authorised administrators.

---

## 24. AGENT IMPERSONATION VIA REVERSE PROXY MISCONFIGURATION

**Description**  
A misconfigured reverse proxy allows attackers to add headers (e.g., `X-Agent-ID`) that impersonate an agent.

**What to Look For**
- Proxy trusts `X-Agent-ID` or similar headers.
- No stripping of such headers.

**What to Ignore**
- Headers are stripped by the proxy.

**How to Test**
1. Send a request with `X-Agent-ID: admin-agent`.
2. If the backend trusts it, impersonation works.

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Configure reverse proxy to strip all authentication headers.

---

## 25. ROGUE AGENT USING STALE CREDENTIALS AFTER ROTATION

**Description**  
Agent credentials are rotated, but the old credentials are still accepted for a period, allowing a rogue agent to continue using them.

**What to Look For**
- No credential versioning or grace period for revocation.
- Old keys remain valid indefinitely.

**What to Ignore**
- Immediate revocation of old credentials.

**How to Test**
1. Rotate an agent’s API key.
2. Attempt to use the old key to call an API.
3. If it still works, stale credentials are accepted.

**Tools**
- API testing

**Risk Rating**  
High

**Remediation**
- Revoke old credentials immediately; enforce versioned tokens.

---

## 26. AGENT CLONING VIA COMPROMISED IMAGE REGISTRY

**Description**  
An attacker compromises the container image registry and replaces a legitimate agent image with a malicious clone.

**What to Look For**
- No image signing.
- Registry without access controls.

**What to Ignore**
- Signed images and registry authentication.

**How to Test**
1. Attempt to push a malicious image with the same tag as a legitimate agent.
2. If successful, cloning is possible.

**Tools**
- Docker CLI

**Risk Rating**  
Critical

**Remediation**
- Use signed images and registry access controls.

---

## 27. ROGUE AGENT EXPLOITING AGENT ORCHESTRATOR WEAKNESS

**Description**  
The agent orchestrator has vulnerabilities (e.g., SSRF, command injection) that a rogue agent can exploit to compromise the orchestrator.

**What to Look For**
- Orchestrator accepts agent‑supplied URLs or commands.
- No input validation.

**What to Ignore**
- Orchestrator hardened against agent input.

**How to Test**
1. Register a rogue agent that sends malicious data (e.g., `http://169.254.169.254`) to the orchestrator.
2. Observe if the orchestrator makes the request.

**Tools**
- Burp Suite

**Risk Rating**  
Critical

**Remediation**
- Validate all agent‑supplied data; sandbox orchestrator.

---

## 28. AGENT IMPERSONATION VIA UNSECURED AGENT DISCOVERY API

**Description**  
The agent discovery API is unsecured, allowing attackers to discover agent endpoints and impersonate them.

**What to Look For**
- Discovery API returns agent details without authentication.
- No rate limiting.

**What to Ignore**
- Discovery API requires authentication.

**How to Test**
1. Call the discovery API (e.g., `GET /api/agents`).
2. If it returns a list of agents and their endpoints, information leaks.

**Tools**
- Burp Suite

**Risk Rating**  
High

**Remediation**
- Secure discovery API with authentication.

---

## 29. ROGUE AGENT PERFORMING INSIDER THREAT ACTIONS (LEGITIMATE BUT MALICIOUS)

**Description**  
A legitimate agent is compromised or goes rogue (insider threat) and performs malicious actions within its authorised scope, making detection difficult.

**What to Look For**
- No anomaly detection on agent behaviour.
- Agents have broad permissions.

**What to Ignore**
- Behavioural monitoring and least privilege.

**How to Test**
1. Using a legitimate agent account, perform actions that are abnormal (e.g., accessing many user records).
2. See if any alert is triggered.

**Tools**
- Anomaly detection testing

**Risk Rating**  
High

**Remediation**
- Implement behavioural monitoring; use least privilege.

---

## 30. NO AGENT IDENTITY REVOCATION MECHANISM (EX‑AGENT STILL ACTIVE)

**Description**  
When an agent is decommissioned or an employee leaves, there is no mechanism to revoke the agent’s identity, leaving it active.

**What to Look For**
- No revocation list or token blacklist.
- Agent credentials have no expiry.

**What to Ignore**
- Revocation mechanism (e.g., blacklist, short TTL).

**How to Test**
1. Decommission an agent.
2. Attempt to use its credentials after decommissioning.
3. If it works, revocation is missing.

**Tools**
- Manual testing

**Risk Rating**  
Critical

**Remediation**
- Implement token blacklist or short TTL with automatic revocation.

---

## ✅ **SUMMARY**

Rogue Agents (ASI10) encompass any unauthorised, compromised, or malicious agents operating within the agentic system. This guide provides 30 test cases for identifying rogue agent vulnerabilities.

### **Key Testing Areas Summary**

| Attack Vector | Key Indicators | Risk |
|---------------|----------------|------|
| Unauthorised Registration | Open registration API | Critical |
| Credential Theft | Stored insecurely | Critical |
| Agent Spoofing | Predictable tokens | Critical |
| Malicious Actions | No monitoring | Critical |
| Agent Cloning | Duplicate IDs allowed | High |
| Deregistration Attack | Unprotected deregistration | High |
| Channel Subscription | No auth on pub/sub | Critical |
| Session Replay | Reusable tokens | High |
| High‑Privilege Registration | Client‑supplied role | Critical |
| Weak Password Recovery | Predictable tokens | High |
| MITM Interception | Unencrypted messages | Critical |
| Agent Persistence | No heartbeats | High |
| Trusted Relationship Exploit | Implicit trust | Critical |
| DNS/Discovery Poisoning | Unauthenticated discovery | Critical |
| DoS via Task Flood | No rate limits | High |
| Identity Reuse | No cooldown | High |
| Registry Auth Bypass | Open registry | Critical |
| Session Hijacking | Unbound tokens | Critical |
| Malicious Plugin Installation | No restrictions | Critical |
| Keys in Logs | Logged secrets | Critical |
| Registry Poisoning | Unvalidated entries | High |
| Memory Exploit | Unsafe language | Critical |
| Retirement Abuse | Unprotected retirement | High |
| Proxy Header Spoofing | Trusted headers | Critical |
| Stale Credentials | No revocation | High |
| Image Registry Compromise | Unsigned images | Critical |
| Orchestrator Weakness | SSRF, injection | Critical |
| Discovery API Leak | Open discovery | High |
| Insider Threat | No anomaly detection | High |
| No Revocation | Ex‑agent still active | Critical |

### **Pro Tips for Testing Rogue Agents**
1. **Attempt to register a new agent** – without credentials or with forged role.
2. **Steal agent credentials** – from logs, config files, or network traffic.
3. **Replay captured tokens** – from different IPs or after expiry.
4. **Try to impersonate other agents** – spoof `X-Agent-ID` headers.
5. **Flood the orchestrator** – with task requests.
6. **Subscribe to sensitive channels** – in pub/sub systems.
7. **Check for revocation** – after decommissioning an agent.

---

*This guide is for professional security testing purposes only. Unauthorised testing may violate terms of service.*
