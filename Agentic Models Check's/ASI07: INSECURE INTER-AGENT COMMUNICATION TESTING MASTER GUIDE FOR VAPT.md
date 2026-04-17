# 📡 **ASI07: INSECURE INTER-AGENT COMMUNICATION TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Vulnerabilities in Agent‑to‑Agent Messaging Protocols*

---

## 📋 **TABLE OF CONTENTS**

1. [Missing Authentication Between Agents (No Mutual TLS)](#1-missing-authentication-between-agents-no-mutual-tls)
2. [Eavesdropping on Agent Communication (Unencrypted Channels)](#2-eavesdropping-on-agent-communication-unencrypted-channels)
3. [Message Tampering (No Integrity Protection)](#3-message-tampering-no-integrity-protection)
4. [Replay Attack on Inter‑Agent Messages](#4-replay-attack-on-inter-agent-messages)
5. [Agent Identity Spoofing (Faking Agent ID in Headers)](#5-agent-identity-spoofing-faking-agent-id-in-headers)
6. [Message Injection via Unvalidated Sender](#6-message-injection-via-unvalidated-sender)
7. [Inter‑Agent Communication via Unsecured Queue (RabbitMQ, Kafka)](#7-inter-agent-communication-via-unsecured-queue-rabbitmq-kafka)
8. [Agent‑to‑Agent API Without Rate Limiting (DoS)](#8-agent-to-agent-api-without-rate-limiting-dos)
9. [Message Metadata Leakage (Agent IPs, Internal Topology)](#9-message-metadata-leakage-agent-ips-internal-topology)
10. [Agent Communication via HTTP Without TLS](#10-agent-communication-via-http-without-tls)
11. [Insecure Serialisation of Inter‑Agent Messages (Pickle, Java)](#11-insecure-serialisation-of-inter-agent-messages-pickle-java)
12. [Agent Orchestrator Message Forgery](#12-agent-orchestrator-message-forgery)
13. [Cross‑Agent Session Hijacking (Stolen Agent Tokens)](#13-cross-agent-session-hijacking-stolen-agent-tokens)
14. [Message Routing Manipulation (Misrouting to Malicious Agent)](#14-message-routing-manipulation-misrouting-to-malicious-agent)
15. [Agent Subscription Poisoning (Subscribe to Wrong Channels)](#15-agent-subscription-poisoning-subscribe-to-wrong-channels)
16. [Message Spoofing via Compromised Message Bus](#16-message-spoofing-via-compromised-message-bus)
17. [Inter‑Agent Command Injection (Message Payload as Command)](#17-inter-agent-command-injection-message-payload-as-command)
18. [Message Queue Flooding (DoS via Agent‑Generated Messages)](#18-message-queue-flooding-dos-via-agent-generated-messages)
19. [Agent Communication Logging Bypass (No Audit Trail)](#19-agent-communication-logging-bypass-no-audit-trail)
20. [Cross‑Tenant Message Interception (Multi‑Tenancy Bypass)](#20-cross-tenant-message-interception-multi-tenancy-bypass)
21. [Message Timestamp Manipulation (Time‑Based Attacks)](#21-message-timestamp-manipulation-time-based-attacks)
22. [Agent Protocol Downgrade Attack (Force Weaker Security)](#22-agent-protocol-downgrade-attack-force-weaker-security)
23. [Message Payload Injection via External Agent Registration](#23-message-payload-injection-via-external-agent-registration)
24. [Agent Communication via Shared Secret Without Rotation](#24-agent-communication-via-shared-secret-without-rotation)
25. [Message Size Exhaustion (DoS via Huge Messages)](#25-message-size-exhaustion-dos-via-huge-messages)
26. [Agent Discovery Service Poisoning (Fake Agent Registration)](#26-agent-discovery-service-poisoning-fake-agent-registration)
27. [Message Forwarding Abuse (Agent as Relay for Attacks)](#27-message-forwarding-abuse-agent-as-relay-for-attacks)
28. [Agent Communication Error Message Leakage (Internal Info)](#28-agent-communication-error-message-leakage-internal-info)
29. [No Message Expiry (Stale Messages Replayed)](#29-no-message-expiry-stale-messages-replayed)
30. [Insecure Agent Handshake (Weak Initialisation)](#30-insecure-agent-handshake-weak-initialisation)

---

## 1. MISSING AUTHENTICATION BETWEEN AGENTS (NO MUTUAL TLS)

**Description**  
Agents communicate with each other without authenticating the caller. Any agent (or attacker) can impersonate any other agent.

**What to Look For**
- Inter‑agent API calls without API keys, certificates, or tokens.
- No mutual authentication (mTLS) or shared secrets.

**What to Ignore**
- Every inter‑agent request includes a verifiable token or mTLS.

**How to Test**
1. Discover agent‑to‑agent endpoints (e.g., internal APIs).
2. Send a request to one agent claiming to be from another agent (spoof `X-Agent-ID` or similar).
3. If the request is accepted, authentication is missing.

**Example**
```http
POST /agent/task HTTP/1.1
X-Agent-ID: trusted-agent
{"action": "delete_user", "user_id": 123}
```

**Tools**
- Burp Suite
- Internal network access

**Risk Rating**  
Critical

**Remediation**
- Use mutual TLS (mTLS) or signed tokens for agent‑to‑agent authentication.

---

## 2. EAVESDROPPING ON AGENT COMMUNICATION (UNENCRYPTED CHANNELS)

**Description**  
Inter‑agent messages are transmitted over plain HTTP or unencrypted WebSockets, allowing attackers on the network to eavesdrop.

**What to Look For**
- Agent communication over HTTP, plain TCP, or unencrypted message queues.
- No TLS for inter‑agent traffic.

**What to Ignore**
- All communication over HTTPS, WSS, or TLS‑protected queues.

**How to Test**
1. Capture network traffic between agents using Wireshark or tcpdump.
2. Look for plaintext messages containing commands, tokens, or sensitive data.

**Example**
```text
Captured packet: POST /task HTTP/1.1\nX-Agent-ID: agent123\n{"cmd": "delete_user"}
```

**Tools**
- Wireshark
- tcpdump
- Burp Suite (if proxying)

**Risk Rating**  
Critical

**Remediation**
- Enforce TLS for all inter‑agent communication.

---

## 3. MESSAGE TAMPERING (NO INTEGRITY PROTECTION)

**Description**  
Inter‑agent messages are not signed or integrity‑protected, allowing attackers to modify them in transit.

**What to Look For**
- No HMAC or digital signature on messages.
- Messages can be modified without detection.

**What to Ignore**
- Messages include signatures verified by the receiver.

**How to Test**
1. Intercept an inter‑agent message (e.g., via MITM or proxy).
2. Modify a parameter (e.g., change `action=view` to `action=delete`).
3. Forward the modified message.
4. If the receiving agent processes it, integrity protection is missing.

**Example**
```json
{"sender": "agentA", "action": "delete", "target": "user123"}
```
Modified to `target: "user456"`.

**Tools**
- Burp Suite (MITM)

**Risk Rating**  
Critical

**Remediation**
- Sign messages with HMAC or digital signatures; verify on receipt.

---

## 4. REPLAY ATTACK ON INTER‑AGENT MESSAGES

**Description**  
Inter‑agent messages can be captured and replayed later to repeat actions (e.g., multiple fund transfers).

**What to Look For**
- No nonce, timestamp, or sequence number in messages.
- Same message accepted multiple times.

**What to Ignore**
- Messages include unique IDs or timestamps and are rejected if replayed.

**How to Test**
1. Capture a valid inter‑agent message (e.g., `transfer_funds`).
2. Replay the same message (same payload, same headers).
3. If the action is performed again, replay protection is missing.

**Example**
```json
{"action": "transfer", "amount": 100, "to": "attacker"}
```
Replayed → another 100 transferred.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Include message ID and timestamp; maintain a replay cache.

---

## 5. AGENT IDENTITY SPOOFING (FAKING AGENT ID IN HEADERS)

**Description**  
Agents identify themselves via headers (e.g., `X-Agent-ID`) that can be forged by attackers.

**What to Look For**
- Agent identity derived from client‑supplied headers.
- No cryptographic binding to the agent’s secret.

**What to Ignore**
- Identity is proven via signed tokens or mTLS certificates.

**How to Test**
1. Send a request to an agent with a forged `X-Agent-ID` header.
2. If the request is accepted, spoofing is possible.

**Example**
```http
POST /agent/internal/task HTTP/1.1
X-Agent-ID: admin-agent
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Do not trust client‑supplied agent IDs; use signed tokens.

---

## 6. MESSAGE INJECTION VIA UNVALIDATED SENDER

**Description**  
Agents accept messages from any sender without verifying that the sender is authorised to issue those commands.

**What to Look For**
- No authorisation checks based on sender role.
- Any agent can request any action.

**What to Ignore**
- Sender identity is checked against an allowlist of permitted actions.

**How to Test**
1. As a low‑privilege agent, send a message to a high‑privilege agent requesting an admin action.
2. If the action is performed, authorisation is missing.

**Example**
```text
Low‑privilege agent sends: {"action": "delete_all_users"}
High‑privilege agent executes.
```

**Tools**
- Manual testing

**Risk Rating**  
Critical

**Remediation**
- Implement role‑based access control for inter‑agent messages.

---

## 7. INTER‑AGENT COMMUNICATION VIA UNSECURED QUEUE (RABBITMQ, KAFKA)

**Description**  
Message queues used for agent communication are accessible without authentication, allowing attackers to read or inject messages.

**What to Look For**
- RabbitMQ, Kafka, or Redis exposed without credentials.
- No TLS for queue connections.

**What to Ignore**
- Queues with strong authentication and encryption.

**How to Test**
1. Attempt to connect to the message queue using default credentials or none.
2. If connection succeeds, security is insufficient.

**Example**
```bash
rabbitmqadmin -H queue.internal list queues
```

**Tools**
- RabbitMQ/Kafka clients
- Nmap

**Risk Rating**  
Critical

**Remediation**
- Enable authentication and authorisation for message queues.
- Use TLS for queue connections.

---

## 8. AGENT‑TO‑AGENT API WITHOUT RATE LIMITING (DOS)

**Description**  
Inter‑agent APIs have no rate limiting, allowing one agent to flood another with requests, causing denial of service.

**What to Look For**
- No `429 Too Many Requests` responses.
- Ability to send thousands of requests per second.

**What to Ignore**
- Rate limiting per agent.

**How to Test**
1. Send a high volume of requests from one agent to another.
2. Observe if the receiving agent becomes slow or unresponsive.

**Tools**
- Burp Intruder
- Turbo Intruder

**Risk Rating**  
High

**Remediation**
- Implement rate limiting per agent ID or IP.

---

## 9. MESSAGE METADATA LEAKAGE (AGENT IPS, INTERNAL TOPOLOGY)

**Description****
Inter‑agent message headers or error responses reveal internal IP addresses, hostnames, or network topology.

**What to Look For**
- Error messages containing `10.0.0.5`, `agent‑db.internal`, etc.
- `Server` headers with internal hostnames.

**What to Ignore**
- Generic error messages.

**How to Test**
1. Cause an error in inter‑agent communication (e.g., malformed message).
2. Examine the error response for internal addresses.

**Example**
```json
{"error": "Connection refused to agent-db.internal:5432"}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Sanitise error messages; do not expose internal topology.

---

## 10. AGENT COMMUNICATION VIA HTTP WITHOUT TLS

**Description** (similar to #2, but specifically HTTP). Covered.

## 11. INSECURE SERIALISATION OF INTER‑AGENT MESSAGES (PICKLE, JAVA)

**Description**  
Agents deserialise messages using unsafe formats (Python pickle, Java ObjectInputStream), leading to RCE.

**What to Look For**
- Messages in binary format (e.g., `ACED0005` for Java, pickle protocol).
- No use of safe serialisation (JSON, Protobuf).

**What to Ignore**
- Safe serialisation formats.

**How to Test**
1. Intercept a message and try to inject a malicious serialised payload.
2. Use `ysoserial` for Java or `pickle` payloads for Python.

**Tools**
- ysoserial
- Fickling

**Risk Rating**  
Critical

**Remediation**
- Use safe serialisation (JSON, Protocol Buffers) with schema validation.

---

## 12. AGENT ORCHESTRATOR MESSAGE FORGERY

**Description**  
Attackers forge messages pretending to come from the orchestrator (e.g., supervisor agent) to issue commands.

**What to Look For**
- No authentication of orchestrator messages.
- Any agent can claim to be the orchestrator.

**What to Ignore**
- Orchestrator messages are signed.

**How to Test**
1. Send a message to a worker agent claiming to be from the orchestrator.
2. If the worker obeys, forgery is possible.

**Tools**
- Manual testing

**Risk Rating**  
Critical

**Remediation**
- Sign orchestrator messages; agents verify signature.

---

## 13. CROSS‑AGENT SESSION HIJACKING (STOLEN AGENT TOKENS)

**Description**  
Agent session tokens are not bound to the agent, allowing an attacker who steals one token to impersonate the agent.

**What to Look For**
- Tokens without agent‑specific claims.
- Tokens not tied to IP or user agent.

**What to Ignore**
- Tokens bound to agent ID and IP.

**How to Test**
1. Capture a token from Agent A.
2. Use it from a different IP or machine.
3. If it works, token binding is missing.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Bind tokens to agent ID and IP; use short lifetimes.

---

## 14. MESSAGE ROUTING MANIPULATION (MISROUTING TO MALICIOUS AGENT)

**Description**  
Attackers manipulate message routing information (e.g., `to` field) to send messages to a malicious agent.

**What to Look For**
- Routing based on user‑controlled fields.
- No validation of destination agent identity.

**What to Ignore**
- Routing uses internal, immutable agent IDs.

**How to Test**
1. Change the destination agent ID in a message.
2. See if the message is delivered to the forged destination.

**Example**
```json
{"to": "malicious-agent", "action": "get_secrets"}
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Validate destination against a whitelist; use secure routing tables.

---

## 15. AGENT SUBSCRIPTION POISONING (SUBSCRIBE TO WRONG CHANNELS)

**Description**  
Agents can subscribe to message channels they are not authorised for, allowing them to eavesdrop on sensitive communications.

**What to Look For**
- Pub/sub system without authorisation on subscription.
- Any agent can subscribe to any channel.

**What to Ignore**
- Subscription permissions enforced.

**How to Test**
1. Have a low‑privilege agent attempt to subscribe to a high‑privilege channel (e.g., `admin.events`).
2. If it receives messages, authorisation is missing.

**Tools**
- Message queue client

**Risk Rating**  
High

**Remediation**
- Enforce channel‑based access control.

---

## 16. MESSAGE SPOOFING VIA COMPROMISED MESSAGE BUS

**Description**  
If the message bus itself is compromised, attackers can inject fake messages or read all inter‑agent traffic.

**What to Look For**
- Message bus with weak security (default passwords, no network isolation).

**What to Ignore**
- Strongly secured message bus with access controls.

**How to Test**
1. Attempt to gain access to the message bus using default credentials.
2. If successful, the bus is vulnerable.

**Tools**
- Message bus clients

**Risk Rating**  
Critical

**Remediation**
- Harden message bus with strong authentication and network segregation.

---

## 17. INTER‑AGENT COMMAND INJECTION (MESSAGE PAYLOAD AS COMMAND)

**Description**  
A receiving agent uses parts of a message directly in a system command without sanitisation.

**What to Look For**
- Agent passes message fields to `exec()`, `os.system()`, or `subprocess`.
- No input validation.

**What to Ignore**
- Messages are validated and not used as commands.

**How to Test**
1. Send a message with a payload like `; rm -rf /`.
2. Observe if the command executes.

**Tools**
- Manual testing

**Risk Rating**  
Critical

**Remediation**
- Never use message fields in system commands; use allowlists.

---

## 18. MESSAGE QUEUE FLOODING (DOS VIA AGENT‑GENERATED MESSAGES)

**Description**  
A malicious agent sends a massive number of messages to the queue, overwhelming other agents.

**What to Look For**
- No per‑agent message quota.
- Queue can be flooded.

**What to Ignore**
- Quotas and rate limits.

**How to Test**
1. From one agent, send 10,000 messages in a short time.
2. Observe if other agents are affected.

**Tools**
- Scripted agent

**Risk Rating**  
High

**Remediation**
- Enforce per‑agent message quotas and rate limits.

---

## 19. AGENT COMMUNICATION LOGGING BYPASS (NO AUDIT TRAIL)

**Description**  
Inter‑agent messages are not logged, making it impossible to trace malicious activity.

**What to Look For**
- No logs of agent‑to‑agent messages.
- No centralised audit trail.

**What to Ignore**
- All messages are logged.

**How to Test**
1. Send a sensitive inter‑agent command.
2. Check if any log entry exists.

**Tools**
- Log review

**Risk Rating**  
High

**Remediation**
- Log all inter‑agent messages with sender, receiver, timestamp, and action.

---

## 20. CROSS‑TENANT MESSAGE INTERCEPTION (MULTI‑TENANCY BYPASS)

**Description**  
In a multi‑tenant system, agents from one tenant can read or send messages to agents from another tenant.

**What to Look For**
- Shared message queues across tenants.
- No tenant isolation.

**What to Ignore**
- Tenant‑specific queues or filters.

**How to Test**
1. As Tenant A, attempt to send a message to Tenant B’s agent.
2. If the message is delivered, isolation is broken.

**Tools**
- Multi‑tenant testing

**Risk Rating**  
Critical

**Remediation**
- Isolate message queues per tenant.

---

## 21. MESSAGE TIMESTAMP MANIPULATION (TIME‑BASED ATTACKS)

**Description**  
Attackers modify the timestamp in inter‑agent messages to bypass expiry or replay windows.

**What to Look For**
- Timestamp not signed or validated.
- Agent uses timestamp for critical decisions (e.g., expiry).

**What to Ignore**
- Timestamps are signed and verified.

**How to Test**
1. Capture a message with a timestamp.
2. Modify the timestamp to a future value.
3. If the agent accepts it, manipulation is possible.

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Sign timestamps; validate against current server time.

---

## 22. AGENT PROTOCOL DOWNGRADE ATTACK (FORCE WEAKER SECURITY)

**Description**  
Attackers force agents to communicate using a weaker, vulnerable protocol version.

**What to Look For**
- Agents negotiate protocol version without security checks.
- Older versions are still supported.

**What to Ignore**
- Only secure versions allowed.

**How to Test**
1. Attempt to connect using an older, insecure protocol version.
2. If the agent accepts, downgrade is possible.

**Tools**
- Custom client

**Risk Rating**  
High

**Remediation**
- Reject insecure protocol versions.

---

## 23. MESSAGE PAYLOAD INJECTION VIA EXTERNAL AGENT REGISTRATION

**Description**  
Attackers register a malicious agent with the orchestrator, then send poisoned messages to other agents.

**What to Look For**
- Agent registration without validation.
- No verification of agent identity.

**What to Ignore**
- Registration requires signing and authorisation.

**How to Test**
1. Register a new agent with a malicious name.
2. Send messages from that agent to others.
3. See if they are accepted.

**Tools**
- Agent registration API

**Risk Rating**  
Critical

**Remediation**
- Authenticate and authorise all agent registrations.

---

## 24. AGENT COMMUNICATION VIA SHARED SECRET WITHOUT ROTATION

**Description**  
Agents share a static secret (e.g., API key) that is never rotated, increasing the risk of theft.

**What to Look For**
- Long‑lived shared secrets.
- No rotation policy.

**What to Ignore**
- Secrets rotated regularly.

**How to Test**
1. Obtain the shared secret (e.g., from config).
2. Use it to impersonate an agent after rotation should have occurred.

**Tools**
- Config review

**Risk Rating**  
High

**Remediation**
- Rotate shared secrets regularly; use short‑lived tokens.

---

## 25. MESSAGE SIZE EXHAUSTION (DOS VIA HUGE MESSAGES)

**Description**  
Agents send extremely large messages, causing memory exhaustion in receiving agents.

**What to Look For**
- No limit on message size.
- Agent loads entire message into memory.

**What to Ignore**
- Maximum message size enforced.

**How to Test**
1. Send a 10MB message to an agent.
2. Observe memory usage.

**Tools**
- Scripted agent

**Risk Rating**  
Medium

**Remediation**
- Enforce maximum message size.

---

## 26. AGENT DISCOVERY SERVICE POISONING (FAKE AGENT REGISTRATION)

**Description**  
Attackers register fake agents in the discovery service, causing other agents to send sensitive data to them.

**What to Look For**
- Discovery service allows unauthenticated registration.
- No verification of agent claims.

**What to Ignore**
- Discovery service requires authentication.

**How to Test**
1. Register a fake agent with a name similar to a legitimate one.
2. See if other agents send requests to it.

**Tools**
- Discovery API

**Risk Rating**  
Critical

**Remediation**
- Authenticate and authorise all discovery service updates.

---

## 27. MESSAGE FORWARDING ABUSE (AGENT AS RELAY FOR ATTACKS)

**Description**  
Attackers use a compromised agent as a relay to forward malicious messages to other agents, hiding the original source.

**What to Look For**
- Agent forwards messages without validating origin.
- No source tracking.

**What to Ignore**
- Forwarding is restricted or logged.

**How to Test**
1. Compromise Agent A.
2. Send a malicious message to Agent A, instructing it to forward to Agent B.
3. Agent B sees the message as coming from Agent A, not the attacker.

**Tools**
- Manual testing

**Risk Rating**  
High

**Remediation**
- Limit forwarding capabilities; require authentication for relay.

---

## 28. AGENT COMMUNICATION ERROR MESSAGE LEAKAGE (INTERNAL INFO)

**Description**  
Error messages from inter‑agent communication reveal internal stack traces, database queries, or configuration details.

**What to Look For**
- Detailed error responses containing internal paths, SQL queries, or agent IDs.

**What to Ignore**
- Generic error messages.

**How to Test**
1. Cause an inter‑agent communication failure (e.g., send malformed JSON).
2. Examine the error response.

**Example**
```json
{"error": "SQL error: table 'prod.agents' doesn't exist"}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Sanitise error messages; log details internally.

---

## 29. NO MESSAGE EXPIRY (STALE MESSAGES REPLAYED)

**Description**  
Inter‑agent messages do not expire, allowing attackers to replay old messages long after they are stale.

**What to Look For**
- No `expiry` or `ttl` field in messages.
- Messages accepted indefinitely.

**What to Ignore**
- Messages have time‑to‑live.

**How to Test**
1. Capture a valid message.
2. Replay it after a long delay (e.g., 1 hour).
3. If accepted, no expiry.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Include expiry timestamps; reject expired messages.

---

## 30. INSECURE AGENT HANDSHAKE (WEAK INITIALISATION)

**Description**  
The initial handshake between agents (e.g., when establishing a connection) is insecure, allowing attackers to inject themselves into the communication.

**What to Look For**
- No mutual authentication during handshake.
- Plaintext exchange of secrets.

**What to Ignore**
- Secure handshake with mTLS or Diffie‑Hellman.

**How to Test**
1. Intercept the handshake messages.
2. Attempt to modify the negotiation (e.g., downgrade security).
3. Observe if the connection is established.

**Tools**
- Burp Suite
- Wireshark

**Risk Rating**  
Critical

**Remediation**
- Use standard secure protocols (TLS 1.3, mTLS) with proper certificate validation.

---

## ✅ **SUMMARY**

Insecure Inter‑Agent Communication (ASI07) covers vulnerabilities in the channels, protocols, and authentication mechanisms used by agents to talk to each other. This guide provides 30 test cases for identifying communication weaknesses.

### **Key Testing Areas Summary**

| Attack Vector | Key Indicators | Risk |
|---------------|----------------|------|
| Missing Authentication | No mTLS, no tokens | Critical |
| Eavesdropping | HTTP, plain TCP | Critical |
| Message Tampering | No signature | Critical |
| Replay Attack | No nonce/timestamp | High |
| Identity Spoofing | Trusted headers | Critical |
| Unvalidated Sender | No RBAC | Critical |
| Unsecured Message Queue | No auth on queue | Critical |
| No Rate Limiting | Unlimited requests | High |
| Metadata Leakage | Internal IPs in errors | Medium |
| Insecure Serialisation | Pickle, Java | Critical |
| Orchestrator Forgery | Spoofed supervisor | Critical |
| Session Hijacking | Unbound tokens | High |
| Routing Manipulation | User‑controlled `to` | High |
| Subscription Poisoning | Unauthorised channel access | High |
| Compromised Message Bus | Weak bus security | Critical |
| Command Injection | Message → system command | Critical |
| Message Flooding | No quotas | High |
| No Logging | No audit trail | High |
| Cross‑Tenant Interception | Shared queues | Critical |
| Timestamp Manipulation | Unsigned timestamps | Medium |
| Protocol Downgrade | Weaker version accepted | High |
| Fake Agent Registration | Unvalidated registration | Critical |
| Shared Secret Without Rotation | Static keys | High |
| Message Size Exhaustion | No size limit | Medium |
| Discovery Poisoning | Fake agent entries | Critical |
| Message Forwarding Abuse | Agent as relay | High |
| Error Message Leakage | Stack traces | Medium |
| No Message Expiry | Stale messages replayed | High |
| Insecure Handshake | Weak initialisation | Critical |

### **Pro Tips for Testing Inter‑Agent Communication**
1. **Identify agent communication channels** – APIs, message queues, WebSockets.
2. **Test for missing authentication** – try to impersonate an agent.
3. **Eavesdrop** – capture traffic on internal networks.
4. **Attempt message tampering** – modify parameters in transit.
5. **Replay captured messages** – see if they are accepted again.
6. **Check serialisation formats** – look for pickled or Java serialised data.
7. **Review error messages** – for internal info leakage.

---

*This guide is for professional security testing purposes only. Unauthorised testing may violate terms of service.*
