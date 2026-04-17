# ⛓️ **ASI08: CASCADING FAILURES TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Systemic Failure Propagation in Multi‑Agent Systems*

---

## 📋 **TABLE OF CONTENTS**

1. [Single Point of Failure (SPOF) in Agent Orchestrator](#1-single-point-of-failure-spof-in-agent-orchestrator)
2. [No Circuit Breaker for Downstream Agent Failures](#2-no-circuit-breaker-for-downstream-agent-failures)
3. [Agent Dependency Chain Collapse (Domino Effect)](#3-agent-dependency-chain-collapse-domino-effect)
4. [Resource Exhaustion Cascading via Retry Storms](#4-resource-exhaustion-cascading-via-retry-storms)
5. [Error Propagation Without Fallback (Unhandled Exceptions)](#5-error-propagation-without-fallback-unhandled-exceptions)
6. [Agent Timeout Misconfiguration (Amplified Latency)](#6-agent-timeout-misconfiguration-amplified-latency)
7. [Queue Backlog Overflow from Downstream Failure](#7-queue-backlog-overflow-from-downstream-failure)
8. [Cascading Authorization Bypass (One Compromised Agent Breaks Others)](#8-cascading-authorization-bypass-one-compromised-agent-breaks-others)
9. [No Bulkhead Isolation (Failure in One Tenant Affects Others)](#9-no-bulkhead-isolation-failure-in-one-tenant-affects-others)
10. [Agent Health Check Failure (False Positive/False Negative)](#10-agent-health-check-failure-false-positivefalse-negative)
11. [Database Connection Pool Exhaustion Cascade](#11-database-connection-pool-exhaustion-cascade)
12. [Memory Leak in Agent Leading to Cascading Restarts](#12-memory-leak-in-agent-leading-to-cascading-restarts)
13. [Deadlock in Multi‑Agent Coordination](#13-deadlock-in-multi-agent-coordination)
14. [Infinite Loop via Agent Self‑Call (Recursive Cascade)](#14-infinite-loop-via-agent-self-call-recursive-cascade)
15. [No Graceful Degradation (All Agents Fail Together)](#15-no-graceful-degradation-all-agents-fail-together)
16. [Cascading Log Flood (Disk Filled by Error Logs)](#16-cascading-log-flood-disk-filled-by-error-logs)
17. [Agent Start‑up Dependency Order Failures](#17-agent-start-up-dependency-order-failures)
18. [No Rate Limiting on Inter‑Agent Retries (Amplification)](#18-no-rate-limiting-on-inter-agent-retries-amplification)
19. [Sidecar Agent Failure Crashing Main Agent](#19-sidecar-agent-failure-crashing-main-agent)
20. [Configuration Propagation Failure (Inconsistent State)](#20-configuration-propagation-failure-inconsistent-state)
21. [Orchestrator Queue Blocked by Slow Agent](#21-orchestrator-queue-blocked-by-slow-agent)
22. [Cascading Token Expiry (Auth Failure Propagation)](#22-cascading-token-expiry-auth-failure-propagation)
23. [Agent Version Mismatch Across Cluster](#23-agent-version-mismatch-across-cluster)
24. [No Fallback for External API Failures (Cascading 5xx)](#24-no-fallback-for-external-api-failures-cascading-5xx)
25. [Cascading Cache Stampede (Thundering Herd)](#25-cascading-cache-stampede-thundering-herd)
26. [Agent‑to‑Agent Timeout Amplification](#26-agent-to-agent-timeout-amplification)
27. [No Liveness Probe for Agent (Dead Agent Not Detected)](#27-no-liveness-probe-for-agent-dead-agent-not-detected)
28. [Cascading Configuration Reload (Mass Restart)](#28-cascading-configuration-reload-mass-restart)
29. [Agent Fail‑Open Instead of Fail‑Close (Security Cascade)](#29-agent-fail-open-instead-of-fail-close-security-cascade)
30. [No Distributed Tracing (Unable to Diagnose Cascades)](#30-no-distributed-tracing-unable-to-diagnose-cascades)

---

## 1. SINGLE POINT OF FAILURE (SPOF) IN AGENT ORCHESTRATOR

**Description**  
A single orchestrator or coordinator agent is responsible for all task distribution. If it fails, the entire agent system becomes unavailable.

**What to Look For**
- Only one instance of the orchestrator running.
- No leader election or failover mechanism.

**What to Ignore**
- Orchestrator deployed with redundancy (e.g., Kubernetes replicas, leader election).

**How to Test**
1. Kill or stop the orchestrator process.
2. Observe if other agents continue to function or if new tasks can be assigned.

**Example**
- Orchestrator pod crashes; no new agent tasks are scheduled; system hangs.

**Tools**
- Chaos engineering tools (Chaos Mesh, Gremlin)
- Manual process termination

**Risk Rating**  
Critical

**Remediation**
- Deploy orchestrator with redundancy (multiple replicas, leader/follower).
- Implement automatic failover.

---

## 2. NO CIRCUIT BREAKER FOR DOWNSTREAM AGENT FAILURES

**Description**  
When an agent calls a downstream agent or service that is failing, it continues to retry, exhausting resources and causing cascading failures.

**What to Look For**
- No circuit breaker pattern implemented.
- Retries continue indefinitely even when downstream is unavailable.

**What to Ignore**
- Circuit breaker that opens after failures and prevents calls.

**How to Test**
1. Make a downstream agent return errors (e.g., 500) consistently.
2. Observe if the calling agent keeps retrying without circuit opening.
3. Monitor resource usage.

**Example**
```text
Agent A → Agent B (failing). Agent A retries every second, consuming threads and memory.
```

**Tools**
- Chaos engineering
- Load testing

**Risk Rating**  
High

**Remediation**
- Implement circuit breaker with timeout and fallback.

---

## 3. AGENT DEPENDENCY CHAIN COLLAPSE (DOMINO EFFECT)

**Description**  
A single agent failure triggers failures in all agents that depend on it, leading to a chain reaction.

**What to Look For**
- Long dependency chains (A → B → C → D).
- No isolation or fallback for intermediate failures.

**What to Ignore**
- Dependencies are minimised, and agents can function without some dependencies.

**How to Test**
1. Cause one critical agent to fail (e.g., Agent B).
2. Observe if Agent A and Agent C also fail.

**Example**
```text
Agent A → Agent B → Agent C. B fails; A and C become unusable.
```

**Tools**
- Chaos engineering

**Risk Rating**  
High

**Remediation**
- Design for graceful degradation; avoid deep dependency chains.

---

## 4. RESOURCE EXHAUSTION CASCADING VIA RETRY STORMS

**Description**  
A failure causes many agents to retry simultaneously, overwhelming resources (CPU, memory, network) and causing more failures.

**What to Look For**
- Aggressive retry policies with no jitter or backoff.
- No rate limiting on retries.

**What to Ignore**
- Exponential backoff with jitter and capped retries.

**How to Test**
1. Cause a downstream service to fail.
2. Measure the number of retry requests from multiple agents.
3. See if resource usage spikes.

**Tools**
- Load testing
- Monitoring dashboards

**Risk Rating**  
High

**Remediation**
- Implement exponential backoff with jitter.
- Limit total retry count.

---

## 5. ERROR PROPAGATION WITHOUT FALLBACK (UNHANDLED EXCEPTIONS)

**Description**  
An agent throws an exception that propagates to the caller without being caught or handled, causing the caller to also fail.

**What to Look For**
- No try‑catch blocks around agent calls.
- Exceptions bubble up to top level.

**What to Ignore**
- Graceful error handling and fallback responses.

**How to Test**
1. Trigger an error in a low‑level agent (e.g., divide by zero).
2. Observe if the calling agent crashes or returns an error to its caller.

**Example**
```text
Agent C throws NullPointerException → Agent B crashes → Agent A crashes.
```

**Tools**
- Manual error injection

**Risk Rating**  
High

**Remediation**
- Use defensive programming; catch exceptions and return fallback responses.

---

## 6. AGENT TIMEOUT MISCONFIGURATION (AMPLIFIED LATENCY)

**Description**  
Agent timeouts are set too high, causing waiting agents to hang for extended periods, tying up threads and leading to cascading delays.

**What to Look For**
- Long timeouts (e.g., 60 seconds) for critical agents.
- No client‑side timeouts.

**What to Ignore**
- Appropriate timeouts (e.g., 5‑10 seconds) with fast failure.

**How to Test**
1. Make a downstream agent very slow (e.g., sleep for 30 seconds).
2. Observe how long calling agents wait and if thread pools exhaust.

**Tools**
- Chaos engineering

**Risk Rating**  
Medium

**Remediation**
- Set reasonable timeouts; use deadlines.

---

## 7. QUEUE BACKLOG OVERFLOW FROM DOWNSTREAM FAILURE

**Description**  
When a downstream agent fails, messages queue up in the channel (e.g., RabbitMQ, Kafka). The queue eventually overflows, dropping messages and causing data loss.

**What to Look For**
- No maximum queue size or overflow policy.
- Queue grows unbounded.

**What to Ignore**
- Queue limits and dead‑letter queues.

**How to Test**
1. Stop a consuming agent.
2. Publish many messages to the queue.
3. Observe if the queue fills up and messages are dropped.

**Tools**
- Message queue monitoring

**Risk Rating**  
High

**Remediation**
- Set queue limits; use dead‑letter queues.

---

## 8. CASCADING AUTHORIZATION BYPASS (ONE COMPROMISED AGENT BREAKS OTHERS)

**Description**  
An agent is compromised, and due to lack of isolation, the attacker uses it to pivot and compromise other agents.

**What to Look For**
- Agents share credentials or trust each other implicitly.
- No zero‑trust networking.

**What to Ignore**
- Strict isolation; compromised agent cannot affect others.

**How to Test**
1. Simulate a compromised agent (e.g., use its credentials to call other agents).
2. See if other agents accept the calls without additional auth.

**Example**
```text
Agent A (compromised) calls Agent B’s admin endpoint; Agent B trusts Agent A’s token.
```

**Tools**
- Manual testing

**Risk Rating**  
Critical

**Remediation**
- Use zero‑trust principles; each agent must authenticate independently.

---

## 9. NO BULKHEAD ISOLATION (FAILURE IN ONE TENANT AFFECTS OTHERS)

**Description**  
In a multi‑tenant system, a failure in one tenant (e.g., high resource usage) can affect other tenants due to shared resources.

**What to Look For**
- Shared thread pools, connection pools, or databases across tenants.
- No per‑tenant resource limits.

**What to Ignore**
- Per‑tenant quotas and isolated resource pools.

**How to Test**
1. Overload one tenant’s agent with requests.
2. Observe if other tenants experience increased latency or errors.

**Tools**
- Load testing

**Risk Rating**  
High

**Remediation**
- Implement bulkheads (per‑tenant thread pools, connection limits).

---

## 10. AGENT HEALTH CHECK FAILURE (FALSE POSITIVE/FALSE NEGATIVE)

**Description**  
Health checks incorrectly report an agent as healthy when it is not (false positive) or as unhealthy when it is (false negative), causing cascading issues.

**What to Look For**
- Health check that only checks TCP connectivity, not actual functionality.
- No liveness vs readiness separation.

**What to Ignore**
- Deep health checks that validate agent’s ability to work.

**How to Test**
1. Make the agent’s internal logic broken but keep the health endpoint responding.
2. See if the orchestrator still sends tasks to it.

**Tools**
- Manual fault injection

**Risk Rating**  
High

**Remediation**
- Implement meaningful health checks (e.g., test database connectivity, dependency availability).

---

## 11. DATABASE CONNECTION POOL EXHAUSTION CASCADE

**Description**  
A slow agent holds database connections for too long, exhausting the pool and causing other agents to fail.

**What to Look For**
- Shared connection pool across agents.
- No per‑agent connection limits.

**What to Ignore**
- Isolated pools or per‑agent limits.

**How to Test**
1. Make one agent execute a long‑running database query.
2. Observe if other agents cannot acquire connections.

**Tools**
- Database monitoring

**Risk Rating**  
High

**Remediation**
- Use separate connection pools per agent or per tenant.

---

## 12. MEMORY LEAK IN AGENT LEADING TO CASCADING RESTARTS

**Description**  
One agent has a memory leak; it crashes and restarts, but the leak persists, causing repeated crashes. If other agents depend on it, they also fail.

**What to Look For**
- No memory limits on agents.
- No monitoring for memory leaks.

**What to Ignore**
- Memory limits and regular restarts.

**How to Test**
1. Run the agent under load for an extended period.
2. Monitor memory usage growth.

**Tools**
- Memory profiling tools

**Risk Rating**  
Medium

**Remediation**
- Set memory limits; restart agents periodically; fix memory leaks.

---

## 13. DEADLOCK IN MULTI‑AGENT COORDINATION

**Description**  
Two or more agents wait for each other to release resources, causing a deadlock and halting the system.

**What to Look For**
- Circular dependencies (Agent A waits for B, B waits for A).
- No timeout on locks.

**What to Ignore**
- Lock ordering or timeouts.

**How to Test**
1. Simulate a scenario where Agent A requires a lock held by Agent B and vice versa.
2. Observe if the system freezes.

**Tools**
- Deadlock detection tools

**Risk Rating**  
High

**Remediation**
- Implement lock timeouts; avoid circular dependencies.

---

## 14. INFINITE LOOP VIA AGENT SELF‑CALL (RECURSIVE CASCADE)

**Description**  
An agent calls itself (directly or indirectly) without a termination condition, causing infinite recursion and resource exhaustion.

**What to Look For**
- Agent’s task includes calling the same agent.
- No recursion depth limit.

**What to Ignore**
- Recursion detection or depth limits.

**How to Test**
1. Send a message that causes Agent A to call Agent A.
2. Observe if the call chain never ends.

**Example**
```text
User: "Process task" → Agent A calls Agent A with same task → infinite loop.
```

**Tools**
- Manual testing

**Risk Rating**  
Critical

**Remediation**
- Implement recursion depth limits; detect self‑calls.

---

## 15. NO GRACEFUL DEGRADATION (ALL AGENTS FAIL TOGETHER)

**Description**  
When a non‑critical dependency fails, the entire system fails instead of continuing with reduced functionality.

**What to Look For**
- No fallback or degraded mode.
- System crashes if any dependency is unavailable.

**What to Ignore**
- Graceful degradation; non‑critical features are disabled.

**How to Test**
1. Shut down a non‑critical dependency (e.g., recommendation engine).
2. See if the main functionality still works.

**Tools**
- Chaos engineering

**Risk Rating**  
High

**Remediation**
- Design for graceful degradation; use feature flags.

---

## 16. CASCADING LOG FLOOD (DISK FILLED BY ERROR LOGS)

**Description**  
A failure causes repeated error logging, filling disk space and causing all agents to fail.

**What to Look For**
- No rate limiting on error logs.
- Log rotation not configured.

**What to Ignore**
- Log rate limiting and rotation.

**How to Test**
1. Trigger a repeated error (e.g., failing API call in a loop).
2. Monitor disk usage.

**Tools**
- Disk monitoring

**Risk Rating**  
Medium

**Remediation**
- Implement log rate limiting; use log rotation.

---

## 17. AGENT START‑UP DEPENDENCY ORDER FAILURES

**Description**  
Agents start in the wrong order, causing cascading failures because dependencies are not ready.

**What to Look For**
- No startup health checks.
- Agents assume dependencies are available.

**What to Ignore**
- Startup ordering via init containers or health checks.

**How to Test**
1. Restart the whole system.
2. Observe if any agent fails because its dependency is not yet up.

**Tools**
- Orchestration logs

**Risk Rating**  
Medium

**Remediation**
- Use readiness probes and dependency waiting.

---

## 18. NO RATE LIMITING ON INTER‑AGENT RETRIES (AMPLIFICATION)

**Description**  
When an agent fails, multiple upstream agents retry, amplifying the load and causing cascading failure.

**What to Look For**
- Many agents retry the same failed operation simultaneously.
- No coordination of retries.

**What to Ignore**
- Exponential backoff and retry coordination.

**How to Test**
1. Cause an agent to fail.
2. Measure the number of retry requests from upstream agents.

**Tools**
- Load testing

**Risk Rating**  
High

**Remediation**
- Use jittered exponential backoff; limit retry concurrency.

---

## 19. SIDECAR AGENT FAILURE CRASHING MAIN AGENT

**Description**  
A sidecar agent (e.g., for logging, monitoring) fails and causes the main agent to exit.

**What to Look For**
- Main agent tightly coupled to sidecar; sidecar failure crashes main.
- No crash‑safe design.

**What to Ignore**
- Sidecar failures do not affect main agent.

**How to Test**
1. Kill the sidecar process.
2. Observe if the main agent continues to function.

**Tools**
- Process management

**Risk Rating**  
High

**Remediation**
- Run sidecar as a separate, non‑critical process; main agent should be resilient.

---

## 20. CONFIGURATION PROPAGATION FAILURE (INCONSISTENT STATE)

**Description**  
A configuration update fails to reach some agents, leading to inconsistent behaviour and cascading errors.

**What to Look For**
- No atomic configuration distribution.
- Agents run with stale configs.

**What to Ignore**
- Configuration versioning and rollback.

**How to Test**
1. Update a configuration.
2. Check if all agents receive the same version.

**Tools**
- Configuration management logs

**Risk Rating**  
Medium

**Remediation**
- Use distributed configuration service with versioning.

---

## 21. ORCHESTRATOR QUEUE BLOCKED BY SLOW AGENT

**Description**  
One slow agent blocks the orchestrator’s task queue, causing all other agents to wait.

**What to Look For**
- Single queue for all agents.
- No per‑agent quotas.

**What to Ignore**
- Separate queues per agent or priority.

**How to Test**
1. Make one agent process tasks very slowly.
2. Observe if other agents’ tasks are delayed.

**Tools**
- Load testing

**Risk Rating**  
High

**Remediation**
- Use per‑agent queues or priority queues.

---

## 22. CASCADING TOKEN EXPIRY (AUTH FAILURE PROPAGATION)

**Description**  
An agent’s authentication token expires, and it cannot renew it. Downstream agents that rely on it also fail.

**What to Look For**
- No token refresh mechanism.
- Token expiry causes agent to stop processing.

**What to Ignore**
- Automatic token refresh.

**How to Test**
1. Let an agent’s token expire.
2. Observe if dependent agents fail.

**Tools**
- Manual time manipulation

**Risk Rating**  
High

**Remediation**
- Implement automatic token refresh; use short‑lived tokens with rotation.

---

## 23. AGENT VERSION MISMATCH ACROSS CLUSTER

**Description**  
Different agents run different versions, leading to compatibility issues and cascading failures.

**What to Look For**
- No version pinning.
- Rolling updates without backward compatibility.

**What to Ignore**
- Version compatibility testing.

**How to Test**
1. Upgrade one agent to a newer version.
2. Observe if interactions with older agents break.

**Tools**
- Version management

**Risk Rating**  
High

**Remediation**
- Use backward‑compatible APIs; test multi‑version deployments.

---

## 24. NO FALLBACK FOR EXTERNAL API FAILURES (CASCADING 5XX)

**Description**  
An agent calls an external API that fails; without fallback, the agent returns an error, causing upstream errors.

**What to Look For**
- No caching or fallback responses.
- External API failure leads to immediate failure.

**What to Ignore**
- Cached responses or default values.

**How to Test**
1. Make the external API return 500 errors.
2. Observe if the agent propagates errors.

**Tools**
- Mock external API

**Risk Rating**  
High

**Remediation**
- Implement fallback (cache, default values, degraded mode).

---

## 25. CASCADING CACHE STAMPEDE (THUNDERING HERD)

**Description****
When a cache entry expires, many agents simultaneously try to recompute the value, overwhelming the backend.

**What to Look For**
- No cache locking or early recomputation.
- Many agents recompute same data.

**What to Ignore**
- Cache stampede prevention (e.g., locking, probabilistic early expiration).

**How to Test**
1. Set a cache TTL to a low value.
2. Trigger many requests after TTL expires.
3. Observe backend load.

**Tools**
- Load testing

**Risk Rating**  
Medium

**Remediation**
- Use cache stampede prevention (e.g., `singleflight`, locking).

---

## 26. AGENT‑TO‑AGENT TIMEOUT AMPLIFICATION

**Description**  
Agent A calls Agent B with a timeout of 30 seconds. Agent B then calls Agent C with another 30‑second timeout. Total time adds up, causing client timeouts.

**What to Look For**
- Cumulative timeouts without overall deadline.
- No propagation of deadline.

**What to Ignore**
- Deadline propagation.

**How to Test**
1. Introduce delays in Agent C.
2. Observe if Agent A’s timeout is exceeded despite each individual timeout being within limits.

**Tools**
- Chaos engineering

**Risk Rating**  
Medium

**Remediation**
- Use deadline propagation (context deadline in gRPC, HTTP headers).

---

## 27. NO LIVENESS PROBE FOR AGENT (DEAD AGENT NOT DETECTED)

**Description****
A dead agent is not detected, and the orchestrator continues sending tasks to it, causing cascading failures.

**What to Look For**
- No liveness probes.
- Agent stays in load balancer even after crash.

**What to Ignore**
- Liveness and readiness probes.

**How to Test**
1. Crash an agent.
2. Check if the orchestrator still routes tasks to it.

**Tools**
- Orchestrator logs

**Risk Rating**  
High

**Remediation**
- Implement liveness probes; remove dead agents.

---

## 28. CASCADING CONFIGURATION RELOAD (MASS RESTART)

**Description**  
A configuration change triggers a reload in all agents simultaneously, causing a system‑wide restart and downtime.

**What to Look For**
- No rolling updates.
- Agents reload in parallel.

**What to Ignore**
- Rolling restart.

**How to Test**
1. Push a configuration change.
2. Observe if all agents restart at once.

**Tools**
- Configuration management

**Risk Rating**  
Medium

**Remediation**
- Use rolling updates; allow gradual reload.

---

## 29. AGENT FAIL‑OPEN INSTEAD OF FAIL‑CLOSE (SECURITY CASCADE)

**Description****
When an agent fails, it fails open (e.g., allows all requests) instead of failing closed, leading to security breaches.

**What to Look For**
- Fallback logic that bypasses authorisation.
- “Fail open” pattern.

**What to Ignore**
- Fail‑closed (deny by default).

**How to Test**
1. Cause an agent to crash or timeout.
2. Check if it allows requests that should be denied.

**Example**
```text
Auth agent fails; downstream agent allows all requests.
```

**Tools**
- Chaos engineering

**Risk Rating**  
Critical

**Remediation**
- Fail closed; deny requests when dependencies are unavailable.

---

## 30. NO DISTRIBUTED TRACING (UNABLE TO DIAGNOSE CASCADES)

**Description**  
Without distributed tracing, it is impossible to identify where a failure originated, making it hard to prevent cascades.

**What to Look For**
- No trace IDs propagated across agents.
- Logs cannot be correlated.

**What to Ignore**
- Distributed tracing implemented.

**How to Test**
1. Cause a cascading failure.
2. Attempt to trace the root cause from logs; if impossible, tracing is missing.

**Tools**
- Log analysis

**Risk Rating**  
Medium (process)

**Remediation**
- Implement distributed tracing (e.g., OpenTelemetry, Jaeger).

---

## ✅ **SUMMARY**

Cascading Failures (ASI08) occur when a single failure propagates through the agent system, causing widespread downtime, data loss, or security breaches. This guide provides 30 test cases for identifying cascade vulnerabilities.

### **Key Testing Areas Summary**

| Attack Vector | Key Indicators | Risk |
|---------------|----------------|------|
| Single Point of Failure | Single orchestrator | Critical |
| No Circuit Breaker | Unlimited retries | High |
| Dependency Chain Collapse | Deep dependency chain | High |
| Retry Storm | Aggressive retries | High |
| Unhandled Exceptions | No fallback | High |
| Long Timeouts | High latency propagation | Medium |
| Queue Backlog | Unbounded queues | High |
| Cascading Auth Bypass | Trusted agents | Critical |
| No Bulkhead | Shared resources | High |
| Health Check Failure | Shallow checks | High |
| Connection Pool Exhaustion | Shared pools | High |
| Memory Leak | Growing memory | Medium |
| Deadlock | Circular waits | High |
| Infinite Self‑Call | Recursion | Critical |
| No Graceful Degradation | All‑or‑nothing | High |
| Log Flood | No rate limit | Medium |
| Startup Order Failure | No readiness | Medium |
| Retry Amplification | Many retriers | High |
| Sidecar Crash | Tight coupling | High |
| Config Propagation | Inconsistent state | Medium |
| Blocked Queue | Slow agent blocks all | High |
| Token Expiry | No refresh | High |
| Version Mismatch | Incompatible versions | High |
| No Fallback | External API failure cascade | High |
| Cache Stampede | Thundering herd | Medium |
| Timeout Amplification | Cumulative delays | Medium |
| No Liveness Probe | Dead agent not removed | High |
| Mass Restart | Rolling update missing | Medium |
| Fail‑Open | Security cascade | Critical |
| No Tracing | Cannot diagnose | Medium (process) |

### **Pro Tips for Testing Cascading Failures**
1. **Use chaos engineering** – inject failures (network delay, process kill, resource exhaustion).
2. **Test retry policies** – see if they cause storms.
3. **Monitor resource usage** – CPU, memory, connections, queues.
4. **Simulate slow dependencies** – observe if timeouts propagate.
5. **Check for single points of failure** – orchestrator, database, message bus.
6. **Test graceful degradation** – turn off non‑critical components.
7. **Verify fallback mechanisms** – cache, default values, degraded mode.

---

*This guide is for professional security testing purposes only. Unauthorised testing may violate terms of service.*
