# CastleBlack (AIPTT) — Autonomous Internal Pentest Tool

> **⚠ Prototype notice.** CastleBlack is an **early prototype** of a larger offensive-security harness currently in active development. It proves the core idea end-to-end on a single discipline (internal network). It is **not** a finished product — treat it as a proof of concept, not a production tool.

> **Authorised use only.** Run this solely against systems you are explicitly authorised to test, under a signed Rules of Engagement. Unauthorised use is illegal.

CastleBlack is a Claude-powered command-line tool that autonomously discovers, exploits and reports vulnerabilities inside a scoped network. It runs an **OPAV loop** — **O**bserve → **P**lan → **A**ct → **V**alidate — where an LLM plans the next move and **deterministic guardrails decide whether it is allowed to run**.

## How it works

1. **Observe** — pull scan data and compromised hosts from the knowledge graph.
2. **Plan** — ask the model to rank the next attack steps.
3. **Act** — execute a step only after it clears every guardrail (scope, blast radius, rate limit, circuit breaker).
4. **Validate** — capture encrypted proof-of-exploitation for anything that worked.

Attack modules cover Active Directory (Kerberoasting, AS-REP Roasting, DCSync, Pass-the-Hash, ADCS, delegation abuse), network RCE and lockout-safe password spraying, and lateral movement.

## Quick start

**Requirements:** Python ≥ 3.12, Docker (sandboxed exploit execution), nmap, an Anthropic API key.

```bash
pip install -e .
cp .env.example .env               # add your Anthropic + encryption keys

aiptt engage init   --name "Corp PT" --cidr 10.0.0.0/24 --roe roe.pdf
aiptt scan discover --engagement-id ENG-XXXX --cidr 10.0.0.0/24
aiptt attack run    --engagement-id ENG-XXXX --max-cycles 10
aiptt report technical --engagement-id ENG-XXXX --output-dir ./reports
```

Preview the model's plan without executing anything with `aiptt attack plan …`. Pause safely with `Ctrl-C`, resume with `aiptt engage resume`.

## Safety controls

| Control | What it does |
|---|---|
| RoE validation | No activity starts without a hashed Rules-of-Engagement document |
| Scope enforcement | Every target checked against the allowed CIDRs; optional host `iptables` lock |
| Blast-radius gate | Destructive classes (DoS, wipe, ransomware) are always blocked |
| Credential rate limiter | Reads the AD lockout policy and stays below the threshold |
| Circuit breaker | Halts the loop on anomalous CPU / IO / DNS activity |
| Docker sandbox | AI-generated exploit code runs in a capability-dropped container |
| Encrypted vault | All proof-of-exploitation stored AES-256-GCM at rest |
| HMAC audit log | Tamper-evident, append-only record of every action |
| Human-in-the-loop | Approval required before crown-jewel targets and deep pivots |

## Status & roadmap

CastleBlack is the **prototype**. The production direction is a **multi-discipline harness on a shared kernel** — a world-state model, a policy/worker loop, deterministic guardrails, per-vuln playbooks, and an evaluation framework — extending beyond internal network to web, cloud and identity. This repo is where the idea was proven; the harness is where it is going.

## License

For authorised security-assessment use only. Redistribution, modification, or use outside explicitly authorised penetration tests is prohibited.
