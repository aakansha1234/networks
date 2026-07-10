# Sentinel

**Network configuration security auditor.**

Sentinel ingests a network device's running configuration, parses it into a
normalized device model, and runs security-posture detection rules against it —
surfacing misconfigurations (default SNMP strings, cleartext management,
over-permissive ACLs, weak crypto, missing hardening) with exact config-line
evidence and a ready-to-apply remediation script.

It is a **diagnose → remediate** tool: vendor-pluggable (Cisco IOS and Palo Alto
PAN-OS), with a language-model interface for querying devices and generating
config, a multi-device ACL-aware reachability engine, and a web dashboard.

> 📄 For design rationale, a feature walkthrough, and known limitations, see
> **[NOTES.md](NOTES.md)**. This README is the command/module reference.

## Install

```bash
uv sync            # or: pip install -e ".[dev]"
```

## Usage

```bash
# audit a config
sentinel scan tests/fixtures/bad_router.cfg

# include a ready-to-paste remediation script
sentinel scan tests/fixtures/bad_router.cfg --fix

# full evidence + descriptions per finding
sentinel scan tests/fixtures/bad_router.cfg --detail

# summarize findings in plain language (needs an LLM endpoint)
sentinel scan tests/fixtures/bad_router.cfg --summary

# machine-readable output for CI (exits non-zero on critical/high)
sentinel scan router.cfg --json
```

### Language-model interface (optional)

```bash
# ask a question; answers reference the parsed interfaces/ACLs/findings
sentinel ask router.cfg "what's the blast radius of the OUTSIDE-IN ACL?"

# describe a change in plain language; get IOS config to review
sentinel remediate router.cfg "lock down vty to ssh from 10.0.0.0/24"
```

### Multi-device topology & reachability

```bash
# infer the network graph from several configs (shared subnets = links)
sentinel topo edge.cfg core.cfg

# compute end-to-end reachability with a cited deciding rule
sentinel reach --src 10.0.1.50 --dst 10.0.2.50 --proto tcp --port 443 edge.cfg core.cfg
```

`reach` evaluates Cisco ACL semantics (wildcard matching, first-match, implicit
deny) at every ingress interface along the path and reports exactly which rule
permitted or denied the flow — the answer is computed, not guessed.

### Web dashboard

```bash
uv sync --extra web            # install FastAPI + uvicorn
sentinel web                   # http://localhost:8000
```

A single-page dashboard: paste a config (or load a bundled Cisco/PAN-OS example),
see the posture score, severity breakdown, the findings table, the remediation
script, and an optional plain-language summary.

The `ask` and `remediate` commands call a configurable language-model endpoint.
They pass the parsed device state and findings as context (not the raw config),
and any config the model returns is linted against valid IOS commands before it
is shown. Works with any OpenAI-compatible endpoint:

```bash
export SENTINEL_LLM_API_KEY=...           # or OPENAI_API_KEY
export SENTINEL_LLM_BASE_URL=https://...  # default: OpenAI; also OpenRouter/Ollama/etc.
export SENTINEL_LLM_MODEL=gpt-4o-mini
```

## Run the tests

```bash
uv run pytest -q
```

## Architecture

```
raw config ─► parser (ios/panos) ─► normalized Device ─► detection rules ─► findings
                                          │                       │
                                          └────► language model ◄─┘  (ask / remediate)
```

- `sentinel/model.py` — normalized, vendor-agnostic device model
- `sentinel/parsers/ios.py` — Cisco IOS / IOS-XE parser
- `sentinel/parsers/panos.py` — Palo Alto PAN-OS (set-format) parser
- `sentinel/rules/ios.py` — IOS detection rules (registered per-OS)
- `sentinel/rules/panos.py` — PAN-OS detection rules
- `sentinel/finding.py` — Finding model, severity, posture score
- `sentinel/remediate.py` — config-delta script builder
- `sentinel/report.py` / `sentinel/cli.py` — human + JSON output
- `sentinel/llm.py` — OpenAI-compatible client (stdlib only, no new deps)
- `sentinel/agent.py` — device-context builder, Q&A and config generation, output lint
- `sentinel/topology.py` — network graph (subnet-inferred adjacency) + ACL-aware reachability
- `sentinel/web.py` — optional FastAPI dashboard (single-page, bundled examples)

Adding a check = write a function, decorate it with `@register("ios")`. Adding a
vendor = write a parser that emits a `Device`, then rules under its OS name.

## Roadmap

- [x] Cisco IOS parser + ~12 detection rules
- [x] Deterministic remediation script generation
- [x] Language-model Q&A and config generation (ask / remediate)
- [x] PAN-OS parser + posture rules (multi-vendor: Cisco + Palo Alto)
- [x] Topology knowledge graph + reachability engine (multi-device, ACL-aware, cited)
- [x] Web dashboard (FastAPI; bundled Cisco + PAN-OS examples)

## Detection coverage (Cisco IOS)

| ID | Check |
|----|-------|
| IOS-SNMP-001 | well-known/default SNMP community strings (public/private…) |
| IOS-SNMP-002 | SNMPv1/v2c in use instead of SNMPv3 |
| IOS-ACCESS-001 | Telnet permitted on VTY lines |
| IOS-ACCESS-002 | `no login` on VTY (unauthenticated access) |
| IOS-ACCESS-003 | VTY reachable from anywhere (no access-class) |
| IOS-ACCESS-004 | weak line password (type 0 cleartext / type 7 reversible) |
| IOS-MGMT-001 | cleartext HTTP management server enabled |
| IOS-MGMT-002 | no remote syslog destination |
| IOS-MGMT-003 | no login banner |
| IOS-CRYPTO-001 | `service password-encryption` disabled |
| IOS-CRYPTO-002 | SSH protocol version 1 |
| IOS-CRYPTO-003 | SSH offered but version not pinned to 2 |
| IOS-ACL-001 | over-permissive `permit ... any any` ACL rule |
| IOS-ROUTE-001 | IP source routing enabled |

## Detection coverage (Palo Alto PAN-OS)

| ID | Check |
|----|-------|
| PAN-RULE-001 | `allow ANY/ANY/ANY/ANY` security rule (catch-all permit) |
| PAN-RULE-002 | allow rule with no session-end logging |
| PAN-RULE-003 | allow rule with `application any` (App-ID bypass) |
| PAN-RULE-004 | internet-facing allow rule matching `source any` |
| PAN-RULE-005 | no explicit, logged default-deny rule in the rulebase |
