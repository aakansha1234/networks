# Sentinel — Session Notes & Interview Guide

Companion to [README.md](README.md). The README is the *reference* (commands,
modules, detection tables). This file is the *narrative*: how to talk about the
project, why it's built the way it is, how to demo it, and what to say about its
edges. Built for interview prep at Cisco and Palo Alto.

---

## 1. The one-liner

> **Sentinel is an AI-augmented network configuration security auditor. It parses
> Cisco IOS and Palo Alto PAN-OS configs, finds security flaws with cited
> evidence, generates apply-ready remediation, and uses a *grounded* LLM to
> answer questions and write config — all backed by a reachability engine that
> computes who can talk to whom across a multi-device network.**

---

## 2. The interview narrative (memorize the shape, not the words)

**Lead with the substrate, then the AI.** The single most important framing:

> "I deliberately built the deterministic layer *first* — parsing, 19 grounded
> rules, cited findings. The LLM sits on top of that substrate and reasons over
> the parsed facts, so it physically cannot invent a misconfiguration. Any config
> it generates is linted against real IOS verbs before it touches a router. That's
> the difference between a credible tool and an LLM wrapper."

Then the three-pillar story in one breath:

1. **Audit** — "Deterministic, testable, CI-ready. Every finding cites a config
   line and maps to a CIS control. No hallucination."
2. **AI layer** — "Grounded QA and natural-language→config over the parsed model.
   The model never sees raw config, only structured facts. Output is validated."
3. **Reachability** — "Computes — doesn't guess — whether host A reaches host B
   across a multi-device path, evaluating full Cisco ACL semantics and citing the
   exact rule that decides the flow."

**The closer:** "It hits networking depth (IOS/PAN-OS, ACLs, topology), security
depth (posture, segmentation, App-ID, CIS), and AI depth (grounded retrieval,
validation) — and it's the same project, not three demos stapled together."

---

## 3. Why this lands for BOTH Cisco and Palo Alto

The project sits exactly on the seam where their businesses overlap — that's the
point of the design.

| Audience | What they see in Sentinel |
|---|---|
| **Cisco** | IOS/IOS-XE parsing, ACL semantics, topology inference, intent-based-config (their "DNA Center / Catalyst Center" story, LLM-native) |
| **Palo Alto** | PAN-OS security policy, App-ID/Zone/segmentation posture, Zero-Trust-adjacent analysis (their "Precision AI / Cortex / ZTNA" story) |
| **Both** | "AI for SecOps" — the exact territory both are investing in. Grounded, validated, multi-vendor. |

If asked "why multi-vendor?": *because real networks are heterogeneous. A
single-vendor auditor is a toy; the normalized `Device` model is the asset that
makes a second parser a small addition rather than a rewrite.*

---

## 4. Demo walkthrough (≈4 minutes)

Run these live. Each makes a distinct point.

```bash
# (1) The audit — deterministic, cited, CI-friendly exit code
sentinel scan tests/fixtures/bad_router.cfg --fix
#    → posture 0/100, 13 findings each citing a line + a ready remediation script

# (2) Same tool, different vendor — autodetect, no code change
sentinel scan tests/fixtures/pa_fw_bad.cfg
#    → Palo Alto, any-any CRITICAL, App-ID bypass findings

# (3) The AI layer — grounded, not hallucinating
#     (set SENTINEL_LLM_API_KEY first)
sentinel ask tests/fixtures/bad_router.cfg "what's the blast radius of the OUTSIDE-IN ACL?"
#    → answer cites the exact 'permit ip any any' rule + the finding ID

# (4) Reachability — computed end-to-end
sentinel topo tests/fixtures/topo_edge.cfg tests/fixtures/topo_core.cfg
sentinel reach --src 10.0.1.50 --dst 10.0.2.50 --proto tcp --port 443 \
    tests/fixtures/topo_edge.cfg tests/fixtures/topo_core.cfg   # PERMITTED + cited rule
sentinel reach --src 10.0.1.50 --dst 10.0.2.50 --proto tcp --port 22  ...   # DENIED + cited rule

# (5) The dashboard
uv sync --extra web && sentinel web    # → browser: paste config, see score/findings/remediation
```

**The beat to hit on (1):** point at the exit code — "this drops into CI; a
critical finding fails the pipeline. That's ops maturity, not a script."

**The beat to hit on (3):** emphasize *grounding* — "I didn't ask the model to
read a config. I parsed it myself and handed the model facts. That's why the
answer is right."

---

## 5. Design decisions (the "why" behind choices — expect to be asked)

- **Deterministic rules first, LLM second.** Trust comes from the rules; the LLM
  is acceleration on a trustworthy substrate. Inverting that = unreviewable risk.
- **Normalized `Device` model as the contract.** Parsers emit it; rules, AI, and
  reachability all consume it. Adding PAN-OS was a new parser + rule file, not a
  refactor. *This is the architectural decision interviewers reward.*
- **Dataclasses, not Pydantic, for the core model.** Zero hard dependency, fast,
  no version churn. Pydantic is reserved for the web layer where validation matters.
- **Stdlib-only LLM client (`urllib`).** No `openai`/`requests` dep; works with
  any OpenAI-compatible endpoint (OpenAI, OpenRouter, Ollama, vLLM, LM Studio).
- **Grounding over RAG-lite.** The model receives a *compact structured summary*
  of the parsed device + findings, not a raw config blob — token-efficient and
  forces facts over prose.
- **Hallucination lint.** Generated config is checked against a known set of IOS
  verbs; leaked prose ("Sure! Here's the config:") is flagged before display.
- **Cisco wildcard ACL matching** (not just CIDR). `10.0.0.0 0.0.0.255` is
  decoded properly — this is the detail that shows you actually know IOS, not
  that you skimmed a tutorial.
- **Plugin registry for rules.** `@register("ios")` / `@register("panos")` — a
  check is one function. Extensibility is a first-class design goal.

---

## 6. "Why isn't this just an LLM wrapper?" (have this answer ready)

1. The findings are **computed**, not generated — reproducible, testable, and
   they cite real lines. `pytest` proves the behavior; an LLM output can't.
2. The LLM is **constrained**: grounded context + output lint. It cannot introduce
   a finding that isn't backed by config, and it cannot emit non-config prose.
3. Reachability is **deterministic graph computation** with zero LLM involvement —
   the answer is mathematically derivable and fully cited.
4. The whole thing **degrades gracefully**: no API key → still a full deterministic
   auditor + remediation generator. The AI is additive, not load-bearing.

---

## 7. Honest limitations — and how to frame them

Name these *proactively*. Framing a limitation well is worth more than hiding it.

- **PAN-OS parses set-format, not XML export.** *Frame:* "Set-format is what
  operators type and paste; XML-export support is a straightforward addition
  behind the same `Device` model — I scoped to set-format to ship the posture
  logic, which is the harder, more valuable part."
- **Reachability models inbound ACLs only** (egress, NAT, zone-firewall policy,
  routing-policy are out of scope). *Frame:* "Inbound is where 95% of filtering
  happens; the model is extensible to egress/NAT by adding more filter stages to
  the path evaluator."
- **Single-config topology inference** (adjacency by shared subnet); no STP/CDP/
  LLDP discovery. *Frame:* "I infer L3 adjacencies from connected subnets —
  enough to compute multi-hop reachability. richer discovery (CDP/LLDP) would feed
  the same graph."
- **No real production configs** (NDA-sensitive). *Frame:* "I built a synthetic
  generator with ground-truth injected flaws so detection can be scored for
  precision/recall — that rigor is itself a signal." *(This is true of the
  fixtures; the generator is a natural next step.)*
- **LLM quality is provider-dependent.** *Frame:* "That's exactly why the LLM is
  grounded and linted — to bound the blast radius of a weak model."

---

## 8. Future extensions (stretch roadmap — good "where would you take it?" answers)

Pick 1–2 to discuss; they show vision without overpromising.

- **PAN-OS XML export parser** — same `Device` model, real device backups.
- **Zone-based reachability** — extend the reachability engine from
  per-interface ACLs to PAN-OS zone-to-zone security policy + App-ID.
- **Synthetic config generator with scored precision/recall** — turn the fixtures
  into a parametrized fuzzer that injects known flaws and measures detection F1.
- **Topology knowledge graph + NL query** — "which devices still point NTP at the
  decommissioned server?" over a graph DB.
- **Agentic RCA** — an LLM agent that, given a symptom, runs `show` commands in a
  sandbox, correlates syslog + flows, and returns ranked hypotheses.
- **Zero-Trust segmentation analysis** — given asset identities + flows, recommend
  least-privilege microsegmentation policy.
- **Diff-aware scanning** — scan a config *change* and flag only newly-introduced
  risk (PR-time review, like a linter on a diff).
- **CI/CD native** — GitHub Action that scans pushed configs and fails on critical.

---

## 9. Verification summary (what was actually exercised)

- **36 unit tests** across parser, rules, agent, and topology — all green.
- **AI layer verified against a live model** (not just fakes): `ask` cited the
  exact ACL rule + finding ID; `remediate` produced valid IOS deltas that passed
  the verb-lint.
- **Reachability** exercised on a 2-device topology: permit + two distinct deny
  cases (intra-device ACL, cross-device block at first hop), each cited.
- **Web dashboard** driven headlessly: both IOS and PAN-OS examples render
  (score, severity badges, findings table, remediation script).
- **Multi-vendor** confirmed end-to-end: same `scan` command, autodetected
  vendor, correct rule set per OS.

---

## 10. Repo map (orientation)

```
sentinel/
  model.py          normalized Device (+ firewall objects: Zone, SecurityRule, Service)
  parsers/ios.py    Cisco IOS / IOS-XE parser
  parsers/panos.py  Palo Alto PAN-OS set-format parser
  rules/ios.py      14 IOS detection rules
  rules/panos.py    5 PAN-OS detection rules
  topology.py       network graph + ACL-aware reachability
  agent.py          grounding + grounded QA / NL→config + hallucination lint
  llm.py            OpenAI-compatible provider (stdlib)
  remediate.py      config-delta script builder
  report.py         rich + JSON rendering
  web.py            optional FastAPI dashboard
  cli.py            command surface (scan/ask/remediate/topo/reach/rules/web)
tests/
  fixtures/         IOS + PAN-OS + topology configs (bad + clean pairs)
  test_*.py         6 files, 36 cases
```

**Run everything:** `uv sync --all-extras && uv run pytest -q`
**Quick demo:** `sentinel scan tests/fixtures/bad_router.cfg --fix`
