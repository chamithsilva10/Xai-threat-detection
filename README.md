# Multi-Agent Explainable AI Framework for Autonomous Cyber Threat Detection

A nine-agent explainable artificial intelligence (XAI) framework that connects network intrusion detection, understandable evidence, selective risk-controlled escalation, and auditable response decisions.

```
01 Data Ingestion Agent       (schema validation + prompt-injection scan + provenance)
       │
02 Detection Agent            (XGBoost classifier + IsolationForest anomaly scoring)
       │
03 Explainability Agent       (SHAP TreeExplainer + LIME attributions + C10 contrastive)
       │
04 Threat Intelligence Agent  (rule-grounded MITRE ATT&CK mapping + IOC enrichment)
       │
05 Risk Scoring & Triage Agent(C9 Conformal Risk-Controlled Abstention)
       │
08 LLM Analyst Agent ◄──────► 09 Independent LLM Verifier Agent (Debate loop + C1 Ledger)
       │
06 Response Orchestrator Agent(policy gate + C16 IoMT medical safeguards + SOAR playbooks)
       │
07 Audit & Feedback Agent     (hash-chained ledger log + C4 feedback + C13 Trust Score)
```

---

## 🔬 Core Theoretical & Scientific Innovations

| Contribution | Mathematical Formulation | Scientific Guarantee |
|---|---|---|
| **C1: Typed Claim–Evidence Ledger** | $\mathcal{L} = \{ (c_i, \mathcal{P}_i, v_i, h_i) \}_{i=1}^N$ using RFC 6901 JSON Pointers $\mathcal{P}_i$, deterministic numerical validation, and RFC 8785 Canonical JSON SHA-256 fingerprinting. | Prevents LLM hallucinations; every assertion is bound to verifiable telemetry; zero-claims sets receive 0.0 grounding; contradictions void grounding. |
| **C9: Selective-Risk Certification** | Ranks uncertainty via nonconformity score $s(x) = 1 - \max_c P(c|x)$. Tests candidate family $\Lambda$ using exact Clopper-Pearson Binomial Upper Confidence Bounds with Bonferroni correction: $\text{UCB}_{1-\delta/K}(k_{err}, n_{acc}) \le \alpha$. | Guarantees under i.i.d. sampling that selective classification error on automatically handled alerts $\mathbb{E}[L \mid a_{\hat{\lambda}}(X)=1] \le \alpha$ with probability $\ge 1 - \delta$. Never silently defaults to 1.0. |
| **C13: Composite Explanation Trust Score (ETS)** | $\text{ETS} = \text{clip}(w_F F(x) + w_A A(x) + w_G G(C) + w_M M(x) - \text{penalties}, 0, 1)$ connecting top-feature deletion drop faithfulness $F(x)$, cross-explainer consistency $A(x)$, ledger grounding $G(C)$, and margin certainty $M(x)$. | Evaluates multi-dimensional explanation validity; mandatory evidence failures (contradictions or 0 grounding) cannot be masked by model confidence. |
| **C16: IoMT Clinical Patient Safeguards** | Maintained asset registry cross-referenced against hospital inventory. Prohibits autonomous disruption (isolation, shutdown, throttling) on life-critical devices (`infusion-pump-01`, `ventilator-icu-02`). | Enforces medical safety; requires joint clinical engineering and medical director authorization workflows before altering network state. |

---

## 🏛️ The Nine Agents

| Agent ID | Name | Role & Output |
|---|---|---|
| **01** | **Data Ingestion** | Normalizes events, validates strict Pydantic schemas, handles partial lines and file rotation, and flags prompt-injection patterns in untrusted fields. |
| **02** | **Detection** | Native multi-class XGBoost classifier predicting 5 canonical classes (`benign`, `c2_beaconing`, `data_exfiltration`, `port_scan`, `ssh_bruteforce`) and Isolation Forest computing anomaly score percentiles relative to benign baselines. |
| **03** | **Explainability** | TreeSHAP exact Shapley values with margin reconstruction verification ($f(x) = \text{base} + \sum \phi_i$), LIME tabular surrogates, and C10 contrastive counterfactuals. |
| **04** | **Threat Intelligence** | MITRE ATT&CK technique mapping with explicit evidence pointers, IOC lookups with provenance tracking, and maintained Asset Registry lookup. |
| **05** | **Risk Scoring & Triage** | Evaluates nonconformity score $s(x)$ against certified threshold $\hat{\lambda}$; marks alerts `AUTO_ELIGIBLE` or enforces `ABSTAIN_AND_ESCALATE`. |
| **08** | **LLM Analyst** | Synthesizes plain-language incident summary and outputs structured atomic claims bound to RFC 6901 JSON pointers. |
| **09** | **Independent LLM Verifier** | Independent model family evaluating claims against the raw evidence snapshot and participating in multi-round debate loops. |
| **06** | **Response Orchestrator** | Proposes SOAR playbooks, separates safe auto-actions from disruptive actions, enforces IoMT clinical safeguards, and binds actions to one-time cryptographic approval tokens. |
| **07** | **Audit & Feedback** | Writes every decision to an append-only JSONL log chained with SHA-256 hashes (RFC 8785 canonical serialization), and tracks Kolmogorov-Smirnov distribution drift. |

---

## 🚀 Quick Start & Environment Setup

### 1. Requirements & Activation
```bash
# Activate virtual environment
source .venv/bin/activate

# Verify dependencies
python -m pytest -v
```

### 2. Training the Detector & Calibrating Selective Risk
```bash
python threat_agents.py train --samples 1500 --target-risk 0.05
```

### 3. Running the 9 Mandated Demonstration Scenarios (Section 20)
```bash
python threat_agents.py demo-scenarios
```
This executes and verifies all 9 required operational scenarios:
1. **Benign Activity**: Normal HTTPS web/dev traffic; low severity; fast automated resolution.
2. **SSH Brute-Force Alert**: Real authentication evidence (`failed_logins = 212`); high severity; SHAP attribution isolation.
3. **Uncertain Anomaly**: Ambiguous flow with classification uncertainty ($s(x) > \hat{\lambda}$); selective risk control abstains and escalates.
4. **Unsupported Analyst Claim**: Verifier rejects hallucinated lateral movement claim; multi-round debate loop resolves within 2 rounds.
5. **Verifier Outage**: Verifier network failure; handled safely by fallback circuit breaker.
6. **Critical IoMT Medical Target**: Infusion pump telemetry tampering; C16 clinical safeguards strictly prohibit autonomous isolation.
7. **Disruptive Action Held for Approval**: Safe forensics and tickets auto-execute; IP block and credential reset are held for human sign-off.
8. **Dry-Run Authorized Remediation**: Human SOC lead authorizes remediation via a one-time cryptographically bound approval token.
9. **Tamper-Evident Audit Verification**: Validates the SHA-256 hash chain and confirms 0 tampering across all log entries.

---

## 🛠️ CLI Operations & Runbook

### Interactive Investigation & Detection
```bash
# Investigate a single alert JSON file
python threat_agents.py investigate --offline --evidence data/scenarios/ssh_bruteforce.json

# Score a CSV of network flows and investigate top alerts
python threat_agents.py detect --offline --flows data/sample_flows.csv --top 3
```

### Human-in-the-Loop Remediation & Approval
```bash
# Review pending remediation actions requiring human authorization
python threat_agents.py pending

# Authorize and execute remediation actions with cryptographically signed tokens
python threat_agents.py approve --alert-id all --analyst-id "soc_lead_chamith"
```

### Cryptographic Audit Verification
```bash
# Check the SHA-256 cryptographic hash chain of the audit log
python threat_agents.py verify-audit
```

---

## 🧪 Full 49-Test Verification Suite

The repository contains 49 automated unit and integration tests covering:
- XGBoost training & inference without data leakage
- TreeSHAP reconstruction in margin space ($|base + \sum \phi_i - f(x)| < 10^{-4}$)
- All 25 mandatory Section 18 test cases
- Statistical simulation of selective-risk certification under finite-sample bounds
- Benchmark evaluations across NSL-KDD, CIC-IDS2017, UNSW-NB15, and CICIoMT2024.

Run the entire test suite:
```bash
python -m pytest -v
```
All 49 tests pass in ~3 seconds.
