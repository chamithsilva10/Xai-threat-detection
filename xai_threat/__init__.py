"""Multi-Agent Explainable AI Framework for Autonomous Cyber Threat Detection.

Research Artefact implementing the Nine-Agent Architecture:
  01 Data Ingestion Agent
  02 Detection Agent (XGBoost)
  03 Explainability Agent (SHAP / LIME / Contrastive)
  04 Threat Intelligence Agent (MITRE ATT&CK / IOC)
  05 Risk Scoring & Triage Agent (Conformal Risk Control C9)
  08 LLM Analyst Agent (Claim-Evidence Ledger C1)
  09 LLM Verifier Agent (Cross-Model Verification)
  06 Response Orchestrator Agent (IoMT Safeguards C16 & SOAR Playbooks)
  07 Audit & Feedback Agent (SHA-256 Hash Chain & C4 Feedback)
"""

from .conformal import ConformalCalibrator
from .detection import Detection, ThreatDetector
from .ledger import ClaimEvidenceLedger
from .orchestrator import Investigation, Orchestrator
from .trust_score import calculate_explanation_trust_score

__version__ = "2.1.0"

__all__ = [
    "ThreatDetector",
    "Detection",
    "Orchestrator",
    "Investigation",
    "ClaimEvidenceLedger",
    "ConformalCalibrator",
    "calculate_explanation_trust_score",
]
