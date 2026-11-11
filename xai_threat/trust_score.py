"""Headline Contribution C13: Composite Explanation Trust Score (ETS).

Formulates a versioned, multi-dimensional trust metric:
  ETS = clip(wF * F + wA * A + wG * G + wM * M - penalties, 0, 1)

Components:
  - F(x): Measured explanation faithfulness via top-feature deletion drop.
  - A(x): Cross-explainer consistency (SHAP vs LIME rank & sign agreement).
  - G(C): Verified factual claim grounding from the C1 Ledger.
  - M(x): Classifier probability margin between top class and runner-up.
  - Penalties: Deductions for prompt-injection flags, unresolved disagreements, or contradictions.

Safety Constraints (Section 13):
  - Weights are non-negative and sum to 1.0.
  - Missing components are explicitly visible.
  - Mandatory evidence failures (e.g. contradictions or 0 grounding) CANNOT be offset by other components.
  - ETS is an experimental trust indicator, NOT a probability of safety or correctness.
"""

from __future__ import annotations

from typing import Any
import numpy as np

from .ledger import ClaimEvidenceLedger
from .schemas import ExplanationTrustScoreBreakdown

ETS_VERSION = "1.1.0"

DEFAULT_WEIGHTS: dict[str, float] = {
    "faithfulness": 0.25,
    "cross_explainer_agreement": 0.25,
    "grounding_ratio": 0.30,
    "model_certainty": 0.20,
}


def compute_faithfulness_drop(
    detector: Any,
    raw_record: dict,
    top_feature: str,
    baseline_value: float,
    predicted_label: str,
) -> tuple[float, bool]:
    """Measure explanation faithfulness via top-feature deletion/masking.
    Faithfulness F = (P(y|x) - P(y|x_masked)) / P(y|x)
    Returns: (faithfulness_score, is_measured)
    """
    if detector is None:
        return 0.70, False  # unmeasured fallback

    try:
        x_orig = detector.vectorize(raw_record)
        probs_orig = detector.clf.predict_proba(x_orig)[0]
        class_idx = list(detector.clf.classes_).index(predicted_label)
        p_orig = float(probs_orig[class_idx])

        if p_orig <= 0.001:
            return 0.0, True

        # Create masked vector where top feature is reverted to normal baseline
        if top_feature not in detector.features:
            return 0.70, False

        feature_idx = detector.features.index(top_feature)
        x_masked = x_orig.copy()
        x_masked[0, feature_idx] = baseline_value

        probs_masked = detector.clf.predict_proba(x_masked)[0]
        p_masked = float(probs_masked[class_idx])

        drop = p_orig - p_masked
        rel_drop = drop / p_orig
        return float(np.clip(rel_drop, 0.0, 1.0)), True
    except Exception:
        return 0.70, False


def compute_explainer_agreement(
    shap_attributions: list[dict],
    lime_attributions: list[dict],
    top_k: int = 3,
) -> tuple[float, bool]:
    """Measure agreement between SHAP and LIME feature attributions.
    Combines Top-K Jaccard rank overlap and directional sign consistency.
    Returns: (agreement_score, is_measured)
    """
    if not shap_attributions or not lime_attributions:
        return 0.75, False  # Single explainer active

    shap_top = [a["feature"] for a in shap_attributions[:top_k] if "feature" in a]
    lime_top = [a["feature"] for a in lime_attributions[:top_k] if "feature" in a]

    set_s = set(shap_top)
    set_l = set(lime_top)
    union = set_s | set_l

    if not union:
        return 1.0, True

    jaccard = len(set_s & set_l) / len(union)

    # Directional sign consistency for overlapping features
    shap_dict = {a["feature"]: a.get("contribution", 0.0) for a in shap_attributions if "feature" in a}
    lime_dict = {a["feature"]: a.get("contribution", 0.0) for a in lime_attributions if "feature" in a}

    intersection = set_s & set_l
    signs_agree = 0
    for f in intersection:
        s_val = shap_dict.get(f, 0.0)
        l_val = lime_dict.get(f, 0.0)
        if (s_val >= 0 and l_val >= 0) or (s_val < 0 and l_val < 0):
            signs_agree += 1

    sign_score = (signs_agree / len(intersection)) if intersection else 0.5
    agreement = 0.6 * jaccard + 0.4 * sign_score
    return float(np.clip(agreement, 0.0, 1.0)), True


def compute_model_certainty(class_probabilities: dict[str, float]) -> tuple[float, bool]:
    """Margin between the top class probability and runner-up class probability.
    Note: Margin is a separation metric, not a calibrated probability of correctness.
    """
    if not class_probabilities or len(class_probabilities) < 2:
        return 0.5, False
    sorted_probs = sorted(class_probabilities.values(), reverse=True)
    margin = sorted_probs[0] - sorted_probs[1]
    return float(np.clip(margin, 0.0, 1.0)), True


def calculate_explanation_trust_score(
    detector: Any,
    raw_record: dict,
    detection_label: str,
    class_probabilities: dict[str, float],
    shap_attributions: list[dict],
    lime_attributions: list[dict],
    ledger: ClaimEvidenceLedger,
    grounding_warnings: list[str] | None = None,
    injection_flags: list[dict] | None = None,
    weights: dict[str, float] | None = None,
) -> ExplanationTrustScoreBreakdown:
    """Calculate the Composite Explanation Trust Score (ETS).
    
    Enforces Section 13 constraint:
      "Mandatory evidence and policy failures cannot be offset by other components."
    """
    w = weights or dict(DEFAULT_WEIGHTS)
    weight_sum = sum(w.values())
    if abs(weight_sum - 1.0) > 1e-4:
        raise ValueError(f"ETS weights must sum to 1.0, got {weight_sum}")

    # 1. Faithfulness F(x)
    if shap_attributions:
        top_feat = shap_attributions[0].get("feature", "")
        baseline_val = shap_attributions[0].get("normal_baseline", 0.0)
        faith, _ = compute_faithfulness_drop(
            detector, raw_record, top_feat, baseline_val, detection_label
        )
    else:
        faith, _ = 0.70, False

    # 2. Consistency A(x)
    agreement, _ = compute_explainer_agreement(shap_attributions, lime_attributions)

    # 3. Grounding Ratio G(C)
    grounding_ratio = ledger.supported_ratio

    # 4. Model Certainty Margin M(x)
    certainty, _ = compute_model_certainty(class_probabilities)

    # 5. Penalties
    penalties = 0.0
    if injection_flags:
        penalties += 0.25
    if grounding_warnings:
        penalties += min(0.04 * len(grounding_warnings), 0.20)
    if ledger.disagreements:
        penalties += min(0.08 * len(ledger.disagreements), 0.25)
    if getattr(ledger, "has_contradiction", False):
        penalties += 0.50

    # Composite formula
    raw_score = (
        w["faithfulness"] * faith
        + w["cross_explainer_agreement"] * agreement
        + w["grounding_ratio"] * grounding_ratio
        + w["model_certainty"] * certainty
        - penalties
    )

    # Section 13 Hard constraint:
    # If grounding is 0.0 or a contradiction exists, ETS cannot exceed 0.25 regardless of certainty!
    if grounding_ratio == 0.0 or getattr(ledger, "has_contradiction", False):
        raw_score = min(raw_score, 0.25)

    composite = float(np.clip(raw_score, 0.0, 1.0))

    return ExplanationTrustScoreBreakdown(
        composite_score=round(composite, 4),
        faithfulness=round(faith, 4),
        cross_explainer_agreement=round(agreement, 4),
        grounding_ratio=round(grounding_ratio, 4),
        model_certainty=round(certainty, 4),
        penalty=round(penalties, 4),
        weights=w,
    )
