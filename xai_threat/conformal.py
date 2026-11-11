"""Selective-Risk Certification (Agent 05: Risk Scoring & Triage).

Implements rigorous finite-sample selective classification risk control
(Geifman & El-Yaniv, 2017; Angelopoulos et al., 2024).

Mathematical Formulation:
--------------------------
1. Ranking / Non-conformity score:
   s(x) = 1 - max_{c in Y} P(c | x)

2. Acceptance rule parameterized by threshold lambda:
   a_lambda(x) = 1 if s(x) <= lambda else 0

3. Selective classification risk:
   R(lambda) = P(hat{Y} != Y | a_lambda(X) = 1)
   Empirical estimate: hat{R}(lambda) = (1 / n_acc) * sum_{i: a_lambda(x_i)=1} L(hat{y}_i, y_i)

4. Exact Finite-Sample Statistical Certification:
   Uses the exact Clopper-Pearson one-sided Binomial Upper Confidence Bound
   with a pre-declared Bonferroni correction over K candidate thresholds:
     delta_k = delta / K
     UCB_{1 - delta_k}(k_errors, n_acc) = Beta.ppf(1 - delta_k, k_errors + 1, n_acc - k_errors)

   Guarantees under i.i.d. sampling:
     P(R(hat{lambda}) <= alpha) >= 1 - delta

5. Safety Requirements:
   - If no candidate qualifies (UCB <= alpha), certification is DISABLED.
   - A threshold of 1.0 is NEVER a silent fallback.
   - Zero accepted examples produces undefined risk, never certified coverage.
   - High confidence alone cannot bypass failed certification.
"""

from __future__ import annotations

from typing import Any, Callable, Sequence
import numpy as np
from scipy import stats

from .schemas import ConformalTriageResult, RiskDecision, Severity


def zero_one_loss(y_pred: str, y_true: str) -> float:
    """Standard 0-1 misclassification loss."""
    return 0.0 if y_pred == y_true else 1.0


def security_loss_function(y_pred: str, y_true: str) -> float:
    """Domain-specific cyber security loss function.
    0.0: correct prediction
    1.0: false negative (missed attack)
    0.5: false alarm on benign traffic
    0.3: incorrect attack categorization
    """
    if y_pred == y_true:
        return 0.0
    if y_true != "benign" and y_pred == "benign":
        return 1.0
    if y_true == "benign" and y_pred != "benign":
        return 0.5
    return 0.3


def clopper_pearson_upper_bound(k_errors: int, n_samples: int, delta: float) -> float:
    """Compute exact one-sided Clopper-Pearson Binomial Upper Confidence Bound at level 1 - delta."""
    if n_samples <= 0:
        return 1.0
    if k_errors >= n_samples:
        return 1.0
    if k_errors < 0:
        return 0.0
    return float(stats.beta.ppf(1.0 - delta, k_errors + 1, n_samples - k_errors))


class ConformalCalibrator:
    """Selective-Risk Certifier and Conformal Triage Engine."""

    def __init__(
        self,
        target_risk: float = 0.05,
        failure_probability: float = 0.01,
        min_accepted_samples: int = 15,
        loss_fn: Callable[[str, str], float] = zero_one_loss,
    ):
        self.target_risk = float(target_risk)
        self.failure_probability = float(failure_probability)
        self.min_accepted_samples = int(min_accepted_samples)
        self.loss_fn = loss_fn

        self.is_calibrated: bool = False
        self.is_certified: bool = False
        self.calibrated_threshold: float = 0.0
        self.empirical_calibration_risk: float = 0.0
        self.calibration_coverage: float = 0.0
        self.upper_confidence_bound: float = 1.0
        self.accepted_count: int = 0
        self.certification_history: list[dict[str, Any]] = []
        self.metadata: dict[str, Any] = {}

    def nonconformity_score(self, class_probabilities: dict[str, float]) -> float:
        if not class_probabilities:
            return 1.0
        top_p = max(class_probabilities.values())
        return float(np.clip(1.0 - top_p, 0.0, 1.0))

    def calibrate(
        self,
        X_cal_probs: list[dict[str, float]],
        y_true: Sequence[str],
        num_candidates: int = 50,
        candidates: Sequence[float] | None = None,
    ) -> dict[str, Any]:
        n_total = len(y_true)
        if n_total == 0:
            raise ValueError("Calibration set cannot be empty.")

        scores = np.array([self.nonconformity_score(p) for p in X_cal_probs], dtype=np.float64)
        preds = [max(p.items(), key=lambda t: t[1])[0] for p in X_cal_probs]
        losses = np.array([self.loss_fn(p, t) for p, t in zip(preds, y_true)], dtype=np.float64)

        if candidates is not None:
            cand_family = sorted(list({float(c) for c in candidates if 0.0 <= c <= 1.0}))
        else:
            grid = np.linspace(0.01, 0.99, num_candidates)
            cand_family = sorted(list(set(np.round(grid, 4))))

        K = len(cand_family)
        delta_k = self.failure_probability / float(K)

        history = []
        best_candidate: dict[str, Any] | None = None
        best_coverage = -1.0

        for lam in cand_family:
            accepted_mask = scores <= lam
            n_acc = int(np.sum(accepted_mask))

            if n_acc == 0:
                rec = {
                    "threshold": round(float(lam), 4),
                    "accepted_count": 0,
                    "coverage": 0.0,
                    "empirical_risk": None,
                    "ucb": 1.0,
                    "qualified": False,
                    "disqualification_reason": "Zero accepted examples",
                }
                history.append(rec)
                continue

            k_errors = int(np.sum(losses[accepted_mask] > 0.0))
            empirical_risk = float(k_errors / n_acc)
            coverage = float(n_acc / n_total)
            ucb = clopper_pearson_upper_bound(k_errors, n_acc, delta_k)

            qualified = (n_acc >= self.min_accepted_samples) and (ucb <= self.target_risk)
            disqualification_reason = ""
            if n_acc < self.min_accepted_samples:
                disqualification_reason = f"Sample size {n_acc} < min {self.min_accepted_samples}"
            elif ucb > self.target_risk:
                disqualification_reason = f"UCB {ucb:.4f} > target risk {self.target_risk:.4f}"

            rec = {
                "threshold": round(float(lam), 4),
                "accepted_count": n_acc,
                "error_count": k_errors,
                "coverage": round(coverage, 4),
                "empirical_risk": round(empirical_risk, 4),
                "ucb": round(ucb, 4),
                "qualified": qualified,
                "disqualification_reason": disqualification_reason,
            }
            history.append(rec)

            if qualified and coverage > best_coverage:
                best_candidate = rec
                best_coverage = coverage

        self.certification_history = history
        self.is_calibrated = True

        if best_candidate is not None:
            self.is_certified = True
            self.calibrated_threshold = float(best_candidate["threshold"])
            self.empirical_calibration_risk = float(best_candidate["empirical_risk"])
            self.calibration_coverage = float(best_candidate["coverage"])
            self.upper_confidence_bound = float(best_candidate["ucb"])
            self.accepted_count = int(best_candidate["accepted_count"])
        else:
            self.is_certified = False
            self.calibrated_threshold = 0.0
            self.empirical_calibration_risk = 0.0
            self.calibration_coverage = 0.0
            self.upper_confidence_bound = 1.0
            self.accepted_count = 0

        self.metadata = {
            "target_risk": self.target_risk,
            "target_risk_alpha": self.target_risk,
            "failure_probability_delta": self.failure_probability,
            "bonferroni_delta_k": delta_k,
            "num_candidates": K,
            "n_calibration": n_total,
            "is_certified": self.is_certified,
            "calibrated_threshold": self.calibrated_threshold,
            "calibration_coverage": self.calibration_coverage,
            "upper_confidence_bound": self.upper_confidence_bound,
            "empirical_calibration_risk": self.empirical_calibration_risk,
        }
        return self.metadata

    def triage(
        self,
        detection: Any = None,
        class_probabilities: dict[str, float] | None = None,
        label: str | None = None,
        anomaly_score: float | None = None,
        **kwargs,
    ) -> ConformalTriageResult:
        """Evaluate an alert for autonomous response eligibility under certified bounds."""
        probs = class_probabilities
        if isinstance(detection, dict):
            probs = detection
        elif probs is None and detection is not None:
            probs = getattr(detection, "class_probabilities", None)

        if probs is None:
            return ConformalTriageResult(
                nonconformity_score=1.0,
                calibrated_threshold=self.calibrated_threshold,
                target_risk=self.target_risk,
                empirical_calibration_risk=self.empirical_calibration_risk,
                eligible_for_auto_response=False,
                decision="ABSTAIN_AND_ESCALATE",
                abstain_reason="No probability distribution available for selective-risk evaluation",
                risk_band="high",
            )

        score = self.nonconformity_score(probs)

        # Check certification prerequisites
        if not self.is_calibrated or not self.is_certified:
            return ConformalTriageResult(
                nonconformity_score=round(score, 4),
                calibrated_threshold=round(self.calibrated_threshold, 4),
                target_risk=self.target_risk,
                empirical_calibration_risk=round(self.empirical_calibration_risk, 4),
                eligible_for_auto_response=False,
                decision="ABSTAIN_AND_ESCALATE",
                abstain_reason="Selective-risk certification not established (UCB > alpha or uncalibrated)",
                risk_band="high",
            )

        if score <= self.calibrated_threshold:
            return ConformalTriageResult(
                nonconformity_score=round(score, 4),
                calibrated_threshold=round(self.calibrated_threshold, 4),
                target_risk=self.target_risk,
                empirical_calibration_risk=round(self.empirical_calibration_risk, 4),
                eligible_for_auto_response=True,
                decision="AUTO_ELIGIBLE",
                abstain_reason="",
                risk_band="low" if score < 0.05 else "medium",
            )
        else:
            return ConformalTriageResult(
                nonconformity_score=round(score, 4),
                calibrated_threshold=round(self.calibrated_threshold, 4),
                target_risk=self.target_risk,
                empirical_calibration_risk=round(self.empirical_calibration_risk, 4),
                eligible_for_auto_response=False,
                decision="ABSTAIN_AND_ESCALATE",
                abstain_reason=(
                    f"Nonconformity score {score:.4f} exceeds certified threshold "
                    f"{self.calibrated_threshold:.4f} (risk cannot be bounded <= {self.target_risk:.2%})"
                ),
                risk_band="high",
            )

    def evaluate_test_set(
        self,
        X_test_probs: list[dict[str, float]],
        y_test: Sequence[str],
    ) -> dict[str, Any]:
        n_test = len(y_test)
        if n_test == 0:
            return {"error": "Test set is empty"}

        scores = np.array([self.nonconformity_score(p) for p in X_test_probs])
        preds = [max(p.items(), key=lambda t: t[1])[0] for p in X_test_probs]
        losses = np.array([self.loss_fn(p, t) for p, t in zip(preds, y_test)])

        if not self.is_certified:
            return {
                "n_test": n_test,
                "is_certified": False,
                "test_coverage": 0.0,
                "test_risk": None,
                "violation": False,
                "note": "Model was not certified on calibration data",
            }

        accepted_mask = scores <= self.calibrated_threshold
        n_acc = int(np.sum(accepted_mask))
        n_abstain = n_test - n_acc

        cov = float(n_acc / n_test)
        if n_acc > 0:
            k_errors = int(np.sum(losses[accepted_mask] > 0.0))
            empirical_test_risk = float(k_errors / n_acc)
        else:
            empirical_test_risk = 0.0

        violation = empirical_test_risk > self.target_risk

        return {
            "n_test": n_test,
            "accepted_count": n_acc,
            "abstained_count": n_abstain,
            "test_coverage": round(cov, 4),
            "test_risk": round(empirical_test_risk, 4),
            "target_risk": self.target_risk,
            "violation": violation,
            "calibrated_threshold": self.calibrated_threshold,
            "certified_ucb": self.upper_confidence_bound,
        }
