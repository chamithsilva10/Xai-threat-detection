"""Feature Extraction, Provenance, and Transformation Parity (Agent 01 & 02).

Implements Section 5 requirements:
- Documented origin, unit, aggregation window, and missing-value behavior for every model feature.
- Explicit distinction between missing values (None) and genuine zero values (0.0).
- Feature parity verification between training transformations and runtime serving.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any
import numpy as np

from .schemas import FeatureVector

PIPELINE_VERSION = "1.2.0"

# ---------------------------------------------------------------------------
# Feature Definition Metadata Registry (Section 5)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FeatureSpec:
    name: str
    origin: str
    unit: str
    aggregation_window: str
    missing_value_policy: str
    default_impute_value: float
    min_bound: float
    max_bound: float


MODEL_FEATURES: list[FeatureSpec] = [
    FeatureSpec(
        name="failed_logins",
        origin="SSH/OS authentication evidence (auth.log, Windows Event ID 4625)",
        unit="attempts",
        aggregation_window="60s sliding window per (src_ip, target_host)",
        missing_value_policy="Imputed to 0.0 (no failed authentications observed in window)",
        default_impute_value=0.0,
        min_bound=0.0,
        max_bound=10000.0,
    ),
    FeatureSpec(
        name="conn_rate",
        origin="Zeek conn.log / Suricata flow timestamps",
        unit="connections/second",
        aggregation_window="60s sliding window per (src_ip, dst_ip)",
        missing_value_policy="Imputed to normal network baseline 1.0",
        default_impute_value=1.0,
        min_bound=0.0,
        max_bound=5000.0,
    ),
    FeatureSpec(
        name="distinct_dst_ports",
        origin="Transport layer unique destination ports per src_ip",
        unit="port count",
        aggregation_window="60s window per src_ip",
        missing_value_policy="Imputed to 1.0 (single service interaction)",
        default_impute_value=1.0,
        min_bound=1.0,
        max_bound=65535.0,
    ),
    FeatureSpec(
        name="bytes_out_mb",
        origin="Network interface outbound payload octets (egress counter)",
        unit="megabytes (MB)",
        aggregation_window="Per network session or 60s summary",
        missing_value_policy="Imputed to 0.0 MB",
        default_impute_value=0.0,
        min_bound=0.0,
        max_bound=100000.0,
    ),
    FeatureSpec(
        name="dns_query_entropy",
        origin="DNS request query name Shannon entropy (-sum p log2 p)",
        unit="bits of information entropy",
        aggregation_window="Per query or aggregated mean over 30s",
        missing_value_policy="Imputed to standard English domain mean 2.50 bits",
        default_impute_value=2.50,
        min_bound=0.0,
        max_bound=8.0,
    ),
]

FEATURE_NAMES: list[str] = [f.name for f in MODEL_FEATURES]
FEATURE_SPEC_MAP: dict[str, FeatureSpec] = {f.name: f for f in MODEL_FEATURES}


class FeatureExtractor:
    """Extracts, validates, and vectors features with documented provenance and bounds."""

    def __init__(self, pipeline_version: str = PIPELINE_VERSION):
        self.version = pipeline_version
        self.feature_names = list(FEATURE_NAMES)

    def extract(self, raw_record: dict[str, Any], event_id: str = "evt-extract") -> FeatureVector:
        """Extract structured feature vector while explicitly preserving missing values as None."""
        raw_feats = raw_record.get("features", {})
        extracted: dict[str, float | None] = {}
        origins: dict[str, str] = {}
        windows: dict[str, str] = {}

        for spec in MODEL_FEATURES:
            val = raw_feats.get(spec.name)
            if val is None and spec.name in raw_record:
                val = raw_record[spec.name]

            if val is None or val == "":
                extracted[spec.name] = None  # Explicit missingness, not disguised as 0.0
            else:
                try:
                    f_val = float(val)
                    if not math.isfinite(f_val):
                        extracted[spec.name] = None
                    else:
                        # Clip to physical domain bounds
                        extracted[spec.name] = float(np.clip(f_val, spec.min_bound, spec.max_bound))
                except (ValueError, TypeError):
                    extracted[spec.name] = None

            origins[spec.name] = spec.origin
            windows[spec.name] = spec.aggregation_window

        return FeatureVector(
            event_id=event_id,
            feature_pipeline_version=self.version,
            features=extracted,
            feature_origins=origins,
            aggregation_windows=windows,
        )

    def vectorize(self, fv: FeatureVector | dict[str, Any]) -> np.ndarray:
        """Vectorize feature dictionary into a 2D float NumPy array for XGBoost serving.
        
        Applies explicit imputation policy for missing values.
        """
        feats = fv.features if isinstance(fv, FeatureVector) else fv.get("features", fv)
        row = []
        for spec in MODEL_FEATURES:
            v = feats.get(spec.name)
            if v is None:
                # Impute according to documented spec
                row.append(spec.default_impute_value)
            else:
                row.append(float(v))
        return np.array([row], dtype=np.float32)

    def verify_parity(self, sample_dict: dict[str, Any]) -> tuple[bool, str]:
        """Verify serving-training parity for a feature dictionary."""
        fv = self.extract(sample_dict)
        vec1 = self.vectorize(fv)
        vec2 = self.vectorize(sample_dict)
        if not np.allclose(vec1, vec2):
            return False, f"Parity mismatch: vector from FeatureVector {vec1} != vector from raw dict {vec2}"
        return True, "Parity confirmed"
