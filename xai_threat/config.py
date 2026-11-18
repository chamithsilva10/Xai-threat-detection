"""Runtime configuration. Secrets come from the environment or a local .env file, never from code."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_dotenv(*paths: Path) -> None:
    """Minimal .env loader (no extra dependency). Real environment variables win over the file."""
    for path in paths:
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip().removeprefix("export ").strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


load_dotenv(Path.cwd() / ".env", PROJECT_ROOT / ".env")


def _csv_set(value: str) -> frozenset[str]:
    return frozenset(v.strip() for v in value.split(",") if v.strip())


@dataclass(frozen=True)
class Settings:
    # Core LLM provider configurations (Section 12: Dual-LLM configuration)
    analyst_provider: str = "ollama"
    analyst_model: str = "llama3.1:8b"
    analyst_api_key: str | None = None
    verifier_provider: str = "ollama"
    verifier_model: str | None = None
    verifier_api_key: str | None = None

    # Legacy & Direct Model Aliases
    model: str = "llama3.1:8b"
    host: str = "http://localhost:11434"
    api_key: str | None = None
    offline: bool = False
    operating_mode: str = "REPLAY"
    mode: str = "REPLAY"
    request_timeout: float = 120.0
    max_retries: int = 2
    max_revision_rounds: int = 2          # analyst <-> critic debate rounds
    token_limit: int = 4096
    redact_sensitive_telemetry: bool = True
    max_field_len: int = 500              # truncate attacker-controlled strings
    alert_threshold: float = 0.70         # ML confidence needed to raise an alert
    audit_log: Path = PROJECT_ROOT / "runs" / "audit_log.jsonl"
    pending_queue: Path = PROJECT_ROOT / "runs" / "pending_actions.jsonl"
    reports_dir: Path = PROJECT_ROOT / "runs" / "reports"
    model_path: Path = PROJECT_ROOT / "models" / "detector.joblib"
    ioc_feed: Path = PROJECT_ROOT / "data" / "ioc_feed.json"
    critical_assets: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_env(cls, **overrides) -> "Settings":
        env = os.environ
        analyst_prov = env.get("ANALYST_LLM_PROVIDER", "ollama")
        analyst_mod = env.get("ANALYST_LLM_MODEL", env.get("OLLAMA_MODEL", cls.model))
        analyst_key = env.get("ANALYST_LLM_API_KEY", env.get("OLLAMA_API_KEY"))

        verifier_prov = env.get("VERIFIER_LLM_PROVIDER", analyst_prov)
        verifier_mod = env.get("VERIFIER_LLM_MODEL", env.get("OLLAMA_VERIFIER_MODEL"))
        verifier_key = env.get("VERIFIER_LLM_API_KEY", analyst_key)

        values = dict(
            analyst_provider=analyst_prov,
            analyst_model=analyst_mod,
            analyst_api_key=analyst_key,
            verifier_provider=verifier_prov,
            verifier_model=verifier_mod,
            verifier_api_key=verifier_key,
            model=analyst_mod,
            host=env.get("OLLAMA_HOST", cls.host).rstrip("/"),
            api_key=analyst_key,
            offline=env.get("OFFLINE_MODE", "false").lower() in ("true", "1", "yes"),
            operating_mode=env.get("OPERATING_MODE", env.get("MODE", "REPLAY")).upper(),
            mode=env.get("OPERATING_MODE", env.get("MODE", "REPLAY")).upper(),
            request_timeout=float(env.get("OLLAMA_TIMEOUT", cls.request_timeout)),
            max_retries=int(env.get("MAX_RETRIES", cls.max_retries)),
            max_revision_rounds=int(env.get("MAX_REVISION_ROUNDS", cls.max_revision_rounds)),
            token_limit=int(env.get("LLM_TOKEN_LIMIT", cls.token_limit)),
            redact_sensitive_telemetry=env.get("REDACT_TELEMETRY", "true").lower() in ("true", "1", "yes"),
            alert_threshold=float(env.get("ALERT_THRESHOLD", cls.alert_threshold)),
            critical_assets=_csv_set(env.get("CRITICAL_ASSETS", "10.0.0.5,10.0.0.10,dc01,db-prod-01")),
        )
        if env.get("AUDIT_LOG"):
            values["audit_log"] = Path(env["AUDIT_LOG"])
        values.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**values)

    @property
    def is_cloud(self) -> bool:
        return not (
            self.host.startswith("http://localhost")
            or self.host.startswith("http://127.0.0.1")
            or self.host.startswith("http://0.0.0.0")
        )
