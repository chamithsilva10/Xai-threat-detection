"""LLM backends and a robust structured-output caller.

OllamaBackend - Ollama cloud (https://ollama.com, needs OLLAMA_API_KEY) or a local Ollama server.
MockBackend   - deterministic, offline stand-in for tests, CI and demos without network access.
"""

from __future__ import annotations

import copy
import json
import re
import time
from typing import Any, Protocol, TypeVar

from pydantic import BaseModel, ValidationError

from .config import Settings

T = TypeVar("T", bound=BaseModel)


class LLMError(RuntimeError):
    pass


class LLMBackend(Protocol):
    name: str

    def chat(self, messages: list[dict], schema: dict, *, role: str, context: dict) -> str: ...


def inline_schema(schema: dict) -> dict:
    """Resolve $ref/$defs so every Ollama model (and llama.cpp grammars) accepts the schema."""
    defs = schema.get("$defs", {})

    def resolve(node):
        if isinstance(node, dict):
            if "$ref" in node:
                return resolve(copy.deepcopy(defs[node["$ref"].split("/")[-1]]))
            return {k: resolve(v) for k, v in node.items() if k != "$defs"}
        if isinstance(node, list):
            return [resolve(v) for v in node]
        return node

    return resolve(schema)


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------
class OllamaBackend:
    def __init__(self, settings: Settings):
        from ollama import Client  # imported lazily so offline mode needs no package

        if settings.is_cloud and not settings.api_key:
            raise LLMError("OLLAMA_API_KEY is not set. Put it in .env or the environment, "
                           "or point OLLAMA_HOST at a local Ollama server.")
        headers = {"Authorization": f"Bearer {settings.api_key}"} if settings.api_key else {}
        self.client = Client(host=settings.host, headers=headers, timeout=settings.request_timeout)
        self.model = settings.model
        self.name = f"ollama:{settings.model}@{settings.host}"

    def chat(self, messages, schema, *, role, context):
        from ollama import ResponseError

        try:
            resp = self.client.chat(model=self.model, messages=messages, format=schema,
                                    options={"temperature": 0, "seed": 42})
        except ResponseError as e:
            if e.status_code in (401, 403):
                raise LLMError(f"Ollama rejected the API key (HTTP {e.status_code}). "
                               "Check OLLAMA_API_KEY.") from e
            if e.status_code == 404:
                raise LLMError(f"Model '{self.model}' not found on {self.name}. "
                               "Run `ollama pull <model>` or pick another --model.") from e
            raise
        return resp.message.content or ""

    def ping(self) -> str:
        models = self.client.list()
        names = [m.model for m in getattr(models, "models", [])]
        return f"connected to {self.name}; {len(names)} models visible"


# ---------------------------------------------------------------------------
# Structured-output caller with validation feedback
# ---------------------------------------------------------------------------
_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


def _extract_json(text: str) -> Any:
    text = _FENCE.sub("", text.strip())
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            return json.loads(text[start:end + 1])
        raise


def call_agent(backend: LLMBackend, *, role: str, system: str, user: str, schema: type[T],
               context: dict | None = None, retries: int = 2) -> tuple[T, dict]:
    """Returns (validated_output, telemetry). Retries with the validation error fed back to the model."""
    json_schema = inline_schema(schema.model_json_schema())
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    telemetry = {"role": role, "attempts": 0, "errors": [], "latency_s": 0.0}
    t0 = time.perf_counter()

    for attempt in range(retries + 1):
        telemetry["attempts"] = attempt + 1
        raw = ""
        try:
            raw = backend.chat(messages, json_schema, role=role, context=context or {})
            result = schema.model_validate(_extract_json(raw))
            telemetry["latency_s"] = round(time.perf_counter() - t0, 2)
            return result, telemetry
        except LLMError:
            raise
        except (json.JSONDecodeError, ValidationError) as e:
            err = str(e).splitlines()[0] if isinstance(e, json.JSONDecodeError) else _short(e)
            telemetry["errors"].append(err)
            messages += [
                {"role": "assistant", "content": raw[:4000]},
                {"role": "user", "content": f"That response failed validation: {err}. "
                                            "Return ONLY one JSON object that matches the schema."},
            ]
        except Exception as e:  # network / server errors
            telemetry["errors"].append(f"{type(e).__name__}: {e}")
            time.sleep(min(2 ** attempt, 8))
    raise LLMError(f"{role} agent failed after {retries + 1} attempts: {telemetry['errors'][-1]}")


def _short(e: ValidationError) -> str:
    return "; ".join(f"{'.'.join(map(str, err['loc']))}: {err['msg']}" for err in e.errors()[:5])
