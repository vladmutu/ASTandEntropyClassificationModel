from __future__ import annotations

import json
import os
from typing import Optional

import joblib
import numpy as np
import redis as redis_lib

MODEL_PATH = os.getenv("MODEL_PATH", "lightgbm_model.pkl")
THRESHOLD_PATH = os.getenv("THRESHOLD_PATH", "lightgbm_threshold.pkl")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
JOB_TTL = 3600

_model = None
_threshold: float | None = None
_feature_columns: list[str] | None = None


def _load_model():
    global _model, _threshold, _feature_columns
    if _model is None:
        _model = joblib.load(MODEL_PATH)
        threshold_data = joblib.load(THRESHOLD_PATH)
        _threshold = float(threshold_data["threshold"])
        _feature_columns = list(threshold_data["feature_columns"])
    return _model, _threshold, _feature_columns


def _get_redis() -> redis_lib.Redis:
    return redis_lib.from_url(REDIS_URL, decode_responses=True)


def _update_pkg(
    r: redis_lib.Redis,
    job_id: str,
    pkg_key: str,
    **fields,
) -> None:
    key = f"job:{job_id}:pkg:{pkg_key}"
    serialized = {}
    for k, v in fields.items():
        if isinstance(v, (dict, list)):
            serialized[k] = json.dumps(v)
        elif v is None:
            serialized[k] = ""
        else:
            serialized[k] = str(v)
    pipe = r.pipeline()
    pipe.hset(key, mapping=serialized)
    pipe.expire(key, JOB_TTL)
    pipe.execute()


def analyze_package(
    job_id: str,
    pkg_key: str,
    name: str,
    version: Optional[str],
    ecosystem: str,
) -> dict:
    """RQ task: download → extract → classify a single package.

    Timeout is enforced by RQ (job_timeout set at enqueue time).
    Results are written back to Redis so the coordinator can serve them.
    """
    r = _get_redis()
    _update_pkg(r, job_id, pkg_key, status="running")

    try:
        model, threshold, feature_columns = _load_model()

        from worker.pipeline import build_feature_vector

        max_entropy, avg_entropy, ast_counts = build_feature_vector(name, version, ecosystem)

        features: dict[str, float] = {
            "max_entropy": max_entropy,
            "avg_entropy": avg_entropy,
        }
        features.update({k: float(v) for k, v in ast_counts.items()})

        # Engineered features — must match the training notebook exactly
        features["entropy_gap"] = max_entropy - avg_entropy
        features["exec_eval_ratio"] = features.get("exec_count", 0.0) / (features.get("eval_count", 0.0) + 1.0)
        features["network_exec_ratio"] = features.get("network_call_count", 0.0) / (features.get("exec_count", 0.0) + 1.0)
        features["obfuscation_index"] = features["entropy_gap"] * float(np.log1p(features.get("base64_count", 0.0)))

        # Build the feature vector in column order from training
        X = np.array([[features.get(col, 0.0) for col in feature_columns]])
        prob = float(model.predict_proba(X)[0, 1])
        verdict = "malicious" if prob >= threshold else "benign"

        _update_pkg(
            r, job_id, pkg_key,
            status="done",
            verdict=verdict,
            probability=prob,
            features=features,
        )
        return {"verdict": verdict, "probability": prob}

    except Exception as exc:
        _update_pkg(r, job_id, pkg_key, status="error", error=str(exc))
        raise


def analyze_uploaded_package(
    job_id: str,
    pkg_key: str,
    name: str,
    filename: str,
) -> dict:
    """RQ task: classify a package uploaded directly as an archive file."""
    import base64
    import tempfile
    from pathlib import Path

    from worker.pipeline import build_feature_vector_from_file

    r = _get_redis()
    _update_pkg(r, job_id, pkg_key, status="running")

    try:
        model, threshold, feature_columns = _load_model()

        upload_key = f"job:{job_id}:upload:{pkg_key}"
        raw = r.get(upload_key)
        if raw is None:
            raise ValueError("Upload data not found in Redis (may have expired)")
        data = base64.b64decode(raw)

        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / filename
            dest.write_bytes(data)
            max_entropy, avg_entropy, ast_counts = build_feature_vector_from_file(dest)

        r.delete(upload_key)

        features: dict[str, float] = {"max_entropy": max_entropy, "avg_entropy": avg_entropy}
        features.update({k: float(v) for k, v in ast_counts.items()})
        features["entropy_gap"] = max_entropy - avg_entropy
        features["exec_eval_ratio"] = features.get("exec_count", 0.0) / (features.get("eval_count", 0.0) + 1.0)
        features["network_exec_ratio"] = features.get("network_call_count", 0.0) / (features.get("exec_count", 0.0) + 1.0)
        features["obfuscation_index"] = features["entropy_gap"] * float(np.log1p(features.get("base64_count", 0.0)))

        X = np.array([[features.get(col, 0.0) for col in feature_columns]])
        prob = float(model.predict_proba(X)[0, 1])
        verdict = "malicious" if prob >= threshold else "benign"

        _update_pkg(r, job_id, pkg_key, status="done", verdict=verdict, probability=prob, features=features)
        return {"verdict": verdict, "probability": prob}

    except Exception as exc:
        _update_pkg(r, job_id, pkg_key, status="error", error=str(exc))
        raise
