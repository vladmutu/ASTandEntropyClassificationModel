from __future__ import annotations

import os
from typing import Optional

import joblib
import numpy as np
import pandas as pd
import requests

MODEL_PATH = os.getenv("MODEL_PATH", "lightgbm_model.pkl")
THRESHOLD_PATH = os.getenv("THRESHOLD_PATH", "lightgbm_threshold.pkl")
COORDINATOR_URL = os.getenv("COORDINATOR_URL", "http://coordinator:8090")

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


def _post_result(callback_url: str, payload: dict) -> None:
    try:
        requests.post(callback_url, json=payload, timeout=10)
    except Exception as exc:
        print(f"[worker] WARNING: failed to deliver result to coordinator: {exc}", flush=True)


def analyze_package(
    job_id: str,
    package_uuid: str,
    name: str,
    version: Optional[str],
    ecosystem: str,
    callback_url: str,
) -> dict:
    """RQ task: download → extract → classify a single package, then POST result to coordinator."""
    try:
        model, threshold, feature_columns = _load_model()

        from worker.pipeline import build_feature_vector

        max_entropy, avg_entropy, ast_counts = build_feature_vector(name, version, ecosystem)

        features: dict[str, float] = {
            "max_entropy": max_entropy,
            "avg_entropy": avg_entropy,
        }
        features.update({k: float(v) for k, v in ast_counts.items()})

        features["entropy_gap"] = max_entropy - avg_entropy
        features["exec_eval_ratio"] = features.get("exec_count", 0.0) / (features.get("eval_count", 0.0) + 1.0)
        features["network_exec_ratio"] = features.get("network_call_count", 0.0) / (features.get("exec_count", 0.0) + 1.0)
        features["obfuscation_index"] = features["entropy_gap"] * float(np.log1p(features.get("base64_count", 0.0)))

        X = pd.DataFrame([[features.get(col, 0.0) for col in feature_columns]], columns=feature_columns)
        prob = float(model.predict_proba(X)[0, 1])
        verdict = "malicious" if prob >= threshold else "benign"

        result = {
            "package_uuid": package_uuid,
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "status": "done",
            "verdict": verdict,
            "probability": prob,
            "features": features,
            "error": None,
        }
        _post_result(callback_url, result)
        return result

    except Exception as exc:
        _post_result(callback_url, {
            "package_uuid": package_uuid,
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "status": "error",
            "verdict": None,
            "probability": None,
            "features": None,
            "error": str(exc),
        })
        raise


def analyze_uploaded_package(
    job_id: str,
    package_uuid: str,
    pkg_key: str,
    name: str,
    filename: str,
    callback_url: str,
) -> dict:
    """RQ task: classify a package uploaded directly as an archive file."""
    import base64
    import tempfile
    from pathlib import Path

    import redis as redis_lib

    from worker.pipeline import build_feature_vector_from_file

    redis_url = os.getenv("REDIS_URL", "redis://redis:6379")
    r = redis_lib.from_url(redis_url, decode_responses=True)

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

        X = pd.DataFrame([[features.get(col, 0.0) for col in feature_columns]], columns=feature_columns)
        prob = float(model.predict_proba(X)[0, 1])
        verdict = "malicious" if prob >= threshold else "benign"

        result = {
            "package_uuid": package_uuid,
            "name": name,
            "version": None,
            "ecosystem": "upload",
            "status": "done",
            "verdict": verdict,
            "probability": prob,
            "features": features,
            "error": None,
        }
        _post_result(callback_url, result)
        return result

    except Exception as exc:
        _post_result(callback_url, {
            "package_uuid": package_uuid,
            "name": name,
            "version": None,
            "ecosystem": "upload",
            "status": "error",
            "verdict": None,
            "probability": None,
            "features": None,
            "error": str(exc),
        })
        raise


def analyze_package_sync(name: str, version: Optional[str], ecosystem: str) -> dict:
    """Standalone sync wrapper used by worker/main.py HTTP server mode (no RQ, no Redis, no callback)."""
    model, threshold, feature_columns = _load_model()

    from worker.pipeline import build_feature_vector

    max_entropy, avg_entropy, ast_counts = build_feature_vector(name, version, ecosystem)

    features: dict[str, float] = {"max_entropy": max_entropy, "avg_entropy": avg_entropy}
    features.update({k: float(v) for k, v in ast_counts.items()})
    features["entropy_gap"] = max_entropy - avg_entropy
    features["exec_eval_ratio"] = features.get("exec_count", 0.0) / (features.get("eval_count", 0.0) + 1.0)
    features["network_exec_ratio"] = features.get("network_call_count", 0.0) / (features.get("exec_count", 0.0) + 1.0)
    features["obfuscation_index"] = features["entropy_gap"] * float(np.log1p(features.get("base64_count", 0.0)))

    X = pd.DataFrame([[features.get(col, 0.0) for col in feature_columns]], columns=feature_columns)
    prob = float(model.predict_proba(X)[0, 1])
    return {
        "verdict": "malicious" if prob >= threshold else "benign",
        "probability": prob,
        "features": features,
    }


def analyze_uploaded_package_sync(filename: str, data: bytes) -> dict:
    """Standalone sync wrapper used by worker/main.py HTTP server mode (no RQ, no Redis, no callback)."""
    import tempfile
    from pathlib import Path

    model, threshold, feature_columns = _load_model()

    from worker.pipeline import build_feature_vector_from_file

    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / filename
        dest.write_bytes(data)
        max_entropy, avg_entropy, ast_counts = build_feature_vector_from_file(dest)

    features: dict[str, float] = {"max_entropy": max_entropy, "avg_entropy": avg_entropy}
    features.update({k: float(v) for k, v in ast_counts.items()})
    features["entropy_gap"] = max_entropy - avg_entropy
    features["exec_eval_ratio"] = features.get("exec_count", 0.0) / (features.get("eval_count", 0.0) + 1.0)
    features["network_exec_ratio"] = features.get("network_call_count", 0.0) / (features.get("exec_count", 0.0) + 1.0)
    features["obfuscation_index"] = features["entropy_gap"] * float(np.log1p(features.get("base64_count", 0.0)))

    X = pd.DataFrame([[features.get(col, 0.0) for col in feature_columns]], columns=feature_columns)
    prob = float(model.predict_proba(X)[0, 1])
    return {
        "verdict": "malicious" if prob >= threshold else "benign",
        "probability": prob,
        "features": features,
    }
