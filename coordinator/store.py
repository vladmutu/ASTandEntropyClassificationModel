from __future__ import annotations

import base64
from typing import Optional

import redis as redis_lib

JOB_TTL = 3600  # seconds — used for upload expiry
VALID_ECOSYSTEMS = {"npm", "pypi"}
UPLOAD_SIZE_LIMIT = 100 * 1024 * 1024  # 100 MB
ALLOWED_UPLOAD_SUFFIXES = {".tar.gz", ".tgz", ".zip", ".whl"}


def upload_redis_key(job_id: str, pkg_key: str) -> str:
    return f"job:{job_id}:upload:{pkg_key}"


def make_pkg_key(name: str, version: Optional[str], ecosystem: str) -> str:
    return f"{ecosystem.lower()}:{name}:{version or 'latest'}"


def store_upload(r: redis_lib.Redis, job_id: str, pkg_key: str, data: bytes) -> None:
    key = upload_redis_key(job_id, pkg_key)
    r.set(key, base64.b64encode(data).decode("ascii"))
    r.expire(key, JOB_TTL)


def get_upload(r: redis_lib.Redis, job_id: str, pkg_key: str) -> Optional[bytes]:
    val = r.get(upload_redis_key(job_id, pkg_key))
    return base64.b64decode(val) if val else None
