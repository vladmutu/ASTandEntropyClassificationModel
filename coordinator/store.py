from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Optional

import redis as redis_lib

from coordinator.models import JobResponse, PackageResult

JOB_TTL = 3600  # seconds
VALID_ECOSYSTEMS = {"npm", "pypi"}
UPLOAD_SIZE_LIMIT = 100 * 1024 * 1024  # 100 MB
ALLOWED_UPLOAD_SUFFIXES = {".tar.gz", ".tgz", ".zip", ".whl"}


def pkg_redis_key(job_id: str, pkg_key: str) -> str:
    return f"job:{job_id}:pkg:{pkg_key}"


def job_meta_key(job_id: str) -> str:
    return f"job:{job_id}:meta"


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


def create_job(r: redis_lib.Redis, job_id: str, packages: list[dict]) -> None:
    pipe = r.pipeline()
    meta = job_meta_key(job_id)
    pipe.hset(meta, mapping={
        "status": "pending",
        "total": str(len(packages)),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    pipe.expire(meta, JOB_TTL)

    for pkg in packages:
        pk = make_pkg_key(pkg["name"], pkg.get("version"), pkg["ecosystem"])
        key = pkg_redis_key(job_id, pk)
        pipe.hset(key, mapping={"status": "pending", "name": pkg["name"],
                                 "version": pkg.get("version") or "", "ecosystem": pkg["ecosystem"].lower()})
        pipe.expire(key, JOB_TTL)

    pipe.execute()


def get_job(r: redis_lib.Redis, job_id: str) -> Optional[JobResponse]:
    meta = r.hgetall(job_meta_key(job_id))
    if not meta:
        return None

    pkg_keys = list(r.scan_iter(f"job:{job_id}:pkg:*"))

    packages: list[PackageResult] = []
    if pkg_keys:
        pipe = r.pipeline()
        for pk in pkg_keys:
            pipe.hgetall(pk)
        all_data = pipe.execute()

        for data in all_data:
            if not data:
                continue

            features: Optional[dict] = None
            raw_features = data.get("features")
            if raw_features:
                try:
                    features = json.loads(raw_features)
                except (json.JSONDecodeError, TypeError):
                    pass

            raw_prob = data.get("probability")
            packages.append(PackageResult(
                name=data.get("name", ""),
                version=data.get("version") or None,
                ecosystem=data.get("ecosystem", ""),
                status=data.get("status", "pending"),
                verdict=data.get("verdict") or None,
                probability=float(raw_prob) if raw_prob else None,
                features=features,
                error=data.get("error") or None,
            ))

    done_count = sum(1 for p in packages if p.status in ("done", "error"))
    total = int(meta.get("total", 0))
    all_done = total > 0 and done_count == total

    return JobResponse(
        job_id=job_id,
        status="done" if all_done else ("running" if done_count > 0 else "pending"),
        total=total,
        done=done_count,
        created_at=datetime.fromisoformat(meta["created_at"]),
        packages=packages,
    )


def delete_job(r: redis_lib.Redis, job_id: str) -> bool:
    meta = job_meta_key(job_id)
    if not r.exists(meta):
        return False

    pipe = r.pipeline()
    pipe.delete(meta)
    for pk in r.scan_iter(f"job:{job_id}:pkg:*"):
        pipe.delete(pk)
    for uk in r.scan_iter(f"job:{job_id}:upload:*"):
        pipe.delete(uk)
    pipe.execute()
    return True
