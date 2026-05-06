from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import redis as redis_lib
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, status
from rq import Queue

from coordinator.models import JobResponse, JobSubmitRequest, PackageResult
from coordinator.store import (
    ALLOWED_UPLOAD_SUFFIXES,
    JOB_TTL,
    UPLOAD_SIZE_LIMIT,
    VALID_ECOSYSTEMS,
    create_job,
    delete_job,
    get_job,
    job_meta_key,
    make_pkg_key,
    pkg_redis_key,
    store_upload,
)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
QUEUE_NAME = os.getenv("QUEUE_NAME", "analysis")
JOB_TIMEOUT = int(os.getenv("JOB_TIMEOUT", "180"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "10"))
WORKER_IMAGE = os.getenv("WORKER_IMAGE", "")
WORKER_NETWORK = os.getenv("WORKER_NETWORK", "")

_redis: redis_lib.Redis | None = None
_queue: Queue | None = None


def _ensure_workers(num_packages: int) -> None:
    """Start burst worker containers up to min(num_packages, MAX_WORKERS).

    Workers use --burst so they exit (and auto-remove) when the queue empties.
    No-op when WORKER_IMAGE / WORKER_NETWORK are not configured (e.g. K8s).
    """
    if not WORKER_IMAGE or not WORKER_NETWORK:
        return
    desired = min(num_packages, MAX_WORKERS)
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        running = client.containers.list(
            filters={"label": "com.docker.compose.service=worker", "status": "running"}
        )
        to_start = desired - len(running)
        if to_start <= 0:
            return
        for _ in range(to_start):
            client.containers.run(
                image=WORKER_IMAGE,
                command=["rq", "worker", "analysis", "--url", REDIS_URL, "--burst"],
                detach=True,
                remove=True,
                network=WORKER_NETWORK,
                labels={"com.docker.compose.service": "worker"},
                environment={
                    "REDIS_URL": REDIS_URL,
                    "MODEL_PATH": "/app/lightgbm_model.pkl",
                    "THRESHOLD_PATH": "/app/lightgbm_threshold.pkl",
                    "DOWNLOAD_TIMEOUT": "30",
                },
                user="1000",
            )
        print(f"[scaling] started {to_start} burst worker(s) (total desired={desired})", flush=True)
    except Exception as exc:
        print(f"[scaling] WARNING: worker scaling failed: {exc}", flush=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _redis, _queue
    _redis = redis_lib.from_url(REDIS_URL, decode_responses=True)
    _queue = Queue(QUEUE_NAME, connection=redis_lib.from_url(REDIS_URL))
    yield
    _redis.close()


app = FastAPI(title="Malware Classifier Coordinator", version="1.0.0", lifespan=lifespan)


def _get_redis() -> redis_lib.Redis:
    assert _redis is not None
    return _redis


def _get_queue() -> Queue:
    assert _queue is not None
    return _queue


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/jobs/{job_id}", status_code=status.HTTP_202_ACCEPTED)
def submit_job(job_id: str, request: JobSubmitRequest):
    for pkg in request.packages:
        if pkg.ecosystem.lower() not in VALID_ECOSYSTEMS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid ecosystem '{pkg.ecosystem}'. Must be one of: {sorted(VALID_ECOSYSTEMS)}",
            )

    r = _get_redis()
    if r.exists(job_meta_key(job_id)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Job already exists")

    # Deduplicate by package identity so each key gets exactly one worker task.
    seen: set[str] = set()
    unique_packages = []
    for pkg in request.packages:
        pk = make_pkg_key(pkg.name, pkg.version, pkg.ecosystem)
        if pk not in seen:
            seen.add(pk)
            unique_packages.append(pkg)

    create_job(r, job_id, [p.model_dump() for p in unique_packages])

    q = _get_queue()
    for pkg in unique_packages:
        pk = make_pkg_key(pkg.name, pkg.version, pkg.ecosystem)
        q.enqueue(
            "worker.task.analyze_package",
            kwargs={
                "job_id": job_id,
                "pkg_key": pk,
                "name": pkg.name,
                "version": pkg.version,
                "ecosystem": pkg.ecosystem.lower(),
            },
            job_timeout=JOB_TIMEOUT,
        )

    skipped = len(request.packages) - len(unique_packages)
    _ensure_workers(len(unique_packages))
    return {"job_id": job_id, "queued": len(unique_packages), "skipped_duplicates": skipped}


@app.post("/jobs/{job_id}/upload", status_code=status.HTTP_202_ACCEPTED)
async def upload_package(
    job_id: str,
    file: UploadFile = File(...),
    name: str = Form(default=""),
):
    filename = file.filename or "package"
    suffix = ".tar.gz" if filename.endswith(".tar.gz") else Path(filename).suffix
    if suffix not in ALLOWED_UPLOAD_SUFFIXES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported file type '{suffix}'. Allowed: {sorted(ALLOWED_UPLOAD_SUFFIXES)}",
        )

    data = await file.read()
    if len(data) > UPLOAD_SIZE_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File exceeds the 100 MB limit",
        )

    pkg_name = name.strip() or Path(filename.removesuffix(".tar.gz").removesuffix(".tgz")).stem
    pkg_key = make_pkg_key(pkg_name, None, "upload")

    r = _get_redis()
    if r.exists(job_meta_key(job_id)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Job already exists")

    store_upload(r, job_id, pkg_key, data)
    create_job(r, job_id, [{"name": pkg_name, "version": None, "ecosystem": "upload"}])

    _get_queue().enqueue(
        "worker.task.analyze_uploaded_package",
        kwargs={"job_id": job_id, "pkg_key": pkg_key, "name": pkg_name, "filename": filename},
        job_timeout=JOB_TIMEOUT,
    )

    _ensure_workers(1)
    return {"job_id": job_id, "queued": 1, "filename": filename}


@app.get("/jobs/{job_id}", response_model=JobResponse)
def get_job_status(job_id: str):
    result = get_job(_get_redis(), job_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return result


@app.get("/jobs/{job_id}/packages/{pkg_key:path}", response_model=PackageResult)
def get_package_result(job_id: str, pkg_key: str):
    r = _get_redis()
    if not r.exists(job_meta_key(job_id)):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")

    import json

    data = r.hgetall(pkg_redis_key(job_id, pkg_key))
    if not data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Package not found in job")

    features = None
    if data.get("features"):
        try:
            features = json.loads(data["features"])
        except (json.JSONDecodeError, TypeError):
            pass

    return PackageResult(
        name=data.get("name", ""),
        version=data.get("version") or None,
        ecosystem=data.get("ecosystem", ""),
        status=data.get("status", "pending"),
        verdict=data.get("verdict") or None,
        probability=float(data["probability"]) if data.get("probability") else None,
        features=features,
        error=data.get("error") or None,
    )


@app.delete("/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
def cancel_job(job_id: str):
    if not delete_job(_get_redis(), job_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
