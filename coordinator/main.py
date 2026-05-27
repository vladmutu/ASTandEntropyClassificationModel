from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import redis as redis_lib
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from rq import Queue

from coordinator.models import JobSubmitRequest, PackageResult
from coordinator.store import (
    ALLOWED_UPLOAD_SUFFIXES,
    JOB_TTL,
    UPLOAD_SIZE_LIMIT,
    VALID_ECOSYSTEMS,
    make_pkg_key,
    store_upload,
)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
QUEUE_NAME = os.getenv("QUEUE_NAME", "analysis")
JOB_TIMEOUT = int(os.getenv("JOB_TIMEOUT", "180"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "15"))
WORKER_IMAGE = os.getenv("WORKER_IMAGE", "")
WORKER_NETWORK = os.getenv("WORKER_NETWORK", "")
COORDINATOR_URL = os.getenv("COORDINATOR_URL", "http://coordinator:8090")
BURST_LABEL = "malware-classifier.burst"

_redis: redis_lib.Redis | None = None
_queue: Queue | None = None

# In-memory delivery queues: job_id → asyncio.Queue of PackageResult
_result_queues: dict[str, asyncio.Queue] = {}
# Total expected results per job (needed to send cancellation sentinels)
_job_totals: dict[str, int] = {}


def _ensure_workers(num_packages: int) -> None:
    """Start burst worker containers so that running + new == min(num_packages, MAX_WORKERS).

    Workers use --burst so they exit (and auto-remove) when the queue empties.
    No-op when WORKER_IMAGE / WORKER_NETWORK are not configured (e.g. K8s).
    """
    if not WORKER_IMAGE or not WORKER_NETWORK:
        return
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        running = client.containers.list(
            filters={"label": f"{BURST_LABEL}=true", "status": "running"}
        )
    except Exception as exc:
        print(f"[scaling] WARNING: docker client init failed: {exc}", flush=True)
        return

    to_start = min(num_packages, max(0, MAX_WORKERS - len(running)))
    if to_start <= 0:
        return

    # Worker TTL: force-exit after JOB_TIMEOUT + 60 s so burst workers never zombie.
    worker_ttl = str(JOB_TIMEOUT + 60)

    started = 0
    for _ in range(to_start):
        try:
            resp = client.api.create_container(
                image=WORKER_IMAGE,
                command=["rq", "worker", "analysis", "--url", REDIS_URL, "--burst",
                         "--worker-ttl", worker_ttl],
                environment={
                    "REDIS_URL": REDIS_URL,
                    "COORDINATOR_URL": COORDINATOR_URL,
                    "MODEL_PATH": "/app/lightgbm_model.pkl",
                    "THRESHOLD_PATH": "/app/lightgbm_threshold.pkl",
                    "DOWNLOAD_TIMEOUT": "30",
                },
                labels={BURST_LABEL: "true"},
                user="1000",
                host_config=client.api.create_host_config(
                    auto_remove=True,
                    network_mode=WORKER_NETWORK,
                ),
            )
            client.api.start(resp["Id"])
            started += 1
        except Exception as exc:
            print(f"[scaling] WARNING: failed to start a worker: {exc}", flush=True)

    if started:
        print(
            f"[scaling] started {started}/{to_start} burst worker(s)"
            f" (running={len(running)}, requested={num_packages})",
            flush=True,
        )


async def _cleanup_stale_workers() -> None:
    """Background coroutine: kill burst workers alive longer than JOB_TIMEOUT * 2 seconds."""
    max_age = JOB_TIMEOUT * 2
    while True:
        await asyncio.sleep(60)
        if not WORKER_IMAGE or not WORKER_NETWORK:
            continue
        try:
            import docker as docker_sdk
            client = docker_sdk.from_env()
            now = time.time()
            for container in client.containers.list(
                filters={"label": f"{BURST_LABEL}=true", "status": "running"}
            ):
                created_str = container.attrs.get("Created", "")
                if not created_str:
                    continue
                try:
                    created_at = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                    age = now - created_at.timestamp()
                    if age > max_age:
                        print(
                            f"[cleanup] Killing stale burst worker {container.id[:12]}"
                            f" (age={age:.0f}s > max={max_age}s)",
                            flush=True,
                        )
                        container.stop(timeout=5)
                except Exception:
                    pass
        except Exception as exc:
            print(f"[cleanup] WARNING: stale worker check failed: {exc}", flush=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _redis, _queue
    _redis = redis_lib.from_url(REDIS_URL, decode_responses=True)
    _queue = Queue(QUEUE_NAME, connection=redis_lib.from_url(REDIS_URL))

    cleanup_task = asyncio.create_task(_cleanup_stale_workers())

    yield

    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass

    # On shutdown, stop all burst worker containers so they don't outlive the stack.
    if WORKER_IMAGE and WORKER_NETWORK:
        try:
            import docker as docker_sdk
            client = docker_sdk.from_env()
            for container in client.containers.list(
                filters={"label": f"{BURST_LABEL}=true", "status": "running"}
            ):
                container.stop(timeout=5)
        except Exception as exc:
            print(f"[scaling] WARNING: failed to stop burst workers on shutdown: {exc}", flush=True)
    _redis.close()


app = FastAPI(title="Malware Classifier Coordinator", version="2.0.0", lifespan=lifespan)


def _get_redis() -> redis_lib.Redis:
    assert _redis is not None
    return _redis


def _get_queue() -> Queue:
    assert _queue is not None
    return _queue


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/internal/result/{job_id}", include_in_schema=False)
async def receive_result(job_id: str, result: PackageResult):
    """Called by workers when a package analysis finishes. Delivers result to the waiting stream."""
    q = _result_queues.get(job_id)
    if q is not None:
        await q.put(result)
    return {"ok": True}


@app.delete("/jobs/{job_id}")
async def cancel_job(job_id: str):
    """Cancel a pending job: unblocks the generate() stream immediately via sentinel values."""
    q = _result_queues.pop(job_id, None)
    total = _job_totals.pop(job_id, 0)
    if q is not None:
        # Fill the queue with None sentinels so the waiting generate() coroutine exits promptly.
        for _ in range(total + 1):
            q.put_nowait(None)
    return {"ok": True}


@app.post("/jobs/{job_id}")
@app.post("/analyze/{job_id}")
async def submit_job(job_id: str, request: JobSubmitRequest):
    for pkg in request.packages:
        if pkg.ecosystem.lower() not in VALID_ECOSYSTEMS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid ecosystem '{pkg.ecosystem}'. Must be one of: {sorted(VALID_ECOSYSTEMS)}",
            )

    total = len(request.packages)

    # Register delivery queue BEFORE enqueuing RQ tasks to avoid any race
    q: asyncio.Queue = asyncio.Queue()
    _result_queues[job_id] = q
    _job_totals[job_id] = total

    rq = _get_queue()
    for pkg in request.packages:
        callback_url = f"{COORDINATOR_URL}/internal/result/{job_id}"
        rq.enqueue(
            "worker.task.analyze_package",
            kwargs={
                "job_id": job_id,
                "package_uuid": pkg.package_uuid,
                "name": pkg.name,
                "version": pkg.version,
                "ecosystem": pkg.ecosystem.lower(),
                "callback_url": callback_url,
            },
            job_timeout=max(30, JOB_TIMEOUT - 30),
        )

    _ensure_workers(total)

    pending: dict[str, object] = {pkg.package_uuid: pkg for pkg in request.packages}

    async def generate():
        try:
            received = 0
            while received < total:
                try:
                    result: PackageResult | None = await asyncio.wait_for(q.get(), timeout=JOB_TIMEOUT)
                    if result is None:  # cancellation sentinel
                        break
                    pending.pop(result.package_uuid, None)
                    yield json.dumps(result.model_dump()) + "\n"
                    received += 1
                except asyncio.TimeoutError:
                    break
        finally:
            for pkg in pending.values():
                yield json.dumps({
                    "package_uuid": pkg.package_uuid,
                    "name": pkg.name,
                    "version": pkg.version,
                    "ecosystem": pkg.ecosystem,
                    "status": "timeout",
                    "verdict": None,
                    "probability": None,
                    "features": None,
                    "error": "Analysis timed out",
                }) + "\n"
            _result_queues.pop(job_id, None)
            _job_totals.pop(job_id, None)

    return StreamingResponse(generate(), media_type="application/x-ndjson")


@app.post("/jobs/{job_id}/upload")
async def upload_package(
    job_id: str,
    file: UploadFile = File(...),
    package_uuid: str = Form(...),
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
    store_upload(r, job_id, pkg_key, data)

    # Register delivery queue BEFORE enqueuing RQ task
    q: asyncio.Queue = asyncio.Queue()
    _result_queues[job_id] = q
    _job_totals[job_id] = 1

    callback_url = f"{COORDINATOR_URL}/internal/result/{job_id}"
    _get_queue().enqueue(
        "worker.task.analyze_uploaded_package",
        kwargs={
            "job_id": job_id,
            "package_uuid": package_uuid,
            "pkg_key": pkg_key,
            "name": pkg_name,
            "filename": filename,
            "callback_url": callback_url,
        },
        job_timeout=max(30, JOB_TIMEOUT - 30),
    )

    _ensure_workers(1)

    async def generate():
        try:
            try:
                result: PackageResult | None = await asyncio.wait_for(q.get(), timeout=JOB_TIMEOUT)
                if result is not None:
                    yield json.dumps(result.model_dump()) + "\n"
                else:
                    yield json.dumps({
                        "package_uuid": package_uuid,
                        "name": pkg_name,
                        "version": None,
                        "ecosystem": "upload",
                        "status": "timeout",
                        "verdict": None,
                        "probability": None,
                        "features": None,
                        "error": "Analysis cancelled",
                    }) + "\n"
            except asyncio.TimeoutError:
                yield json.dumps({
                    "package_uuid": package_uuid,
                    "name": pkg_name,
                    "version": None,
                    "ecosystem": "upload",
                    "status": "timeout",
                    "verdict": None,
                    "probability": None,
                    "features": None,
                    "error": "Analysis timed out",
                }) + "\n"
        finally:
            _result_queues.pop(job_id, None)
            _job_totals.pop(job_id, None)

    return StreamingResponse(generate(), media_type="application/x-ndjson")
