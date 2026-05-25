from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, File, Form, UploadFile
from pydantic import BaseModel

from worker.task import _load_model, analyze_package_sync, analyze_uploaded_package_sync


@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_model()  # pre-load so first request is not slow
    yield


app = FastAPI(title="Malware Classifier Worker", lifespan=lifespan)


class AnalyzeRequest(BaseModel):
    name: str
    version: Optional[str] = None
    ecosystem: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(req: AnalyzeRequest) -> dict:
    return analyze_package_sync(req.name, req.version, req.ecosystem)


@app.post("/analyze/upload")
async def analyze_upload(
    file: UploadFile = File(...),
    name: str = Form(default=""),
) -> dict:
    data = await file.read()
    result = analyze_uploaded_package_sync(file.filename or "package", data)
    pkg_name = name.strip() or file.filename or "package"
    return {**result, "name": pkg_name}
