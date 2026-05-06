from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class PackageSpec(BaseModel):
    name: str
    version: Optional[str] = None
    ecosystem: str  # "npm" or "pypi"


class JobSubmitRequest(BaseModel):
    packages: list[PackageSpec] = Field(min_length=1)


class PackageResult(BaseModel):
    name: str
    version: Optional[str]
    ecosystem: str
    status: str  # pending | running | done | error
    verdict: Optional[str] = None  # benign | malicious
    probability: Optional[float] = None
    features: Optional[dict[str, float]] = None
    error: Optional[str] = None


class JobResponse(BaseModel):
    job_id: str
    status: str  # pending | running | done
    total: int
    done: int
    created_at: datetime
    packages: list[PackageResult]
