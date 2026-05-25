from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class PackageSpec(BaseModel):
    package_uuid: str
    name: str
    version: Optional[str] = None
    ecosystem: str  # "npm" or "pypi"


class JobSubmitRequest(BaseModel):
    packages: list[PackageSpec] = Field(min_length=1)


class PackageResult(BaseModel):
    package_uuid: str
    name: str
    version: Optional[str]
    ecosystem: str
    status: str  # pending | running | done | error
    verdict: Optional[str] = None  # benign | malicious
    probability: Optional[float] = None
    features: Optional[dict[str, float]] = None
    error: Optional[str] = None
