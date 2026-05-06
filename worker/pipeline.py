from __future__ import annotations

import os
import tempfile
from pathlib import Path

import requests

from build_dataset import extract_entropy_and_code_features
from downloader import PackageTask, download_file, get_npm_download_info, get_pypi_download_info

_REQUEST_TIMEOUT = int(os.getenv("DOWNLOAD_TIMEOUT", "30"))


def build_feature_vector(
    name: str,
    version: str | None,
    ecosystem: str,
) -> tuple[float, float, dict]:
    """Download a compressed package and compute all static features.

    Returns (max_entropy, avg_entropy, ast_feature_counts).
    """
    task = PackageTask(
        ecosystem=ecosystem.lower(),
        name=name,
        version=version,
        source_file=Path(os.devnull),
        line_number=0,
        output_dir=Path(tempfile.gettempdir()),
    )

    with requests.Session() as session:
        session.headers.update({"User-Agent": "MalwareClassifier-Worker/1.0"})

        if ecosystem.lower() == "pypi":
            url, filename = get_pypi_download_info(session, task)
        elif ecosystem.lower() == "npm":
            url, filename = get_npm_download_info(session, task)
        else:
            raise ValueError(f"Unknown ecosystem: {ecosystem!r}")

        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / filename
            download_file(session, url, dest)
            return extract_entropy_and_code_features(dest)


def build_feature_vector_from_file(archive_path: Path) -> tuple[float, float, dict]:
    """Run the feature extraction pipeline on an already-downloaded archive."""
    return extract_entropy_and_code_features(archive_path)
