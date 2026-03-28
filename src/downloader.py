import argparse
import datetime
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import quote, unquote, urlparse

import requests
from tqdm import tqdm


PYPI_ROOT = "https://pypi.org/pypi"
NPM_ROOT = "https://registry.npmjs.org"
REQUEST_TIMEOUT = 20
CHUNK_SIZE = 1024 * 128


@dataclass
class PackageTask:
    ecosystem: str
    name: str
    version: Optional[str]
    source_file: Path
    line_number: int
    output_dir: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mass download package archives from PyPI and NPM without installing them."
    )
    parser.add_argument(
        "--data-list-dir",
        default="data_list",
        help="Directory containing split package lists (default: data_list)",
    )
    parser.add_argument(
        "--output-root",
        default="data/raw",
        help="Root output directory for downloaded archives (default: data/raw)",
    )
    parser.add_argument(
        "--missing-log",
        default="missing_packages.log",
        help="Path to missing/error package log file (default: missing_packages.log)",
    )
    return parser.parse_args()


def parse_pypi_spec(spec: str) -> tuple[str, Optional[str]]:
    clean = spec.split(";", 1)[0].strip()
    if "==" in clean:
        name, version = clean.split("==", 1)
        return name.strip(), version.strip() or None

    lowered = clean.lower()
    stripped = clean
    if lowered.endswith(".tar.gz"):
        stripped = clean[: -len(".tar.gz")]
    elif lowered.endswith(".tgz"):
        stripped = clean[: -len(".tgz")]
    elif lowered.endswith(".whl"):
        wheel_base = clean[: -len(".whl")]
        wheel_parts = wheel_base.split("-")
        if len(wheel_parts) >= 5:
            stripped = "-".join(wheel_parts[:-3])
        else:
            stripped = wheel_base

    parts = re.split(r"-(?=\d)", stripped, maxsplit=1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip() or None

    return stripped.strip(), None


def parse_npm_spec(spec: str) -> tuple[str, Optional[str]]:
    clean = spec.strip()
    clean = clean.replace("##", "/")
    if clean.lower().endswith(".tgz"):
        clean = clean[: -len(".tgz")]

    # Scoped packages can look like @scope/name@1.2.3; split on the last @.
    if clean.startswith("@"):
        last_at = clean.rfind("@")
        if last_at > 0:
            name = clean[:last_at]
            version = clean[last_at + 1 :].strip()
            if "/" in name and version:
                return name.strip(), version

        parts = re.split(r"-(?=\d)", clean, maxsplit=1)
        if len(parts) == 2 and "/" in parts[0]:
            return parts[0].strip(), parts[1].strip() or None

        return clean, None

    match = re.match(r"^(?P<name>[^@\s]+)@(?P<version>[^\s]+)$", clean)
    if match:
        return match.group("name"), match.group("version")

    parts = re.split(r"-(?=\d)", clean, maxsplit=1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip() or None

    return clean, None


def collect_tasks(data_list_dir: Path, output_root: Path) -> list[PackageTask]:
    tasks: list[PackageTask] = []
    for pkg_file in data_list_dir.rglob("packages.txt"):
        rel_parent = pkg_file.relative_to(data_list_dir).parent
        output_dir = output_root / rel_parent
        parts_upper = {part.upper() for part in pkg_file.parts}

        if "PYPI" in parts_upper:
            ecosystem = "pypi"
        elif "NPM" in parts_upper:
            ecosystem = "npm"
        else:
            continue

        with pkg_file.open("r", encoding="utf-8") as handle:
            for idx, line in enumerate(handle, start=1):
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue

                if ecosystem == "pypi":
                    name, version = parse_pypi_spec(raw)
                else:
                    name, version = parse_npm_spec(raw)

                if not name:
                    continue

                tasks.append(
                    PackageTask(
                        ecosystem=ecosystem,
                        name=name,
                        version=version,
                        source_file=pkg_file,
                        line_number=idx,
                        output_dir=output_dir,
                    )
                )

    return tasks


def log_missing(log_path: Path, task: PackageTask, reason: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    entry = (
        f"[{timestamp}] {task.ecosystem.upper()} {task.name}"
        f" version={task.version or 'latest'}"
        f" source={task.source_file}:{task.line_number}"
        f" reason={reason}\n"
    )
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(entry)


def get_pypi_download_info(session: requests.Session, task: PackageTask) -> tuple[str, str]:
    package_name = re.sub(r"[-_.]+", "-", task.name).lower()
    if task.version:
        metadata_url = f"{PYPI_ROOT}/{package_name}/{task.version}/json"
    else:
        metadata_url = f"{PYPI_ROOT}/{package_name}/json"

    try:
        print(f"  -> Querying PyPI API: {metadata_url}")
        response = session.get(metadata_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except requests.HTTPError:
        if task.version is not None:
            metadata_url = f"{PYPI_ROOT}/{package_name}/json"
            print(f"  -> Querying PyPI API: {metadata_url}")
            response = session.get(metadata_url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
        else:
            raise

    payload = response.json()

    candidates = payload.get("urls", [])
    selected = None

    for item in candidates:
        if item.get("packagetype") == "sdist" and str(item.get("filename", "")).endswith(".tar.gz"):
            selected = item
            break

    if selected is None:
        for item in candidates:
            if item.get("packagetype") == "bdist_wheel" and str(item.get("filename", "")).endswith(".whl"):
                selected = item
                break

    if selected is None:
        raise ValueError("No .tar.gz or .whl artifact found in PyPI metadata")

    url = selected.get("url")
    filename = selected.get("filename")
    if not url or not filename:
        raise ValueError("Incomplete PyPI artifact metadata")

    return url, filename


def get_npm_download_info(session: requests.Session, task: PackageTask) -> tuple[str, str]:
    encoded_name = quote(task.name, safe="@")
    if task.version:
        metadata_url = f"{NPM_ROOT}/{encoded_name}/{task.version}"
    else:
        metadata_url = f"{NPM_ROOT}/{encoded_name}/latest"

    try:
        print(f"  -> Querying NPM API: {metadata_url}")
        response = session.get(metadata_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except requests.HTTPError:
        if task.version is not None:
            metadata_url = f"{NPM_ROOT}/{encoded_name}/latest"
            print(f"  -> Querying NPM API: {metadata_url}")
            response = session.get(metadata_url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
        else:
            raise

    payload = response.json()

    tarball_url = payload.get("dist", {}).get("tarball")
    if not tarball_url:
        raise ValueError("No tarball URL found in NPM metadata")

    filename = unquote(Path(urlparse(tarball_url).path).name)
    if not filename.endswith(".tgz"):
        suffix = ".tgz"
        safe_name = task.name.replace("/", "-").replace("@", "")
        filename = f"{safe_name}-{task.version or 'latest'}{suffix}"

    return tarball_url, filename


def download_file(session: requests.Session, url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)

    with session.get(url, timeout=REQUEST_TIMEOUT, stream=True) as response:
        response.raise_for_status()
        with destination.open("wb") as output_handle:
            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:
                    output_handle.write(chunk)


def process_task(session: requests.Session, task: PackageTask, log_path: Path) -> bool:
    try:
        if task.ecosystem == "pypi":
            url, filename = get_pypi_download_info(session, task)
        else:
            url, filename = get_npm_download_info(session, task)

        destination = task.output_dir / filename
        if destination.exists() and destination.stat().st_size > 0:
            return True

        download_file(session, url, destination)
        return True
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        log_missing(log_path, task, f"HTTP error {status}")
    except requests.RequestException as exc:
        log_missing(log_path, task, f"Request error: {exc}")
    except Exception as exc:  # Keep bulk downloads resilient to bad package entries.
        log_missing(log_path, task, f"Error: {exc}")

    return False


def main() -> int:
    args = parse_args()
    data_list_dir = Path(args.data_list_dir)
    output_root = Path(args.output_root)
    missing_log = Path(args.missing_log)

    if not data_list_dir.exists():
        print(f"Input directory not found: {data_list_dir}")
        return 1

    tasks = collect_tasks(data_list_dir, output_root)
    if not tasks:
        print("No package tasks found.")
        return 0

    success_count = 0
    with requests.Session() as session:
        session.headers.update({"User-Agent": "MassDownloader/1.0"})
        for task in tqdm(tasks, desc="Downloading packages", unit="pkg"):
            if process_task(session, task, missing_log):
                success_count += 1

    print(f"Completed. Downloaded/available: {success_count}/{len(tasks)}")
    print(f"Missing/error entries logged to: {missing_log}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
