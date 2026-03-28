import argparse
import concurrent.futures
import re
from pathlib import Path

import pandas as pd
from tqdm import tqdm

from ast_parser import analyze_code_files
from entropy import calculate_shannon_entropy
from extractor import SafeExtractor


SUPPORTED_ARCHIVE_SUFFIXES = (
    ".tar.gz",
    ".tgz",
    ".zip",
    ".whl",
)

SUPPORTED_ECOSYSTEMS = {"NPM", "PYPI"}
SUPPORTED_LABELS = {"BENIGN", "MALIGN", "MALWARE"}

_WORKER_RAW_ROOT: Path | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build dataset CSV from raw package archives using entropy and AST features."
    )
    parser.add_argument(
        "--raw-root",
        default="data",
        help="Root folder containing package files/folders (default: data)",
    )
    parser.add_argument(
        "--output-csv",
        default="data/dataset.csv",
        help="Output CSV path (default: data/dataset.csv)",
    )
    parser.add_argument(
        "--validation-report",
        default="data/dataset_validation.txt",
        help="Validation report path (default: data/dataset_validation.txt)",
    )
    return parser.parse_args()


def _is_supported_archive(path: Path) -> bool:
    if not path.is_file():
        return False
    path_lower = str(path).lower()
    return any(path_lower.endswith(suffix) for suffix in SUPPORTED_ARCHIVE_SUFFIXES)


def _looks_like_version(name: str) -> bool:
    return bool(re.match(r"^v?\d+(?:\.\d+){0,4}(?:[-._][A-Za-z0-9]+)*$", name))


def discover_package_inputs(raw_root: Path) -> list[Path]:
    package_inputs: list[Path] = []

    for ecosystem_dir in raw_root.iterdir():
        if not ecosystem_dir.is_dir() or ecosystem_dir.name.upper() not in SUPPORTED_ECOSYSTEMS:
            continue

        for label_dir in ecosystem_dir.iterdir():
            if not label_dir.is_dir() or label_dir.name.upper() not in SUPPORTED_LABELS:
                continue

            for item in label_dir.iterdir():
                if _is_supported_archive(item):
                    package_inputs.append(item)
                    continue

                if not item.is_dir():
                    continue

                nested_archives = [candidate for candidate in item.rglob("*") if _is_supported_archive(candidate)]
                if nested_archives:
                    package_inputs.extend(nested_archives)
                    continue

                children = list(item.iterdir())
                child_dirs = [child for child in children if child.is_dir()]
                child_files = [child for child in children if child.is_file()]

                # Some malicious samples are organized as package/version/<files>.
                if not child_files and child_dirs and all(_looks_like_version(child.name) for child in child_dirs):
                    package_inputs.extend(child_dirs)
                else:
                    package_inputs.append(item)

    return sorted(set(package_inputs))


def package_input_id(path: Path, raw_root: Path) -> str:
    try:
        rel = path.resolve().relative_to(raw_root.resolve())
    except Exception:
        rel = path
    return rel.as_posix().lower()


def _init_worker(raw_root: str) -> None:
    global _WORKER_RAW_ROOT
    _WORKER_RAW_ROOT = Path(raw_root)


def detect_ecosystem(path: Path) -> str | None:
    parts = {part.upper() for part in path.parts}
    if "PYPI" in parts:
        return "PyPI"
    if "NPM" in parts:
        return "NPM"
    return None


def detect_label(path: Path) -> int | None:
    parts = {part.upper() for part in path.parts}
    if "BENIGN" in parts:
        return 0
    if "MALIGN" in parts:
        return 1
    if "MALWARE" in parts:
        return 1
    return None


def package_name_from_input(path: Path) -> str:
    if path.is_dir():
        if _looks_like_version(path.name) and path.parent.name.upper() not in SUPPORTED_LABELS:
            return f"{path.parent.name}-{path.name}"
        return path.name

    if _looks_like_version(path.parent.name) and path.parent.parent.name.upper() not in SUPPORTED_LABELS:
        return f"{path.parent.parent.name}-{path.parent.name}"

    name = path.name
    lower_name = name.lower()

    for suffix in SUPPORTED_ARCHIVE_SUFFIXES:
        if lower_name.endswith(suffix):
            return name[: -len(suffix)]

    return path.stem


def _compute_features_from_files(file_paths: list[Path]) -> tuple[float, float, dict[str, int]]:
    entropies: list[float] = []
    code_files: list[Path] = []

    for file_path in file_paths:
        try:
            data = file_path.read_bytes()
        except OSError:
            continue
        entropies.append(calculate_shannon_entropy(data))

        suffix = file_path.suffix.lower()
        if suffix in {".py", ".js"}:
            code_files.append(file_path)

    max_entropy = max(entropies) if entropies else 0.0
    avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
    ast_features = analyze_code_files(code_files)
    return max_entropy, avg_entropy, ast_features


def extract_entropy_and_code_features(package_input: Path) -> tuple[float, float, dict[str, int]]:
    if package_input.is_dir():
        file_paths = [path for path in package_input.rglob("*") if path.is_file()]
        return _compute_features_from_files(file_paths)

    extractor = SafeExtractor(package_input)
    with extractor.extracted_tree() as extraction_dir:
        file_paths = [path for path in extractor.iter_files(extraction_dir)]
        return _compute_features_from_files(file_paths)


def process_archive(package_input: Path) -> dict[str, object]:
    ecosystem = detect_ecosystem(package_input)
    label = detect_label(package_input)
    if ecosystem is None or label is None:
        return {
            "ok": False,
            "path": str(package_input),
            "reason": "Could not detect ecosystem or label from path.",
        }

    try:
        max_entropy, avg_entropy, ast_counts = extract_entropy_and_code_features(package_input)
    except Exception as exc:
        return {
            "ok": False,
            "path": str(package_input),
            "reason": str(exc),
        }

    raw_root = _WORKER_RAW_ROOT or Path(".")
    return {
        "ok": True,
        "path": str(package_input),
        "path_id": package_input_id(package_input, raw_root),
        "row": {
            "package_name": package_name_from_input(package_input),
            "ecosystem": ecosystem,
            "max_entropy": max_entropy,
            "avg_entropy": avg_entropy,
            "eval_count": ast_counts.get("eval_count", 0),
            "exec_count": ast_counts.get("exec_count", 0),
            "base64_count": ast_counts.get("base64_count", 0),
            "network_imports": ast_counts.get("network_imports", 0),
            "label": label,
        },
    }


def main() -> int:
    args = parse_args()
    raw_root = Path(args.raw_root)
    output_csv = Path(args.output_csv)
    validation_report_path = Path(args.validation_report)

    if not raw_root.exists():
        print(f"Raw data directory not found: {raw_root}")
        return 1

    package_inputs = discover_package_inputs(raw_root)
    if not package_inputs:
        print("No package inputs found to process.")
        return 0

    rows: list[dict[str, object]] = []
    expected_ids = {package_input_id(path, raw_root) for path in package_inputs}
    processed_ids: set[str] = set()
    failed_inputs: list[tuple[Path, str]] = []

    with concurrent.futures.ProcessPoolExecutor(
        initializer=_init_worker,
        initargs=(str(raw_root),),
    ) as executor:
        results = list(
            tqdm(
                executor.map(process_archive, package_inputs),
                total=len(package_inputs),
                desc="Building dataset",
                unit="pkg",
            )
        )

    for result in results:
        package_path = Path(str(result.get("path", "")))
        if not result.get("ok", False):
            reason = str(result.get("reason", "Unknown error"))
            failed_inputs.append((package_path, reason))
            print(f"Skipping {package_path}: {reason}")
            continue

        row = result.get("row")
        path_id = result.get("path_id")
        if isinstance(row, dict):
            rows.append(row)
        if isinstance(path_id, str):
            processed_ids.add(path_id)

    dataset = pd.DataFrame(rows)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_csv(output_csv, index=False)

    missing_ids = sorted(expected_ids - processed_ids)
    processed_count = len(processed_ids)
    expected_count = len(expected_ids)
    failed_count = len(failed_inputs)

    validation_report_path.parent.mkdir(parents=True, exist_ok=True)
    with validation_report_path.open("w", encoding="utf-8") as report_file:
        report_file.write(f"expected_packages={expected_count}\n")
        report_file.write(f"processed_packages={processed_count}\n")
        report_file.write(f"failed_packages={failed_count}\n")
        report_file.write(f"missing_packages={len(missing_ids)}\n")
        report_file.write("\n")

        if missing_ids:
            report_file.write("[missing_package_inputs]\n")
            for item in missing_ids:
                report_file.write(f"{item}\n")
            report_file.write("\n")

        if failed_inputs:
            report_file.write("[failed_package_inputs]\n")
            for path, reason in failed_inputs:
                report_file.write(f"{package_input_id(path, raw_root)}\t{reason}\n")

    validation_ok = (expected_count == processed_count)

    print(f"Saved dataset with {len(dataset)} rows to {output_csv}")
    print(
        f"Validation: expected={expected_count}, processed={processed_count}, "
        f"failed={failed_count}, missing={len(missing_ids)}"
    )
    print(f"Validation report written to {validation_report_path}")

    if not validation_ok:
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
