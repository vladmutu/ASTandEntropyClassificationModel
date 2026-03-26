import argparse
from pathlib import Path

import pandas as pd
from tqdm import tqdm

from ast_parser import analyze_code_files
from entropy import calculate_shannon_entropy
from extractor import SafeExtractor


SUPPORTED_ARCHIVE_SUFFIXES = (
    ".tar.gz",
    ".tgz",
    ".whl",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build dataset CSV from raw package archives using entropy and AST features."
    )
    parser.add_argument(
        "--raw-root",
        default="data/raw",
        help="Root folder containing raw package archives (default: data/raw)",
    )
    parser.add_argument(
        "--output-csv",
        default="data/dataset.csv",
        help="Output CSV path (default: data/dataset.csv)",
    )
    return parser.parse_args()


def discover_archives(raw_root: Path) -> list[Path]:
    archives: list[Path] = []
    for path in raw_root.rglob("*"):
        if not path.is_file():
            continue
        path_lower = str(path).lower()
        if any(path_lower.endswith(suffix) for suffix in SUPPORTED_ARCHIVE_SUFFIXES):
            archives.append(path)
    return archives


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
    if "MALWARE" in parts:
        return 1
    return None


def package_name_from_archive(path: Path) -> str:
    name = path.name
    lower_name = name.lower()

    for suffix in SUPPORTED_ARCHIVE_SUFFIXES:
        if lower_name.endswith(suffix):
            return name[: -len(suffix)]

    return path.stem


def extract_entropy_and_code_features(archive_path: Path) -> tuple[float, float, dict[str, int]]:
    extractor = SafeExtractor(archive_path)

    with extractor.extracted_tree() as extraction_dir:
        entropies: list[float] = []
        code_files: list[Path] = []

        for file_path in extractor.iter_files(extraction_dir):
            data = file_path.read_bytes()
            entropies.append(calculate_shannon_entropy(data))

            suffix = file_path.suffix.lower()
            if suffix in {".py", ".js"}:
                code_files.append(file_path)

        max_entropy = max(entropies) if entropies else 0.0
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        ast_features = analyze_code_files(code_files)
        return max_entropy, avg_entropy, ast_features


def main() -> int:
    args = parse_args()
    raw_root = Path(args.raw_root)
    output_csv = Path(args.output_csv)

    if not raw_root.exists():
        print(f"Raw data directory not found: {raw_root}")
        return 1

    archives = discover_archives(raw_root)
    if not archives:
        print("No archives found to process.")
        return 0

    rows: list[dict[str, object]] = []

    for archive_path in tqdm(archives, desc="Building dataset", unit="pkg"):
        ecosystem = detect_ecosystem(archive_path)
        label = detect_label(archive_path)
        if ecosystem is None or label is None:
            continue

        try:
            max_entropy, avg_entropy, ast_counts = extract_entropy_and_code_features(archive_path)
        except Exception as exc:
            print(f"Skipping {archive_path}: {exc}")
            continue

        row = {
            "package_name": package_name_from_archive(archive_path),
            "ecosystem": ecosystem,
            "max_entropy": max_entropy,
            "avg_entropy": avg_entropy,
            "eval_count": ast_counts.get("eval_count", 0),
            "exec_count": ast_counts.get("exec_count", 0),
            "base64_count": ast_counts.get("base64_count", 0),
            "network_imports": ast_counts.get("network_imports", 0),
            "label": label,
        }
        rows.append(row)

    dataset = pd.DataFrame(rows)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_csv(output_csv, index=False)

    print(f"Saved dataset with {len(dataset)} rows to {output_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
