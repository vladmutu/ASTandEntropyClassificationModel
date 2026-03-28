import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from entropy import calculate_shannon_entropy


ZIP_PASSWORD_CANDIDATES = (b"infected",)


@dataclass
class PackageEntropyResult:
    archive_path: Path
    file_count: int
    max_entropy: float
    average_entropy: float


class SafeExtractor:
    """Safely extract supported package archives and compute file entropy statistics."""

    def __init__(self, archive_path: str | Path):
        self.archive_path = Path(archive_path)
        self._validate_archive_path()

    def _validate_archive_path(self) -> None:
        if not self.archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {self.archive_path}")
        if not self.archive_path.is_file():
            raise ValueError(f"Archive path is not a file: {self.archive_path}")

    def _safe_join(self, base: Path, target: str) -> Path:
        destination = (base / target).resolve()
        if base.resolve() not in [destination, *destination.parents]:
            raise ValueError(f"Blocked path traversal attempt: {target}")
        return destination

    def _extract_tar_safely(self, destination: Path) -> None:
        with tarfile.open(self.archive_path, mode="r:*") as tar:
            for member in tar.getmembers():
                if member.islnk() or member.issym() or member.isdev():
                    continue
                self._safe_join(destination, member.name)
                tar.extract(member, path=destination, set_attrs=False)

    def _extract_zip_safely(self, destination: Path) -> None:
        with zipfile.ZipFile(self.archive_path, mode="r") as archive:
            for info in archive.infolist():
                name = info.filename
                if name.endswith("/"):
                    continue

                destination_path = self._safe_join(destination, name)
                destination_path.parent.mkdir(parents=True, exist_ok=True)

                # Some malware corpora ship encrypted ZIPs (e.g., password "infected").
                if info.flag_bits & 0x1:
                    extracted = False
                    for password in ZIP_PASSWORD_CANDIDATES:
                        try:
                            with archive.open(info, mode="r", pwd=password) as source_stream:
                                destination_path.write_bytes(source_stream.read())
                            extracted = True
                            break
                        except RuntimeError:
                            continue

                    if not extracted:
                        raise RuntimeError(
                            f"Encrypted ZIP member could not be extracted with known passwords: {info.filename}"
                        )
                    continue

                with archive.open(info, mode="r") as source_stream:
                    destination_path.write_bytes(source_stream.read())

    def _extract_archive(self, destination: Path) -> None:
        suffixes = [s.lower() for s in self.archive_path.suffixes]
        if suffixes[-1:] == [".whl"] or suffixes[-1:] == [".zip"]:
            self._extract_zip_safely(destination)
            return
        if suffixes[-2:] == [".tar", ".gz"] or suffixes[-1:] == [".tgz"]:
            self._extract_tar_safely(destination)
            return
        raise ValueError(f"Unsupported archive format: {self.archive_path.name}")

    @contextmanager
    def extracted_tree(self) -> Iterator[Path]:
        """Yield a temporary extraction directory and clean it up immediately after use."""
        with tempfile.TemporaryDirectory(prefix="safe_extract_") as temp_dir:
            extraction_dir = Path(temp_dir)
            self._extract_archive(extraction_dir)
            yield extraction_dir

    @staticmethod
    def iter_files(extraction_dir: Path) -> Iterator[Path]:
        for extracted_file in extraction_dir.rglob("*"):
            if extracted_file.is_file():
                yield extracted_file

    def process(self) -> PackageEntropyResult:
        with self.extracted_tree() as extraction_dir:
            entropies: list[float] = []
            for extracted_file in self.iter_files(extraction_dir):
                try:
                    data = extracted_file.read_bytes()
                except OSError:
                    continue
                entropies.append(calculate_shannon_entropy(data))

            if entropies:
                max_entropy = max(entropies)
                average_entropy = sum(entropies) / len(entropies)
            else:
                max_entropy = 0.0
                average_entropy = 0.0

            return PackageEntropyResult(
                archive_path=self.archive_path,
                file_count=len(entropies),
                max_entropy=max_entropy,
                average_entropy=average_entropy,
            )
