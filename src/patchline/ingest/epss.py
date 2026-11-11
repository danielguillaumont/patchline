"""FIRST EPSS daily bulk ingestion with validated immutable gzip snapshots."""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import re
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import httpx

from patchline.ingest.kev import KEVIngestionError, _atomic_write_new

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
MODEL_RE = re.compile(r"^v\d{4}\.\d{2}\.\d{2}$")
MAX_COMPRESSED_BYTES = 30 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 120 * 1024 * 1024
MAX_ROWS = 2_000_000


class EPSSIngestionError(ValueError):
    """Untrusted EPSS source or archived snapshot fails validation."""


def _timestamp(text: str) -> datetime:
    if not text.endswith("Z"):
        raise EPSSIngestionError("EPSS score_date must be UTC with Z suffix")
    try:
        timestamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EPSSIngestionError("EPSS score_date is invalid") from exc
    if timestamp.utcoffset() != UTC.utcoffset(None):
        raise EPSSIngestionError("EPSS score_date must be UTC")
    if timestamp > datetime.now(UTC):
        raise EPSSIngestionError("EPSS score_date is in the future")
    return timestamp


def _decompressed_lines(data: bytes):
    """Yield validated UTF-8 lines with a hard decompressed-byte ceiling."""
    total = 0
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
        for raw_line in stream:
            total += len(raw_line)
            if total > MAX_UNCOMPRESSED_BYTES:
                raise EPSSIngestionError("EPSS decompressed data exceeds size limit")
            yield raw_line.decode("utf-8-sig" if total == len(raw_line) else "utf-8")


def validate_epss(data: bytes) -> dict[str, Any]:
    """Stream every row and return metadata, without materializing a full table."""
    if not data or len(data) > MAX_COMPRESSED_BYTES:
        raise EPSSIngestionError("EPSS compressed data is empty or exceeds size limit")
    try:
        lines = iter(_decompressed_lines(data))
        comment = next(lines).strip()
        parts = comment.split(",")
        if len(parts) != 2 or not parts[0].startswith("#model_version:") or not parts[1].startswith("score_date:"):
            raise EPSSIngestionError("Missing or unexpected EPSS metadata header")
        model_version = parts[0].split(":", 1)[1]
        score_date = parts[1].split(":", 1)[1]
        if not MODEL_RE.fullmatch(model_version):
            raise EPSSIngestionError("Invalid EPSS model version")
        _timestamp(score_date)
        reader = csv.reader(lines, strict=True)
        if next(reader) != ["cve", "epss", "percentile"]:
            raise EPSSIngestionError("EPSS CSV columns changed")
        seen: set[str] = set()
        count = 0
        for row in reader:
            count += 1
            if count > MAX_ROWS:
                raise EPSSIngestionError("EPSS row count exceeds limit")
            if len(row) != 3 or not CVE_RE.fullmatch(row[0]):
                raise EPSSIngestionError(f"Invalid EPSS CVE or column count at row {count}")
            if row[0] in seen:
                raise EPSSIngestionError(f"Duplicate EPSS CVE: {row[0]}")
            seen.add(row[0])
            for field, value in zip(("epss", "percentile"), row[1:], strict=True):
                try:
                    score = Decimal(value)
                except InvalidOperation as exc:
                    raise EPSSIngestionError(f"Invalid {field} at row {count}") from exc
                if not score.is_finite() or not Decimal(0) <= score <= Decimal(1):
                    raise EPSSIngestionError(f"Out-of-range {field} at row {count}")
        if count == 0:
            raise EPSSIngestionError("Empty EPSS scored population")
        return {"model_version": model_version, "score_date": score_date, "row_count": count}
    except (OSError, EOFError, UnicodeError, csv.Error, StopIteration) as exc:
        raise EPSSIngestionError(f"Malformed or truncated EPSS gzip/CSV: {exc}") from exc


def _download(client: httpx.Client) -> bytes:
    chunks: list[bytes] = []
    size = 0
    with client.stream("GET", EPSS_URL) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > MAX_COMPRESSED_BYTES:
                raise EPSSIngestionError("EPSS download exceeds size limit")
            chunks.append(chunk)
    return b"".join(chunks)


def ingest_epss(data_dir: Path, *, compressed_bytes: bytes | None = None) -> dict[str, Any]:
    """Acquire and validate EPSS, then publish the source and manifest last."""
    if compressed_bytes is None:
        try:
            with httpx.Client(timeout=httpx.Timeout(60.0), follow_redirects=True) as client:
                compressed_bytes = _download(client)
        except httpx.HTTPError as exc:
            raise EPSSIngestionError(f"EPSS download failed: {type(exc).__name__}: {exc}") from exc
    metadata = validate_epss(compressed_bytes)
    digest = hashlib.sha256(compressed_bytes).hexdigest()
    folder = data_dir / "raw" / "epss" / digest
    source = folder / "scores.csv.gz"
    marker = folder / "manifest.json"
    manifest: dict[str, Any] = {
        "format_version": "patchline.epss-manifest.v1",
        "source": "FIRST EPSS",
        "source_url": EPSS_URL,
        "snapshot_id": digest,
        "compressed_sha256": digest,
        "compressed_bytes": len(compressed_bytes),
        "retrieved_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "validation": "passed",
        **metadata,
    }
    if marker.exists():
        try:
            old = json.loads(marker.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise EPSSIngestionError("Existing EPSS manifest is invalid") from exc
        if not isinstance(old, dict):
            raise EPSSIngestionError("Existing EPSS manifest must be an object")
        for key, value in manifest.items():
            if key != "retrieved_at_utc" and old.get(key) != value:
                raise EPSSIngestionError(f"Existing EPSS manifest mismatch: {key}")
        try:
            retrieval = old["retrieved_at_utc"]
            if not isinstance(retrieval, str):
                raise EPSSIngestionError("Invalid archived retrieval timestamp")
            _timestamp(retrieval)
        except (KeyError, EPSSIngestionError) as exc:
            raise EPSSIngestionError("Invalid archived retrieval timestamp") from exc
        if not source.is_file():
            raise EPSSIngestionError("Incomplete archived EPSS snapshot")
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise EPSSIngestionError("Archived EPSS gzip hash mismatch")
        return {**old, "status": "skipped_existing", "snapshot_path": str(folder)}
    try:
        _atomic_write_new(source, compressed_bytes)
        _atomic_write_new(marker, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    except KEVIngestionError as exc:
        raise EPSSIngestionError(str(exc)) from exc
    return {**manifest, "status": "ingested", "snapshot_path": str(folder)}
