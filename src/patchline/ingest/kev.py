"""CISA KEV source download, validation and immutable archival."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import httpx
from jsonschema import Draft7Validator, FormatChecker

CATALOG_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    "develop/known_exploited_vulnerabilities.json"
)
SCHEMA_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    "develop/known_exploited_vulnerabilities_schema.json"
)
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
MAX_DOWNLOAD_BYTES = 30 * 1024 * 1024


class KEVIngestionError(ValueError):
    """Invalid source data or unsafe ingestion operation."""


def _require_object(data: Any, name: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise KEVIngestionError(f"{name} must be a JSON object")
    return data


def validate_kev(catalog_bytes: bytes, schema_bytes: bytes) -> dict[str, Any]:
    """Validate against official schema plus independently enforced semantic gates."""
    try:
        catalog = _require_object(json.loads(catalog_bytes), "KEV catalog")
        schema = _require_object(json.loads(schema_bytes), "KEV schema")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KEVIngestionError(f"Invalid JSON: {exc}") from exc

    if schema.get("$schema") != "http://json-schema.org/draft-07/schema#":
        raise KEVIngestionError("Unsupported or changed CISA schema draft")
    Draft7Validator.check_schema(schema)
    validator = Draft7Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(catalog), key=lambda err: str(err.path))
    if errors:
        first = errors[0]
        raise KEVIngestionError(f"CISA schema validation failed at {list(first.path)}: {first.message}")

    entries = catalog["vulnerabilities"]
    if catalog["count"] != len(entries):
        raise KEVIngestionError("CISA declared count differs from parsed entries")
    if not entries:
        raise KEVIngestionError("Empty KEV catalog must not be published")

    seen: set[str] = set()
    for index, row in enumerate(entries):
        cve = row["cveID"]
        if not CVE_RE.fullmatch(cve):
            raise KEVIngestionError(f"Invalid CVE at row {index}: {cve}")
        if cve in seen:
            raise KEVIngestionError(f"Duplicate CVE identifier: {cve}")
        seen.add(cve)
        added = date.fromisoformat(row["dateAdded"])
        due = date.fromisoformat(row["dueDate"])
        if added > date.today():
            raise KEVIngestionError(f"Future dateAdded at {cve}")
        if due < added:
            raise KEVIngestionError(f"dueDate precedes dateAdded at {cve}")
    released = datetime.fromisoformat(catalog["dateReleased"].replace("Z", "+00:00"))
    if released.tzinfo is None:
        raise KEVIngestionError("dateReleased lacks timezone")
    return catalog


def _download(client: httpx.Client, url: str) -> bytes:
    # Response size is bounded to limit unexpected upstream payloads.
    chunks: list[bytes] = []
    total = 0
    with client.stream("GET", url) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                raise KEVIngestionError("CISA response exceeded the size limit")
            chunks.append(chunk)
    return b"".join(chunks)


def _atomic_write_new(path: Path, content: bytes) -> None:
    """Create immutable file; fail safely if the final hash-addressed path exists."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != content:
            raise KEVIngestionError(f"Existing snapshot content mismatch: {path}")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".patchline-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        # Same-directory hard link makes the complete temporary file visible
        # atomically, without replacing any already-published file.
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != content:
                raise KEVIngestionError(f"Conflicting snapshot file: {path}") from None
    finally:
        Path(temporary).unlink(missing_ok=True)


def ingest_kev(
    data_dir: Path,
    *,
    catalog_bytes: bytes | None = None,
    schema_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Download both official artifacts unless bytes supplied for offline tests."""
    if (catalog_bytes is None) != (schema_bytes is None):
        raise KEVIngestionError("Provide both fixture documents or neither")
    if catalog_bytes is None:
        with httpx.Client(timeout=httpx.Timeout(30.0), follow_redirects=True) as client:
            catalog_bytes = _download(client, CATALOG_URL)
            schema_bytes = _download(client, SCHEMA_URL)
    assert schema_bytes is not None
    catalog = validate_kev(catalog_bytes, schema_bytes)
    catalog_sha = hashlib.sha256(catalog_bytes).hexdigest()
    schema_sha = hashlib.sha256(schema_bytes).hexdigest()
    snapshot_dir = data_dir / "raw" / "kev" / catalog_sha
    catalog_file = snapshot_dir / "catalog.json"
    schema_file = snapshot_dir / "schema.json"
    manifest_file = snapshot_dir / "manifest.json"
    retrieved = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    manifest = {
        "format_version": "patchline.kev-manifest.v1",
        "source": "CISA KEV",
        "catalog_url": CATALOG_URL,
        "schema_url": SCHEMA_URL,
        "snapshot_id": catalog_sha,
        "catalog_sha256": catalog_sha,
        "schema_sha256": schema_sha,
        "catalog_bytes": len(catalog_bytes),
        "schema_bytes": len(schema_bytes),
        "retrieved_at_utc": retrieved,
        "catalog_version": catalog["catalogVersion"],
        "catalog_date_released": catalog["dateReleased"],
        "row_count": len(catalog["vulnerabilities"]),
        "validation": "passed",
    }
    if manifest_file.exists():
        old = json.loads(manifest_file.read_text(encoding="utf-8"))
        if old.get("catalog_sha256") != catalog_sha or old.get("schema_sha256") != schema_sha:
            raise KEVIngestionError("Existing snapshot manifest does not match source hashes")
        if not catalog_file.is_file() or not schema_file.is_file():
            raise KEVIngestionError("Incomplete existing snapshot; manual review required")
        if hashlib.sha256(catalog_file.read_bytes()).hexdigest() != catalog_sha:
            raise KEVIngestionError("Existing archived catalog hash mismatch")
        if hashlib.sha256(schema_file.read_bytes()).hexdigest() != schema_sha:
            raise KEVIngestionError("Existing archived schema hash mismatch")
        return {**old, "status": "skipped_existing", "snapshot_path": str(snapshot_dir)}

    # Stage all artifacts first; manifest is written last and acts as completion marker.
    _atomic_write_new(catalog_file, catalog_bytes)
    _atomic_write_new(schema_file, schema_bytes)
    _atomic_write_new(
        manifest_file, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    return {**manifest, "status": "ingested", "snapshot_path": str(snapshot_dir)}
