"""EA-03A4B: verified source -> disposable, isolated dbt working copy.

The source NVD DuckDB database remains immutable. dbt may only connect to the
copied destination, never to the evidence-preserving original.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from patchline.warehouse.nvd_stage import NVDWarehouseError, stage_nvd_query

QUERY_ID_RE = re.compile(r"^[0-9a-f]{64}$")


class NVDWorkspaceError(ValueError):
    """Reject non-verified sources and unsafe workspace destinations."""


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare_workspace(*, data_dir: Path, query_id: str, destination: Path) -> dict[str, Any]:
    """Check full upstream chain, then create a new, byte-identical dbt workspace.

    Never overwrites an existing destination. No dbt command is run here.
    """
    data_dir = Path(data_dir)
    destination = Path(destination)
    if QUERY_ID_RE.fullmatch(query_id) is None:
        raise NVDWorkspaceError("query_id must be a lowercase SHA-256")

    source = data_dir / "warehouse" / "nvd-queries" / f"{query_id}.duckdb"
    if destination.exists() or destination.is_symlink():
        raise NVDWorkspaceError("Destination exists; refusing to overwrite")
    if destination.suffix.lower() != ".duckdb":
        raise NVDWorkspaceError("Destination must be a .duckdb file")
    if destination.resolve() == source.resolve():
        raise NVDWorkspaceError("Source and destination must be different")
    if source.is_symlink():
        raise NVDWorkspaceError("Source database must not be a symlink")

    # stage_nvd_query independently rechecks the complete raw-query and normalized
    # chain, including bytewise DuckDB row verification for an existing database.
    try:
        result = stage_nvd_query(data_dir, query_id=query_id)
    except (NVDWarehouseError, OSError, ValueError) as exc:
        raise NVDWorkspaceError(f"Source staging verification failed: {exc}") from exc
    if result.get("database_path") != str(source) or result.get("status") not in {
        "verified_existing", "staged"
    }:
        raise NVDWorkspaceError("Unexpected NVD source verification result")
    if not source.is_file() or source.is_symlink():
        raise NVDWorkspaceError("Verified NVD source database is missing")

    source_hash_before = _digest(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise NVDWorkspaceError("Destination appeared during verification")

    fd, scratch = tempfile.mkstemp(
        prefix=".ea03a4b-", suffix=".duckdb", dir=destination.parent
    )
    scratch_path = Path(scratch)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_stream:
            shutil.copyfileobj(input_stream, output)
            output.flush()
            os.fsync(output.fileno())
        if _digest(scratch_path) != source_hash_before or _digest(source) != source_hash_before:
            raise NVDWorkspaceError("Source changed during copy; refusing workspace")
        # Same-directory, atomic and no-overwrite. Cannot point dbt at the source.
        try:
            os.link(scratch_path, destination)
        except FileExistsError as exc:
            raise NVDWorkspaceError("Destination appeared; refusing overwrite") from exc
        except OSError as exc:
            raise NVDWorkspaceError(f"No-overwrite publication failed: {exc}") from exc
    finally:
        scratch_path.unlink(missing_ok=True)

    if _digest(source) != source_hash_before:
        destination.unlink(missing_ok=True)
        raise NVDWorkspaceError("Source changed after copy publication")

    return {
        "status": "prepared_isolated_copy",
        "query_id": query_id,
        "source_database": str(source),
        "workspace_database": str(destination),
        "copied_sha256": source_hash_before,
        "source_bytes_unchanged": _digest(source) == source_hash_before,
        "verified_source_status": result["status"],
        "source_scope": "one_bounded_nvd_query_not_global_snapshot",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--query-id", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        answer = prepare_workspace(
            data_dir=args.data_dir, query_id=args.query_id, destination=args.destination
        )
    except (NVDWorkspaceError, OSError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(answer, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
