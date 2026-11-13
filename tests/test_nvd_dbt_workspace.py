"""EA-03A4B offline workspace safety and isolated dbt integration tests."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import duckdb
import pytest

from patchline.warehouse import nvd_dbt_workspace as workspace
from patchline.warehouse.nvd_stage import NVDWarehouseError, _ddl

QUERY = "a" * 64


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "data" / "warehouse" / "nvd-queries" / f"{QUERY}.duckdb"
    path.parent.mkdir(parents=True)
    with duckdb.connect(str(path)) as con:
        _ddl(con)
        con.execute(
            "INSERT INTO nvd_stage.query_registry VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                "patchline.nvd-duckdb-query-staging.v1", QUERY, "b" * 64, "c" * 64,
                "NVD_CVE", "last_modified_window", 2, 2, 1,
                False, False, False, False,
            ],
        )
        cve_rows = [
            [
                QUERY, 0, "CVE-2026-10001", "test.fixture", "Analyzed",
                "2026-11-01T00:00:00.000", "2026-11-12T00:00:00.000",
                "Synthetic example only", "d" * 64, 0, 0,
                False, False, False, False, False, '{"cve_id":"CVE-2026-10001"}',
            ],
            [
                QUERY, 1, "CVE-2026-10002", "test.fixture", "Analyzed",
                "2026-11-01T00:00:00.000", "2026-11-12T00:00:00.000",
                None, "d" * 64, 0, 1,
                True, True, True, True, True, '{"cve_id":"CVE-2026-10002"}',
            ],
        ]
        con.executemany(
            "INSERT INTO nvd_stage.cves VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", cve_rows
        )
        con.executemany(
            "INSERT INTO nvd_stage.cvss_metrics VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [
                [QUERY, "CVE-2026-10001", 0, "cvssMetricV31", "3.1", "test", "Primary",
                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL", "{}"],
                [QUERY, "CVE-2026-10001", 1, "cvssMetricV40", "4.0", "test", "Secondary",
                 None, None, "HIGH", "{}"],
            ],
        )
    # Tests imitate an already-verified source. The separate upstream EA-03A4A
    # tests exercise real raw-page, normalized-document and DB verification.
    def verified(_data_dir: Path, *, query_id: str) -> dict:
        assert query_id == QUERY
        return {"status": "verified_existing", "database_path": str(path)}
    monkeypatch.setattr(workspace, "stage_nvd_query", verified)
    return path


def test_copy_is_byte_identical_and_source_unchanged(tmp_path: Path, monkeypatch) -> None:
    source = _source(tmp_path, monkeypatch)
    before = _sha(source)
    target = tmp_path / "scratch" / "nvd-dbt.duckdb"
    result = workspace.prepare_workspace(
        data_dir=tmp_path / "data", query_id=QUERY, destination=target
    )
    assert result["status"] == "prepared_isolated_copy"
    assert result["source_bytes_unchanged"] is True
    assert _sha(source) == _sha(target) == before
    assert not os.path.samefile(source, target)


def test_refuses_existing_destination_without_touching_it(tmp_path: Path, monkeypatch) -> None:
    source = _source(tmp_path, monkeypatch)
    target = tmp_path / "existing.duckdb"
    target.write_bytes(b"do not overwrite")
    with pytest.raises(workspace.NVDWorkspaceError, match="exists"):
        workspace.prepare_workspace(data_dir=tmp_path / "data", query_id=QUERY, destination=target)
    assert target.read_bytes() == b"do not overwrite"
    assert source.is_file()


def test_rejects_source_as_destination(tmp_path: Path, monkeypatch) -> None:
    source = _source(tmp_path, monkeypatch)
    with pytest.raises(workspace.NVDWorkspaceError, match="exists|different"):
        workspace.prepare_workspace(data_dir=tmp_path / "data", query_id=QUERY, destination=source)


def test_rejects_invalid_query_id(tmp_path: Path) -> None:
    with pytest.raises(workspace.NVDWorkspaceError, match="SHA-256"):
        workspace.prepare_workspace(
            data_dir=tmp_path / "data", query_id="../escape",
            destination=tmp_path / "copy.duckdb",
        )
    assert not (tmp_path / "copy.duckdb").exists()


def test_rejects_wrong_extension_before_verification(tmp_path: Path, monkeypatch) -> None:
    _source(tmp_path, monkeypatch)
    with pytest.raises(workspace.NVDWorkspaceError, match=".duckdb"):
        workspace.prepare_workspace(
            data_dir=tmp_path / "data", query_id=QUERY,
            destination=tmp_path / "copy.txt",
        )


def test_upstream_verification_failure_cannot_create_copy(tmp_path: Path, monkeypatch) -> None:
    _source(tmp_path, monkeypatch)
    target = tmp_path / "copy.duckdb"
    def fail(*_args, **_kwargs):
        raise NVDWarehouseError("tampered input")
    monkeypatch.setattr(workspace, "stage_nvd_query", fail)
    with pytest.raises(workspace.NVDWorkspaceError, match="tampered input"):
        workspace.prepare_workspace(
            data_dir=tmp_path / "data", query_id=QUERY, destination=target
        )
    assert not target.exists()


def test_rejects_symlink_destination(tmp_path: Path, monkeypatch) -> None:
    _source(tmp_path, monkeypatch)
    original = tmp_path / "original"
    original.write_bytes(b"unchanged")
    link = tmp_path / "link.duckdb"
    try:
        link.symlink_to(original)
    except (OSError, NotImplementedError):
        pytest.skip("OS does not permit unprivileged symlinks")
    with pytest.raises(workspace.NVDWorkspaceError, match="exists"):
        workspace.prepare_workspace(
            data_dir=tmp_path / "data", query_id=QUERY, destination=link
        )
    assert original.read_bytes() == b"unchanged"


def test_dbt_run_and_all_data_tests_with_isolated_synthetic_db(tmp_path: Path, monkeypatch) -> None:
    dbt_executable = shutil.which("dbt")
    assert dbt_executable is not None, "dbt must be available in the locked development toolchain"
    source = _source(tmp_path, monkeypatch)
    before = _sha(source)
    target = tmp_path / "nvd-dbt-work.duckdb"
    workspace.prepare_workspace(data_dir=tmp_path / "data", query_id=QUERY, destination=target)
    project = Path(__file__).resolve().parents[1] / "dbt_nvd"
    env = os.environ.copy()
    env["EXPLOIT_ATLAS_NVD_DBT_PATH"] = str(target)
    args = [
        "--project-dir", str(project),
        "--profiles-dir", str(project),
        "--target-path", str(tmp_path / "dbt-target"),
        "--log-path", str(tmp_path / "dbt-logs"),
    ]
    for command in ("run", "test"):
        result = subprocess.run(
            [dbt_executable, command, *args],
            capture_output=True, text=True, env=env,
            check=False, timeout=120,
        )
        assert result.returncode == 0, f"dbt {command} failed:\n{result.stdout}\n{result.stderr}"
    with duckdb.connect(str(target), read_only=True) as con:
        assert con.execute(
            "SELECT COUNT(*) FROM nvd_analytics_staging.stg_nvd_cves"
        ).fetchone()[0] == 2
        assert con.execute(
            "SELECT cvss_version, base_score FROM "
            "nvd_analytics_staging.stg_nvd_cvss_metrics ORDER BY metric_index"
        ).fetchall() == [("3.1", 9.8), ("4.0", None)]
    assert _sha(source) == before
