"""Patchline CLI: reproducible offline checks and explicit source ingestion."""

import argparse
import json
import sys
from importlib.resources import files
from pathlib import Path

from patchline import __version__


def fixture_doctor() -> dict[str, object]:
    """Check bundled offline fixture shape without network access."""
    fixture = files("patchline").joinpath("fixtures/sample_kev.json")
    with fixture.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("Fixture must contain a vulnerabilities list")
    ids = [item.get("cveID") for item in vulnerabilities]
    if not all(isinstance(cve, str) and cve.startswith("CVE-") for cve in ids):
        raise ValueError("Fixture includes an invalid CVE identifier")
    if len(ids) != len(set(ids)):
        raise ValueError("Fixture contains duplicate CVE IDs")
    return {"status": "ok", "mode": "fixture_only", "kev_records": len(ids)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="patchline", description="Patchline analytics CLI")
    parser.add_argument("--version", action="version", version=f"patchline {__version__}")
    commands = parser.add_subparsers(dest="command")
    doctor = commands.add_parser("doctor", help="Check offline foundation fixtures")
    doctor.add_argument("--fixture", action="store_true", help="Use only bundled test data")
    ingest = commands.add_parser("ingest", help="Explicitly download and archive an official source")
    ingest.add_argument("--source", choices=["kev", "epss"], required=True)
    ingest.add_argument("--data-dir", type=Path, default=Path("data"))
    warehouse = commands.add_parser("warehouse", help="Build a local DuckDB warehouse")
    warehouse_commands = warehouse.add_subparsers(dest="warehouse_command", required=True)
    build = warehouse_commands.add_parser("build", help="Build from validated source archives")
    build.add_argument("--data-dir", type=Path, default=Path("data"))
    build.add_argument("--output", type=Path, default=Path("data/warehouse/patchline.duckdb"))
    build.add_argument("--kev-snapshot", type=str)
    build.add_argument("--epss-snapshot", type=str)
    batch = commands.add_parser("batch", help="Plan and reserve source-pinned batch runs")
    batch_commands = batch.add_subparsers(dest="batch_command", required=True)
    plan = batch_commands.add_parser("plan", help="Validate sources and preview an isolated run")
    plan.add_argument("--data-dir", type=Path, default=Path("data"))
    plan.add_argument("--kev-snapshot", required=True)
    plan.add_argument("--epss-snapshot", required=True)
    initialize = batch_commands.add_parser("init", help="Reserve one new planned run on disk")
    initialize.add_argument("--data-dir", type=Path, default=Path("data"))
    initialize.add_argument("--kev-snapshot", required=True)
    initialize.add_argument("--epss-snapshot", required=True)
    status = batch_commands.add_parser("status", help="Read a persisted planned run")
    status.add_argument("--data-dir", type=Path, default=Path("data"))
    status.add_argument("--run-id", required=True)
    journal_init = batch_commands.add_parser(
        "journal-init", help="Anchor a new no-overwrite run journal genesis"
    )
    journal_init.add_argument("--data-dir", type=Path, default=Path("data"))
    journal_init.add_argument("--run-id", required=True)
    journal_status = batch_commands.add_parser(
        "journal-status", help="Verify an existing run journal genesis"
    )
    journal_status.add_argument("--data-dir", type=Path, default=Path("data"))
    journal_status.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    if args.command == "doctor":
        if not args.fixture:
            doctor.error("P1 supports only --fixture; live sources start in P2")
        print(json.dumps(fixture_doctor(), sort_keys=True))
        return 0
    if args.command == "ingest":
        from patchline.ingest.epss import EPSSIngestionError, ingest_epss
        from patchline.ingest.kev import KEVIngestionError, ingest_kev

        try:
            result = ingest_kev(args.data_dir) if args.source == "kev" else ingest_epss(args.data_dir)
        except (KEVIngestionError, EPSSIngestionError, OSError, ValueError, RuntimeError) as exc:
            print(f"{args.source.upper()} ingestion failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "warehouse":
        from patchline.warehouse.build import WarehouseError, build_warehouse

        try:
            result = build_warehouse(
                args.data_dir,
                args.output,
                kev_snapshot_id=args.kev_snapshot,
                epss_snapshot_id=args.epss_snapshot,
            )
        except (WarehouseError, OSError, ValueError, RuntimeError) as exc:
            print(f"Warehouse build failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "batch":
        if args.batch_command in {"journal-init", "journal-status"}:
            from patchline.batch.journal import (
                BatchJournalError,
                initialize_journal,
                inspect_journal,
            )

            try:
                result = (
                    initialize_journal(args.data_dir, run_id=args.run_id)
                    if args.batch_command == "journal-init"
                    else inspect_journal(args.data_dir, run_id=args.run_id)
                )
            except (BatchJournalError, OSError) as exc:
                print(f"Batch {args.batch_command} failed: {exc}", file=sys.stderr)
                return 1
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.batch_command == "plan":
            from patchline.batch.plan import BatchPlanError, plan_batch

            try:
                result = plan_batch(
                    args.data_dir,
                    kev_snapshot=args.kev_snapshot,
                    epss_snapshot=args.epss_snapshot,
                )
            except BatchPlanError as exc:
                print(f"Batch plan failed: {exc}", file=sys.stderr)
                return 1
        else:
            from patchline.batch.state import BatchStateError, initialize_run, read_run

            try:
                if args.batch_command == "init":
                    result = initialize_run(
                        args.data_dir,
                        kev_snapshot=args.kev_snapshot,
                        epss_snapshot=args.epss_snapshot,
                    )
                else:
                    result = read_run(args.data_dir, run_id=args.run_id)
            except (BatchStateError, OSError) as exc:
                print(f"Batch {args.batch_command} failed: {exc}", file=sys.stderr)
                return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    parser.print_help()
    return 0
