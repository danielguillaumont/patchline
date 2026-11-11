"""Minimal offline CLI; live data operations are intentionally not implemented yet."""

import argparse
import json
from importlib.resources import files

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
    args = parser.parse_args(argv)
    if args.command == "doctor":
        if not args.fixture:
            doctor.error("P1 supports only --fixture; live sources start in P2")
        print(json.dumps(fixture_doctor(), sort_keys=True))
        return 0
    parser.print_help()
    return 0
