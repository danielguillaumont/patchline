"""Invented CVE source-selection rows for the EA-03A4E3 offline demonstration.

This is NOT a recorded NVD acquisition, verified real archive, or source database.
"""

from __future__ import annotations

import hashlib
from datetime import date
from typing import Any

QUERY_ID = "a" * 64
KEV_ID = hashlib.sha256(b"patchline-ci-synthetic-kev-v1").hexdigest()
EPSS_ID = hashlib.sha256(b"patchline-ci-synthetic-epss-v1").hexdigest()
CUTOFF = "2026-01-15"


def synthetic_selection_and_rows() -> tuple[dict[str, Any], dict[str, Any]]:
    """Fresh selected-source fixture, including true-zero and absent EPSS records."""
    selection = {
        "schema_id": "exploit-atlas.cross-source-selection.v1",
        "status": "source_selection_validated_no_join",
        "kev": {
            "snapshot_id": KEV_ID,
            "source_date": CUTOFF,
            "retrieved_at_utc": "2026-01-15T12:00:00Z",
            "row_count": 2,
        },
        "epss": {
            "snapshot_id": EPSS_ID,
            "source_date": CUTOFF,
            "retrieved_at_utc": "2026-01-15T12:30:00Z",
            "row_count": 2,
            "model_version": "v-ci-synthetic",
        },
        "nvd": {
            "query_id": QUERY_ID,
            "query_mode": "last_modified_window",
            "source": "NVD_CVE",
            "cve_count": 3,
            "cvss_metric_count": 2,
            "source_scope_flags": {
                "point_in_time_consistency_verified": False,
                "global_nvd_completeness_attested": False,
                "source_origin_independently_verified": False,
                "organization_asset_exposure_known": False,
            },
        },
        "cross_source_join_executed": False,
        "join_approved": False,
        "point_in_time_alignment_attested": False,
        "nvd_global_coverage_attested": False,
        "asset_exposure_known": False,
        "source_archive_reverified_by_this_command": False,
    }
    rows = {
        "kev_rows": [
            (KEV_ID, "CVE-2099-0001", date(2026, 1, 10)),
            (KEV_ID, "CVE-2099-0003", date(2026, 1, 11)),
        ],
        "epss_rows": [
            (EPSS_ID, "CVE-2099-0001", date(2026, 1, 15), "v-ci-synthetic", 0.0, 0.0),
            (EPSS_ID, "CVE-2099-9001", date(2026, 1, 15), "v-ci-synthetic", 0.8, 0.9),
        ],
        "nvd_rows": [
            (QUERY_ID, "CVE-2099-0001", "2026-01-01T00:00:00.000",
             "2026-01-12T00:00:00.000", "Analyzed", "d" * 64),
            (QUERY_ID, "CVE-2099-0003", "2026-01-01T00:00:00.000",
             "2026-01-12T00:00:00.000", "Analyzed", "d" * 64),
            (QUERY_ID, "CVE-2099-9999", "2026-01-01T00:00:00.000",
             "2026-01-12T00:00:00.000", "Awaiting Analysis", "d" * 64),
        ],
        "metric_rows": [
            (QUERY_ID, "CVE-2099-0001", 0, "cvssMetricV31", "3.1", "NVD", "Primary",
             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
            (QUERY_ID, "CVE-2099-0001", 1, "cvssMetricV40", "4.0", "NVD", "Secondary",
             None, None, None),
        ],
    }
    return selection, rows
