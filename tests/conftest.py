"""Shared deterministic KEV fixtures for offline ingestion tests."""

import pytest


@pytest.fixture
def schema() -> dict:
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["catalogVersion", "dateReleased", "count", "vulnerabilities"],
        "properties": {
            "catalogVersion": {"type": "string"},
            "dateReleased": {"type": "string", "format": "date-time"},
            "count": {"type": "integer"},
            "vulnerabilities": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["cveID", "dateAdded", "dueDate"],
                    "properties": {
                        "cveID": {"type": "string"},
                        "dateAdded": {"type": "string", "format": "date"},
                        "dueDate": {"type": "string", "format": "date"},
                    },
                },
            },
        },
    }


@pytest.fixture
def catalog() -> dict:
    return {
        "catalogVersion": "test-fixture-only",
        "dateReleased": "2026-11-10T12:00:00Z",
        "count": 2,
        "vulnerabilities": [
            {"cveID": "CVE-2025-0001", "dateAdded": "2025-01-01", "dueDate": "2025-01-31"},
            {"cveID": "CVE-2025-0002", "dateAdded": "2025-01-02", "dueDate": "2025-02-01"},
        ],
    }


