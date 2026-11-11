"""Offline smoke tests for the P1 CLI."""

import json

import pytest

from patchline.cli import fixture_doctor, main


def test_fixture_doctor_has_expected_record_count() -> None:
    assert fixture_doctor() == {"status": "ok", "mode": "fixture_only", "kev_records": 2}


def test_doctor_cli_output(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["doctor", "--fixture"]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "fixture_only"


def test_non_fixture_doctor_refused() -> None:
    with pytest.raises(SystemExit) as error:
        main(["doctor"])
    assert error.value.code == 2
