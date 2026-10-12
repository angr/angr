# pylint:disable=redefined-outer-name,no-self-use,missing-class-docstring
from __future__ import annotations

import os

import pytest

from angr.analyses.decompiler.edits import get_cache
from angr.enums import Flavors
from angr.mcp.edit_tools import rename
from angr.mcp.errors import InvalidArgumentError
from angr.mcp.server import (
    decompile_function,
    get_cfg,
    get_decompilation_flavor,
    list_projects,
    load_binary,
    set_decompilation_flavor,
)
from angr.mcp.session import get_session_manager

from .conftest import BIN_LOCATION

FAUXWARE = os.path.join(BIN_LOCATION, "tests", "x86_64", "fauxware")
RUST = os.path.join(BIN_LOCATION, "tests", "x86_64", "langdetect_rust")


def _load(path: str) -> str:
    if not os.path.exists(path):
        pytest.skip(f"Test binary not found: {path}")
    result = load_binary(path)
    assert result["flavor"] == "pseudocode"
    return result["project_id"]


@pytest.fixture
def project_id():
    pid = _load(FAUXWARE)
    get_cfg(pid)
    yield pid
    get_session_manager().close_session(pid)


class TestFlavorSetting:
    def test_default_is_reported_with_valid_flavors_and_detection(self, project_id):
        result = get_decompilation_flavor(project_id)
        assert result["flavor"] == "pseudocode"
        assert result["available_flavors"] == [str(f) for f in Flavors]
        assert result["detected_language"] == "c"
        assert result["detection_confidence"] in ("low", "medium", "high")
        assert [p["flavor"] for p in list_projects()["projects"] if p["project_id"] == project_id] == ["pseudocode"]

    def test_set_and_get_round_trip(self, project_id):
        result = set_decompilation_flavor(project_id, "rust")
        assert result == {"project_id": project_id, "previous_flavor": "pseudocode", "flavor": "rust"}
        assert get_decompilation_flavor(project_id)["flavor"] == "rust"
        assert get_session_manager().get_session(project_id).flavor == "rust"

    def test_unknown_flavor_names_the_valid_ones(self, project_id):
        with pytest.raises(InvalidArgumentError, match="pseudocode, rust, go"):
            set_decompilation_flavor(project_id, "cobol")
        assert get_decompilation_flavor(project_id)["flavor"] == "pseudocode"
        with pytest.raises(InvalidArgumentError, match="Unknown decompilation flavor"):
            decompile_function(project_id, name="main", flavor="cobol")


class TestDecompileFlavor:
    def test_result_reports_the_session_flavor(self, project_id):
        result = decompile_function(project_id, name="authenticate")
        assert result["flavor"] == "pseudocode"
        assert get_cache(get_session_manager().get_session(project_id).project.kb, int(result["function_address"], 16))

    def test_per_call_override_does_not_change_the_session(self, project_id):
        result = decompile_function(project_id, name="authenticate", flavor="rust")
        assert result["flavor"] == "rust"
        assert "fn " in result["code"]
        assert get_decompilation_flavor(project_id)["flavor"] == "pseudocode"
        kb = get_session_manager().get_session(project_id).project.kb
        addr = int(result["function_address"], 16)
        assert get_cache(kb, addr, "rust") is not None
        assert get_cache(kb, addr, "pseudocode") is None

    def test_edits_follow_the_session_flavor(self, project_id):
        set_decompilation_flavor(project_id, "go")
        before = decompile_function(project_id, name="authenticate")
        assert before["flavor"] == "go"
        assert "func " in before["code"]
        result = rename(
            project_id,
            [{"kind": "function", "function": "authenticate", "new_name": "check_credentials"}],
        )
        assert result["results"][0]["status"] == "ok"
        after = decompile_function(project_id, name="check_credentials")
        assert after["flavor"] == "go"
        assert "check_credentials" in after["code"]
        kb = get_session_manager().get_session(project_id).project.kb
        addr = int(after["function_address"], 16)
        assert get_cache(kb, addr, "go") is not None
        assert get_cache(kb, addr, "pseudocode") is None


class TestLanguageDetection:
    def test_rust_binary_is_detected(self):
        pid = _load(RUST)
        try:
            result = get_decompilation_flavor(pid)
            assert result["detected_language"] == "rust"
            assert result["flavor"] == "pseudocode"
        finally:
            get_session_manager().close_session(pid)
