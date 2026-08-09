# pylint:disable=redefined-outer-name,no-self-use,missing-class-docstring
from __future__ import annotations

import os

import pytest

from angr.mcp.edit_tools import rename, set_comments, set_type
from angr.mcp.errors import InvalidArgumentError
from angr.mcp.server import decompile_function, get_cfg, load_binary
from angr.mcp.session import get_session_manager

from .conftest import BIN_LOCATION

FAUXWARE = os.path.join(BIN_LOCATION, "tests", "x86_64", "fauxware")


@pytest.fixture
def project_id():
    """A loaded fauxware project with a CFG and `authenticate` already decompiled."""
    if not os.path.exists(FAUXWARE):
        pytest.skip(f"Test binary not found: {FAUXWARE}")
    pid = load_binary(FAUXWARE)["project_id"]
    get_cfg(pid)
    decompile_function(pid, name="authenticate")
    yield pid
    get_session_manager().close_session(pid)


def code(project_id: str, name: str = "authenticate") -> str:
    return decompile_function(project_id, name=name)["code"]


class TestRename:
    def test_renames_variables_and_function(self, project_id):
        result = rename(
            project_id,
            [
                {"kind": "variable", "function": "authenticate", "name": "a0", "new_name": "user"},
                {"kind": "variable", "function": "authenticate", "name": "sneaky", "new_name": "backdoor"},
                {"kind": "function", "name": "authenticate", "new_name": "check_login"},
            ],
        )

        assert result["succeeded"] == 3
        assert result["failed"] == 0
        text = code(project_id, "check_login")
        assert "user" in text
        assert "backdoor" in text
        assert "check_login" in text

    def test_renames_a_global_by_address(self, project_id):
        # resolve the global's address through a variable rename first
        found = rename(
            project_id,
            [{"kind": "variable", "function": "authenticate", "name": "sneaky", "new_name": "backdoor"}],
        )
        addr = found["results"][0]["detail"]["global_address"]

        result = rename(project_id, [{"kind": "global", "address": addr, "new_name": "secret_pw"}])
        assert result["succeeded"] == 1
        assert "secret_pw" in code(project_id)

    def test_one_bad_item_does_not_stop_the_others(self, project_id):
        result = rename(
            project_id,
            [
                {"kind": "variable", "function": "authenticate", "name": "nope", "new_name": "x"},
                {"kind": "variable", "function": "authenticate", "name": "a0", "new_name": "user"},
            ],
        )

        assert result["failed"] == 1
        assert result["succeeded"] == 1
        assert result["results"][0]["status"] == "error"
        # a failed lookup reports what the caller could have said instead
        assert "a0" in result["results"][0]["candidates"]

    def test_stop_on_error_skips_the_rest(self, project_id):
        result = rename(
            project_id,
            [
                {"kind": "variable", "function": "authenticate", "name": "nope", "new_name": "x"},
                {"kind": "variable", "function": "authenticate", "name": "a0", "new_name": "user"},
            ],
            stop_on_error=True,
        )

        assert result["failed"] == 1
        assert result["skipped"] == 1
        assert result["results"][1]["status"] == "skipped"
        assert "user" not in code(project_id)

    def test_dry_run_changes_nothing(self, project_id):
        before = code(project_id)
        result = rename(
            project_id,
            [{"kind": "variable", "function": "authenticate", "name": "a0", "new_name": "user"}],
            dry_run=True,
        )

        assert result["dry_run"] is True
        assert result["results"][0]["old"] == "a0"
        assert code(project_id) == before

    def test_collision_is_rejected_by_default(self, project_id):
        result = rename(project_id, [{"kind": "function", "name": "authenticate", "new_name": "main"}])
        assert result["failed"] == 1
        assert result["results"][0]["error_kind"] == "NameCollisionError"

        result = rename(
            project_id,
            [{"kind": "function", "name": "authenticate", "new_name": "main"}],
            allow_overwrite=True,
        )
        assert result["succeeded"] == 1

    def test_renaming_to_the_same_name_is_unchanged(self, project_id):
        result = rename(project_id, [{"kind": "function", "name": "authenticate", "new_name": "authenticate"}])
        assert result["unchanged"] == 1
        assert result["succeeded"] == 0

    def test_missing_kind_is_an_item_error(self, project_id):
        result = rename(project_id, [{"function": "authenticate", "name": "a0", "new_name": "user"}])
        assert result["failed"] == 1
        assert "kind" in result["results"][0]["error"]

    def test_malformed_request_raises(self, project_id):
        with pytest.raises(InvalidArgumentError):
            rename(project_id, [])
        with pytest.raises(InvalidArgumentError):
            rename(project_id, ["not an object"])


class TestSetType:
    def test_retypes_a_local(self, project_id):
        result = set_type(
            project_id,
            [{"kind": "variable", "function": "authenticate", "name": "v2", "type": "long long"}],
        )

        assert result["succeeded"] == 1
        assert "long long v2" in code(project_id)

    def test_sets_a_prototype(self, project_id):
        result = set_type(
            project_id,
            [{"kind": "function", "name": "authenticate", "type": "int authenticate(char *user, char *pw)"}],
        )

        assert result["succeeded"] == 1
        text = code(project_id)
        assert "char *user" in text
        assert "char *pw" in text

    def test_sets_only_the_return_type(self, project_id):
        result = set_type(project_id, [{"kind": "return", "function": "authenticate", "type": "int"}])

        assert result["succeeded"] == 1
        text = code(project_id)
        assert text.startswith("extern") or "int authenticate" in text
        assert "int authenticate(char *" in text

    def test_prototype_change_preserves_earlier_items(self, project_id):
        """A prototype change drops the variable manager; edits from the same batch must survive."""
        result = set_type(
            project_id,
            [
                {"kind": "variable", "function": "authenticate", "name": "v2", "type": "long long"},
                {"kind": "return", "function": "authenticate", "type": "int"},
            ],
        )

        assert result["failed"] == 0
        text = code(project_id)
        assert "long long v2" in text
        assert "int authenticate" in text

    def test_unparseable_type_is_an_item_error(self, project_id):
        result = set_type(
            project_id,
            [{"kind": "variable", "function": "authenticate", "name": "v2", "type": "not a type !!"}],
        )
        assert result["failed"] == 1
        assert result["results"][0]["error_kind"] == "TypeParseError"


class TestSetComments:
    def test_comments_a_function_header(self, project_id):
        result = set_comments(
            project_id,
            [{"kind": "function", "function": "authenticate", "comment": "validates a password"}],
        )

        assert result["succeeded"] == 1
        # the header renders from the knowledge base; it must not also be mirrored into the
        # statement comments, which would show it twice
        assert code(project_id).count("validates a password") == 1

    def test_comment_is_cleared_by_an_empty_string(self, project_id):
        set_comments(project_id, [{"kind": "function", "function": "authenticate", "comment": "temporary"}])
        set_comments(project_id, [{"kind": "function", "function": "authenticate", "comment": ""}])

        assert "temporary" not in code(project_id)

    def test_statement_comment_reports_placement(self, project_id):
        entry = decompile_function(project_id, name="authenticate")
        addr = int(entry["function_address"], 16)

        result = set_comments(project_id, [{"kind": "address", "address": hex(addr + 0x10), "comment": "here"}])
        detail = result["results"][0]["detail"]
        assert "rendered_inline" in detail
        assert "snapped_from" in detail


if __name__ == "__main__":
    pytest.main([__file__])
