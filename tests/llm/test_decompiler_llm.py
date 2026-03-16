# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.llm"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest import mock

import angr
from angr.analyses.decompiler import Decompiler
from angr.analyses.decompiler.decompilation_options import options, PARAM_TO_OPTION
from angr.llm_client import LLMClient

from tests.common import bin_location, set_decompiler_option

test_location = os.path.join(bin_location, "tests")


def _make_mock_llm_client(responses: list[dict | None]):
    """
    Create a mock LLM client that returns the given JSON responses in order.
    Each call to completion_json() pops the next response from the list.
    """
    client = mock.MagicMock(spec=LLMClient)
    client.completion_json.side_effect = list(responses)
    return client


class TestDecompilerLLMOption(unittest.TestCase):
    """Tests for the llm_refine decompilation option."""

    def test_llm_refine_option_exists(self):
        """The llm_refine option should be registered."""
        assert "llm_refine" in PARAM_TO_OPTION
        opt = PARAM_TO_OPTION["llm_refine"]
        assert opt.cls == "decompiler"
        assert opt.value_type is bool
        assert opt.default_value is False
        assert opt.category == "LLM"

    def test_llm_refine_option_in_options_list(self):
        """The llm_refine option should appear in the global options list."""
        llm_options = [o for o in options if o.param == "llm_refine"]
        assert len(llm_options) == 1

    def test_set_decompiler_option_llm_refine(self):
        """set_decompiler_option helper should work with llm_refine."""
        opts = set_decompiler_option(None, [("llm_refine", True)])
        assert len(opts) == 1
        assert opts[0][0].param == "llm_refine"
        assert opts[0][1] is True


class TestDecompilerLLMRefineBase(unittest.TestCase):
    """Base class providing a decompiled fauxware function for LLM tests."""

    @classmethod
    def setUpClass(cls):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        cls.proj = angr.Project(bin_path, auto_load_libs=False)
        cls.cfg = cls.proj.analyses.CFGFast(normalize=True)

    def _decompile(self, func_name_or_addr="main", **kwargs):
        func = self.cfg.functions[func_name_or_addr]
        dec = self.proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=self.cfg.model, **kwargs)
        assert dec.codegen is not None, f"Decompilation of {func_name_or_addr} failed"
        assert dec.codegen.text is not None
        return dec


class TestDecompilerLLMRefine(TestDecompilerLLMRefineBase):
    """Tests for the llm_refine orchestrator method."""

    def test_llm_refine_returns_false_when_no_llm_client(self):
        """llm_refine() should return False when no LLM client is configured."""
        dec = self._decompile("main")
        self.proj.llm_client = None
        result = dec.llm_refine()
        assert result is False

    def test_llm_refine_returns_false_when_no_codegen(self):
        """llm_refine() should return False when codegen is None."""
        dec = self._decompile("main")
        dec.codegen = None
        result = dec.llm_refine()
        assert result is False

    def test_llm_refine_calls_all_three_methods(self):
        """llm_refine() should call all three suggest methods."""
        dec = self._decompile("main")
        mock_client = _make_mock_llm_client([{}, {}, {}])
        self.proj.llm_client = mock_client

        with (
            mock.patch.object(dec, "llm_suggest_variable_names", return_value=False) as m_vars,
            mock.patch.object(dec, "llm_suggest_function_name", return_value=False) as m_func,
            mock.patch.object(dec, "llm_suggest_variable_types", return_value=False) as m_types,
        ):
            dec.llm_refine()
            m_vars.assert_called_once()
            m_func.assert_called_once()
            m_types.assert_called_once()

    def test_llm_refine_regenerates_text_when_changed(self):
        """llm_refine() should call regenerate_text() when changes are made."""
        dec = self._decompile("main")
        mock_client = _make_mock_llm_client([])
        self.proj.llm_client = mock_client

        with (
            mock.patch.object(dec, "llm_suggest_variable_names", return_value=True),
            mock.patch.object(dec, "llm_suggest_function_name", return_value=False),
            mock.patch.object(dec, "llm_suggest_variable_types", return_value=False),
            mock.patch.object(dec.codegen, "regenerate_text") as m_regen,
        ):
            result = dec.llm_refine()
            assert result is True
            m_regen.assert_called_once()

    def test_llm_refine_skips_regenerate_when_no_change(self):
        """llm_refine() should not call regenerate_text() when nothing changed."""
        dec = self._decompile("main")
        mock_client = _make_mock_llm_client([])
        self.proj.llm_client = mock_client

        with (
            mock.patch.object(dec, "llm_suggest_variable_names", return_value=False),
            mock.patch.object(dec, "llm_suggest_function_name", return_value=False),
            mock.patch.object(dec, "llm_suggest_variable_types", return_value=False),
            mock.patch.object(dec.codegen, "regenerate_text") as m_regen,
        ):
            result = dec.llm_refine()
            assert result is False
            m_regen.assert_not_called()


class TestDecompilerLLMSuggestVariableNames(TestDecompilerLLMRefineBase):
    """Tests for llm_suggest_variable_names."""

    def test_renames_variables(self):
        """Should rename variables when the LLM suggests new names."""
        dec = self._decompile("main")
        assert dec._variable_kb is not None
        assert dec.codegen is not None and dec.codegen.text is not None

        # collect current variable names
        varman = dec._variable_kb.variables[dec.func.addr]
        unified_vars = varman.get_unified_variables(sort=None)
        assert len(unified_vars) > 0, "Expected at least one variable"

        # pick a variable to rename
        target_var = unified_vars[0]
        old_name = target_var.name or str(target_var)

        mock_client = _make_mock_llm_client([{old_name: "renamed_var"}])

        result = dec.llm_suggest_variable_names(llm_client=mock_client, code_text=dec.codegen.text)
        assert result is True
        assert target_var.name == "renamed_var"
        assert target_var.renamed is True

    def test_skips_unknown_variables(self):
        """Should skip variable names that don't match any known variable."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None

        mock_client = _make_mock_llm_client([{"nonexistent_var_xyz": "new_name"}])

        result = dec.llm_suggest_variable_names(llm_client=mock_client, code_text=dec.codegen.text)
        assert result is False

    def test_skips_same_name_renames(self):
        """Should skip rename when old_name == new_name."""
        dec = self._decompile("main")
        assert dec._variable_kb is not None
        assert dec.codegen is not None and dec.codegen.text is not None

        varman = dec._variable_kb.variables[dec.func.addr]
        unified_vars = varman.get_unified_variables(sort=None)
        target_var = unified_vars[0]
        old_name = target_var.name or str(target_var)

        mock_client = _make_mock_llm_client([{old_name: old_name}])

        result = dec.llm_suggest_variable_names(llm_client=mock_client, code_text=dec.codegen.text)
        assert result is False

    def test_returns_false_on_empty_response(self):
        """Should return False when LLM returns None."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None
        mock_client = _make_mock_llm_client([None])

        result = dec.llm_suggest_variable_names(llm_client=mock_client, code_text=dec.codegen.text)
        assert result is False

    def test_returns_false_when_no_client(self):
        """Should return False when no LLM client is available."""
        dec = self._decompile("main")
        self.proj.llm_client = None
        result = dec.llm_suggest_variable_names()
        assert result is False

    def test_skips_non_string_values(self):
        """Should ignore non-string rename values."""
        dec = self._decompile("main")
        assert dec._variable_kb is not None
        assert dec.codegen is not None and dec.codegen.text is not None

        varman = dec._variable_kb.variables[dec.func.addr]
        unified_vars = varman.get_unified_variables(sort=None)
        target_var = unified_vars[0]
        old_name = target_var.name or str(target_var)
        original_name = target_var.name

        mock_client = _make_mock_llm_client([{old_name: 42}])

        result = dec.llm_suggest_variable_names(llm_client=mock_client, code_text=dec.codegen.text)
        assert result is False
        assert target_var.name == original_name

    def test_multiple_renames(self):
        """Should rename multiple variables at once."""
        dec = self._decompile("main")
        assert dec._variable_kb is not None
        assert dec.codegen is not None and dec.codegen.text is not None

        varman = dec._variable_kb.variables[dec.func.addr]
        unified_vars = varman.get_unified_variables(sort=None)
        if len(unified_vars) < 2:
            self.skipTest("Need at least 2 variables for this test")

        var_a = unified_vars[0]
        var_b = unified_vars[1]
        name_a = var_a.name or str(var_a)
        name_b = var_b.name or str(var_b)

        mock_client = _make_mock_llm_client([{name_a: "alpha", name_b: "beta"}])

        result = dec.llm_suggest_variable_names(llm_client=mock_client, code_text=dec.codegen.text)
        assert result is True
        assert var_a.name == "alpha"
        assert var_b.name == "beta"


class TestDecompilerLLMSuggestFunctionName(TestDecompilerLLMRefineBase):
    """Tests for llm_suggest_function_name."""

    def test_renames_function_with_default_name(self):
        """Should rename functions that are marked with is_default_name = True."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None

        # Temporarily set the name to a sub_ name
        original_name = dec.func.name
        dec.func.name = "sub_401000"
        dec.func.is_default_name = True
        if dec.codegen.cfunc:
            dec.codegen.cfunc.name = "sub_401000"

        mock_client = _make_mock_llm_client([{"function_name": "check_password"}])

        try:
            result = dec.llm_suggest_function_name(llm_client=mock_client, code_text=dec.codegen.text)
            assert result is True
            assert dec.func.name == "check_password"
            if dec.codegen.cfunc:
                assert dec.codegen.cfunc.name == "check_password"
        finally:
            dec.func.name = original_name

    def test_skips_named_function(self):
        """Should skip functions that already have meaningful names (not sub_/fcn.)."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None

        # "main" doesn't start with sub_ or fcn., so should be skipped
        mock_client = _make_mock_llm_client([{"function_name": "better_name"}])

        result = dec.llm_suggest_function_name(llm_client=mock_client, code_text=dec.codegen.text)
        assert result is False
        assert dec.func.name == "main"
        # LLM should not even be called
        mock_client.completion_json.assert_not_called()

    def test_returns_false_on_empty_response(self):
        """Should return False when LLM returns None."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None

        original_name = dec.func.name
        dec.func.name = "sub_401000"

        mock_client = _make_mock_llm_client([None])

        try:
            result = dec.llm_suggest_function_name(llm_client=mock_client, code_text=dec.codegen.text)
            assert result is False
        finally:
            dec.func.name = original_name

    def test_returns_false_on_same_name(self):
        """Should return False when LLM suggests the same name."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None

        original_name = dec.func.name
        dec.func.name = "sub_401000"

        mock_client = _make_mock_llm_client([{"function_name": "sub_401000"}])

        try:
            result = dec.llm_suggest_function_name(llm_client=mock_client, code_text=dec.codegen.text)
            assert result is False
        finally:
            dec.func.name = original_name

    def test_returns_false_when_no_client(self):
        """Should return False when no LLM client is available."""
        dec = self._decompile("main")
        self.proj.llm_client = None
        result = dec.llm_suggest_function_name()
        assert result is False

    def test_returns_false_on_non_string_name(self):
        """Should return False when function_name in response is not a string."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None

        original_name = dec.func.name
        dec.func.name = "sub_401000"

        mock_client = _make_mock_llm_client([{"function_name": 12345}])

        try:
            result = dec.llm_suggest_function_name(llm_client=mock_client, code_text=dec.codegen.text)
            assert result is False
        finally:
            dec.func.name = original_name


class TestDecompilerLLMSuggestVariableTypes(TestDecompilerLLMRefineBase):
    """Tests for llm_suggest_variable_types."""

    def test_changes_variable_type(self):
        """Should change variable types when LLM suggests valid C types."""
        dec = self._decompile("main")
        assert dec._variable_kb is not None
        assert dec.codegen is not None and dec.codegen.text is not None

        varman = dec._variable_kb.variables[dec.func.addr]
        unified_vars = varman.get_unified_variables(sort=None)
        assert len(unified_vars) > 0

        target_var = unified_vars[0]
        var_name = target_var.name or str(target_var)

        mock_client = _make_mock_llm_client([{var_name: "int"}])

        with mock.patch.object(dec.codegen, "reload_variable_types") as m_reload:
            result = dec.llm_suggest_variable_types(llm_client=mock_client, code_text=dec.codegen.text)
            assert result is True
            m_reload.assert_called_once()

        # verify the type was actually set
        new_type = varman.get_variable_type(target_var)
        assert new_type is not None

    def test_skips_unparseable_types(self):
        """Should skip variables with unparseable type strings."""
        dec = self._decompile("main")
        assert dec._variable_kb is not None
        assert dec.codegen is not None and dec.codegen.text is not None

        varman = dec._variable_kb.variables[dec.func.addr]
        unified_vars = varman.get_unified_variables(sort=None)
        target_var = unified_vars[0]
        var_name = target_var.name or str(target_var)

        mock_client = _make_mock_llm_client([{var_name: "not_a_valid_c_type!!!"}])

        result = dec.llm_suggest_variable_types(llm_client=mock_client, code_text=dec.codegen.text)
        assert result is False

    def test_skips_unknown_variable_names(self):
        """Should skip variable names that don't match any known variable."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None

        mock_client = _make_mock_llm_client([{"nonexistent_var_xyz": "int"}])

        result = dec.llm_suggest_variable_types(llm_client=mock_client, code_text=dec.codegen.text)
        assert result is False

    def test_returns_false_on_empty_response(self):
        """Should return False when LLM returns None."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None
        mock_client = _make_mock_llm_client([None])

        result = dec.llm_suggest_variable_types(llm_client=mock_client, code_text=dec.codegen.text)
        assert result is False

    def test_returns_false_when_no_client(self):
        """Should return False when no LLM client is available."""
        dec = self._decompile("main")
        self.proj.llm_client = None
        result = dec.llm_suggest_variable_types()
        assert result is False

    def test_pointer_type_change(self):
        """Should handle pointer type suggestions."""
        dec = self._decompile("main")
        assert dec._variable_kb is not None
        assert dec.codegen is not None and dec.codegen.text is not None

        varman = dec._variable_kb.variables[dec.func.addr]
        unified_vars = varman.get_unified_variables(sort=None)
        assert len(unified_vars) > 0

        target_var = unified_vars[0]
        var_name = target_var.name or str(target_var)

        mock_client = _make_mock_llm_client([{var_name: "char *"}])

        with mock.patch.object(dec.codegen, "reload_variable_types"):
            result = dec.llm_suggest_variable_types(llm_client=mock_client, code_text=dec.codegen.text)
            assert result is True

    def test_multiple_type_changes(self):
        """Should change types for multiple variables at once."""
        dec = self._decompile("main")
        assert dec._variable_kb is not None
        assert dec.codegen is not None and dec.codegen.text is not None

        varman = dec._variable_kb.variables[dec.func.addr]
        unified_vars = varman.get_unified_variables(sort=None)
        if len(unified_vars) < 2:
            self.skipTest("Need at least 2 variables for this test")

        var_a = unified_vars[0]
        var_b = unified_vars[1]
        name_a = var_a.name or str(var_a)
        name_b = var_b.name or str(var_b)

        mock_client = _make_mock_llm_client([{name_a: "int", name_b: "char *"}])

        with mock.patch.object(dec.codegen, "reload_variable_types"):
            result = dec.llm_suggest_variable_types(llm_client=mock_client, code_text=dec.codegen.text)
            assert result is True

    def test_partial_valid_types(self):
        """When some types parse and some don't, should apply the valid ones."""
        dec = self._decompile("main")
        assert dec._variable_kb is not None
        assert dec.codegen is not None and dec.codegen.text is not None

        varman = dec._variable_kb.variables[dec.func.addr]
        unified_vars = varman.get_unified_variables(sort=None)
        assert len(unified_vars) > 0

        target_var = unified_vars[0]
        var_name = target_var.name or str(target_var)

        # one valid, one invalid
        mock_client = _make_mock_llm_client([{var_name: "int", "bogus_var": "also_bogus_type@@@"}])

        with mock.patch.object(dec.codegen, "reload_variable_types"):
            result = dec.llm_suggest_variable_types(llm_client=mock_client, code_text=dec.codegen.text)
            assert result is True


class TestDecompilerLLMRefineHook(TestDecompilerLLMRefineBase):
    """Tests for the _decompile() hook that triggers llm_refine."""

    def test_hook_not_called_without_option(self):
        """llm_refine should not be called when llm_refine option is not set."""
        with mock.patch("angr.analyses.decompiler.decompiler.Decompiler.llm_refine") as m_refine:
            self._decompile("main")
            m_refine.assert_not_called()

    def test_hook_called_with_option(self):
        """llm_refine should be called when the llm_refine option is enabled."""
        mock_client = _make_mock_llm_client([{}, {}, {}])
        self.proj.llm_client = mock_client

        decompiler_options = set_decompiler_option(None, [("llm_refine", True)])

        try:
            with mock.patch(
                "angr.analyses.decompiler.decompiler.Decompiler.llm_refine", return_value=False
            ) as m_refine:
                self._decompile("main", options=decompiler_options)
                m_refine.assert_called_once()
        finally:
            self.proj.llm_client = None

    def test_hook_catches_exceptions(self):
        """If llm_refine raises, _decompile() should catch it and continue."""
        mock_client = _make_mock_llm_client([])
        self.proj.llm_client = mock_client

        decompiler_options = set_decompiler_option(None, [("llm_refine", True)])

        try:
            with mock.patch(
                "angr.analyses.decompiler.decompiler.Decompiler.llm_refine",
                side_effect=RuntimeError("LLM exploded"),
            ):
                # Should not raise; the exception should be caught
                dec = self._decompile("main", options=decompiler_options)
                assert dec.codegen is not None
        finally:
            self.proj.llm_client = None


class TestDecompilerLLMEndToEnd(TestDecompilerLLMRefineBase):
    """End-to-end tests with mocked LLM responses flowing through the full pipeline."""

    def test_full_variable_rename_flow(self):
        """Full flow: decompile -> mock LLM suggests renames -> verify text changes."""
        dec = self._decompile("main")
        assert dec._variable_kb is not None
        assert dec.codegen is not None and dec.codegen.text is not None

        # collect a variable to rename
        varman = dec._variable_kb.variables[dec.func.addr]
        unified_vars = varman.get_unified_variables(sort=None)
        assert len(unified_vars) > 0

        target_var = unified_vars[0]
        old_name = target_var.name or str(target_var)
        new_name = "llm_suggested_name"

        # mock client that renames one variable, skips function name, skips types
        # Note: llm_suggest_function_name for "main" returns early without calling the LLM
        mock_client = mock.MagicMock(spec=LLMClient)
        mock_client.completion_json.side_effect = [
            {old_name: new_name},  # variable names
            {},  # variable types (function name is skipped for "main")
        ]

        try:
            self.proj.llm_client = mock_client
            result = dec.llm_refine()
            assert result is True
            assert target_var.name == new_name
            # the text should be regenerated and contain the new name
            assert dec.codegen.text is not None
            assert new_name in dec.codegen.text
        finally:
            self.proj.llm_client = None

    def test_full_type_change_flow(self):
        """Full flow: decompile -> mock LLM suggests types -> verify types applied."""
        dec = self._decompile("main")
        assert dec._variable_kb is not None
        assert dec.codegen is not None and dec.codegen.text is not None

        varman = dec._variable_kb.variables[dec.func.addr]
        unified_vars = varman.get_unified_variables(sort=None)
        assert len(unified_vars) > 0

        target_var = unified_vars[0]
        var_name = target_var.name or str(target_var)

        # mock client: no renames, no function rename, one type change
        # Note: llm_suggest_function_name for "main" returns early without calling the LLM
        # (name doesn't start with sub_/fcn.), so only 2 completion_json calls are made
        mock_client = mock.MagicMock(spec=LLMClient)
        mock_client.completion_json.side_effect = [
            {},  # variable names
            {var_name: "int"},  # variable types (function name is skipped for "main")
        ]

        try:
            self.proj.llm_client = mock_client
            result = dec.llm_refine()
            assert result is True

            new_type = varman.get_variable_type(target_var)
            assert new_type is not None
            assert "int" in str(new_type)
        finally:
            self.proj.llm_client = None

    def test_no_changes_flow(self):
        """Full flow: LLM returns empty dicts -> no changes, no regeneration."""
        dec = self._decompile("main")
        assert dec._variable_kb is not None
        assert dec.codegen is not None and dec.codegen.text is not None
        original_text = dec.codegen.text

        # Note: only 2 completion_json calls are made (function name skipped for "main")
        mock_client = mock.MagicMock(spec=LLMClient)
        mock_client.completion_json.side_effect = [
            {},  # variable names
            {},  # variable types (function name is skipped for "main")
        ]

        try:
            self.proj.llm_client = mock_client
            result = dec.llm_refine()
            assert result is False
            # text should remain the same (no regeneration)
            assert dec.codegen.text == original_text
        finally:
            self.proj.llm_client = None


class TestDecompilerLLMSummarizeFunction(TestDecompilerLLMRefineBase):
    """Tests for llm_summarize_function."""

    def test_returns_summary(self):
        """Should return a summary string from the LLM."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None

        mock_client = mock.MagicMock(spec=LLMClient)
        mock_client.completion.return_value = "This function authenticates a user by reading credentials."

        result = dec.llm_summarize_function(llm_client=mock_client, code_text=dec.codegen.text)
        assert result == "This function authenticates a user by reading credentials."
        mock_client.completion.assert_called_once()

    def test_stores_summary_in_cache(self):
        """Should store the summary in the DecompilationCache."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None
        assert dec.cache is not None

        mock_client = mock.MagicMock(spec=LLMClient)
        mock_client.completion.return_value = "This function does something useful."

        result = dec.llm_summarize_function(llm_client=mock_client, code_text=dec.codegen.text)
        assert result == "This function does something useful."
        assert dec.cache.function_summary == "This function does something useful."

    def test_returns_none_when_no_client(self):
        """Should return None when no LLM client is available."""
        dec = self._decompile("main")
        self.proj.llm_client = None
        result = dec.llm_summarize_function()
        assert result is None

    def test_returns_none_when_no_codegen(self):
        """Should return None when no decompiled text is available."""
        dec = self._decompile("main")
        dec.codegen = None

        mock_client = mock.MagicMock(spec=LLMClient)
        result = dec.llm_summarize_function(llm_client=mock_client)
        assert result is None
        mock_client.completion.assert_not_called()

    def test_returns_none_on_empty_response(self):
        """Should return None when the LLM returns an empty string."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None

        mock_client = mock.MagicMock(spec=LLMClient)
        mock_client.completion.return_value = ""

        result = dec.llm_summarize_function(llm_client=mock_client, code_text=dec.codegen.text)
        assert result is None

    def test_returns_none_on_llm_exception(self):
        """Should return None and not raise when the LLM call fails."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None

        mock_client = mock.MagicMock(spec=LLMClient)
        mock_client.completion.side_effect = RuntimeError("LLM exploded")

        result = dec.llm_summarize_function(llm_client=mock_client, code_text=dec.codegen.text)
        assert result is None

    def test_strips_whitespace_from_summary(self):
        """Should strip leading/trailing whitespace from the summary."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None

        mock_client = mock.MagicMock(spec=LLMClient)
        mock_client.completion.return_value = "  \n  A summary with whitespace.  \n  "

        result = dec.llm_summarize_function(llm_client=mock_client, code_text=dec.codegen.text)
        assert result == "A summary with whitespace."

    def test_cache_summary_initially_none(self):
        """The function_summary field should be None before summarization."""
        dec = self._decompile("main")
        assert dec.cache is not None
        assert dec.cache.function_summary is None

    def test_uses_project_llm_client_by_default(self):
        """Should use the project's LLM client when none is explicitly passed."""
        dec = self._decompile("main")
        assert dec.codegen is not None and dec.codegen.text is not None

        mock_client = mock.MagicMock(spec=LLMClient)
        mock_client.completion.return_value = "A summary."

        try:
            self.proj.llm_client = mock_client
            result = dec.llm_summarize_function()
            assert result == "A summary."
            mock_client.completion.assert_called_once()
        finally:
            self.proj.llm_client = None


if __name__ == "__main__":
    unittest.main()
