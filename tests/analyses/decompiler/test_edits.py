# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.decompiler.edits import (
    DecompilationEditError,
    NameCollisionError,
    NotDecompiledError,
    NullEditHooks,
    UnsupportedEditError,
    VariableNotFoundError,
    list_variable_names,
    reflow_types,
    rename_function,
    rename_variable,
    require_cache,
    resolve_function,
    resolve_variable,
    set_comment,
    set_function_prototype,
    set_variable_type,
)
from angr.analyses.decompiler.edits.errors import AmbiguousFunctionError, InvalidNameError
from angr.knowledge_plugins import CommentKind
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")


def load(decompile: str | None = "authenticate"):
    """Load fauxware and optionally decompile one function. Roughly 1s."""
    proj = angr.Project(FAUXWARE, auto_load_libs=False)
    proj.analyses.CFGFast(normalize=True, data_references=True)
    proj.analyses.CompleteCallingConventions(analyze_callsites=True)
    func = proj.kb.functions[decompile] if decompile else None
    if func is not None:
        proj.analyses.Decompiler(func)
    return proj, func


def text_of(proj, func):
    return require_cache(proj.kb, func.addr).codegen.text


class RecordingHooks(NullEditHooks):
    """Records hook calls so ordering and the values observed can be asserted."""

    def __init__(self):
        self.calls: list[tuple] = []

    def before_function_renamed(self, func, old_name, new_name):
        self.calls.append(("function_renamed", func.name, old_name, new_name))

    def before_stack_var_renamed(self, func, offset, old_name, new_name):
        self.calls.append(("stack_var_renamed", offset, old_name, new_name))

    def before_func_arg_renamed(self, func, arg_index, old_name, new_name):
        self.calls.append(("func_arg_renamed", arg_index, old_name, new_name))

    def before_global_var_renamed(self, addr, old_name, new_name):
        self.calls.append(("global_var_renamed", addr, old_name, new_name))

    def before_stack_var_retyped(self, func, offset, old_type, new_type):
        self.calls.append(("stack_var_retyped", offset, str(old_type), str(new_type)))

    def before_func_arg_retyped(self, func, arg_index, old_type, new_type):
        self.calls.append(("func_arg_retyped", arg_index, str(old_type), str(new_type)))

    def before_global_var_retyped(self, addr, old_type, new_type):
        self.calls.append(("global_var_retyped", addr, str(new_type)))

    def before_other_var_retyped(self, var, old_type, new_type):
        self.calls.append(("other_var_retyped", str(new_type)))

    def before_function_retyped(self, func, old_proto, new_proto):
        self.calls.append(("function_retyped", str(old_proto), str(new_proto)))

    def before_comment_changed(self, addr, old, new, created, decomp):
        self.calls.append(("comment_changed", addr, old, new, created, decomp))


class TestResolve(unittest.TestCase):
    def test_resolve_function_by_name_and_address(self):
        proj, func = load()
        assert resolve_function(proj.kb, name="authenticate").addr == func.addr
        assert resolve_function(proj.kb, address=func.addr).addr == func.addr
        # any address inside the function resolves to it
        assert resolve_function(proj.kb, address=func.addr + 4).addr == func.addr
        with self.assertRaises(DecompilationEditError):
            resolve_function(proj.kb, address=func.addr + 4, containing=False)

    def test_resolve_function_ambiguous_after_rename(self):
        proj, _ = load(decompile=None)
        rename_function(proj, proj.kb.functions["main"], "collide")
        rename_function(proj, proj.kb.functions["authenticate"], "collide")
        with self.assertRaises(AmbiguousFunctionError) as ctx:
            resolve_function(proj.kb, name="collide")
        assert len(ctx.exception.addresses) == 2

    def test_resolve_variable_kinds(self):
        proj, func = load()
        codegen = require_cache(proj.kb, func.addr).codegen

        arg = resolve_variable(proj.kb, func.addr, "a0", codegen=codegen)
        assert arg.kind == "argument"
        assert arg.arg_index == 0

        # fauxware's authenticate has a stack-allocated password buffer
        local = next(
            resolve_variable(proj.kb, func.addr, name, codegen=codegen)
            for name in list_variable_names(codegen, proj.kb, func.addr)
            if name.startswith("v")
        )
        assert local.kind == "local"

        # `sneaky` is a global; neither llm_suggest_variable_names nor get_unified_variables sees it
        glob = resolve_variable(proj.kb, func.addr, "sneaky", codegen=codegen)
        assert glob.kind == "global"
        assert glob.global_addr is not None
        assert glob.unified is None

    def test_resolve_variable_unknown_lists_candidates(self):
        proj, func = load()
        with self.assertRaises(VariableNotFoundError) as ctx:
            resolve_variable(proj.kb, func.addr, "no_such_variable")
        assert "a0" in ctx.exception.candidates

    def test_rename_requires_decompilation(self):
        proj, _ = load(decompile=None)
        func = proj.kb.functions["authenticate"]
        with self.assertRaises(NotDecompiledError):
            rename_variable(proj, func, "a0", "user")


class TestRename(unittest.TestCase):
    def test_rename_function_updates_kb_labels_and_codegen(self):
        proj, func = load()
        result = rename_function(proj, func, "check_login")

        assert result.changed
        assert result.old == "authenticate"
        assert func.name == "check_login"
        assert proj.kb.labels.get(func.addr) == "check_login"
        assert func.is_default_name is False
        assert "check_login" in text_of(proj, func)

    def test_rename_function_rejects_collision(self):
        proj, func = load()
        with self.assertRaises(NameCollisionError):
            rename_function(proj, func, "main", allow_overwrite=False)
        # allowed by default
        assert rename_function(proj, func, "main").changed

    def test_rename_function_same_name_is_a_noop(self):
        proj, func = load()
        assert rename_function(proj, func, "authenticate").changed is False

    def test_rename_rejects_non_identifier(self):
        proj, func = load()
        with self.assertRaises(InvalidNameError):
            rename_variable(proj, func, "a0", "int;")

    def test_rename_variable_kinds_render(self):
        proj, func = load()
        rename_variable(proj, func, "a0", "user")
        rename_variable(proj, func, "sneaky", "backdoor_pw")

        text = text_of(proj, func)
        assert "user" in text
        assert "backdoor_pw" in text
        # a global rename is also a label rename
        glob = resolve_variable(proj.kb, func.addr, "backdoor_pw")
        assert proj.kb.labels.get(glob.global_addr) == "backdoor_pw"

    def test_rename_survives_redecompilation(self):
        """Guards the `renamed` flag: without it re-unification overwrites the name."""
        proj, func = load()
        rename_variable(proj, func, "a0", "user")
        rename_variable(proj, func, "sneaky", "backdoor_pw")
        rename_function(proj, func, "check_login")

        proj.analyses.Decompiler(func, regen_clinic=True)
        text = text_of(proj, func)
        assert "user" in text
        assert "backdoor_pw" in text
        assert "check_login" in text

    def test_rename_global_at_function_entry_is_refused(self):
        """kb.labels[addr] = name silently renames a function when addr is its entry."""
        proj, func = load()
        codegen = require_cache(proj.kb, func.addr).codegen
        glob = resolve_variable(proj.kb, func.addr, "sneaky", codegen=codegen)

        # pretend the global lives at a function entry
        proj.kb.functions._function_map[glob.global_addr] = proj.kb.functions["main"]
        try:
            with self.assertRaises(UnsupportedEditError):
                rename_variable(proj, func, "sneaky", "not_a_function")
        finally:
            del proj.kb.functions._function_map[glob.global_addr]


class TestTypes(unittest.TestCase):
    def test_set_variable_type_reflows_and_rerenders(self):
        """reflow_variable_types does not re-render; the text must still be refreshed."""
        proj, func = load()
        local = next(n for n in list_variable_names(require_cache(proj.kb, func.addr).codegen) if n.startswith("v"))

        set_variable_type(proj, func, local, "long long")
        assert f"long long {local}" in text_of(proj, func)

    def test_manual_type_survives_reflow(self):
        proj, func = load()
        local = next(n for n in list_variable_names(require_cache(proj.kb, func.addr).codegen) if n.startswith("v"))
        set_variable_type(proj, func, local, "long long")

        reflow_types(proj, func)
        assert f"long long {local}" in text_of(proj, func)

    def test_set_argument_type_updates_prototype(self):
        proj, func = load()
        result = set_variable_type(proj, func, "a1", "long long *")

        assert func.prototype is not None
        assert "long long" in str(func.prototype.args[1])
        assert func.addr in result.refresh.redecompile

        proj.analyses.Decompiler(func, regen_clinic=True)
        assert "long long *a1" in text_of(proj, func)

    def test_set_argument_type_can_be_refused(self):
        proj, func = load()
        with self.assertRaises(UnsupportedEditError):
            set_variable_type(proj, func, "a1", "long long *", allow_prototype_change=False)

    def test_unparseable_type_is_rejected(self):
        proj, func = load()
        with self.assertRaises(DecompilationEditError):
            set_variable_type(proj, func, "a0", "not a real type !!")

    def test_set_function_prototype_invalidates_caches(self):
        proj, func = load()
        set_function_prototype(proj, func, "int authenticate(char *user, char *pw)")

        assert (func.addr, "pseudocode") not in proj.kb.decompilations
        assert not proj.kb.dec_variables.has_function_manager(func.addr)

    def test_set_function_prototype_applies_new_argument_names(self):
        proj, func = load()
        result = set_function_prototype(proj, func, "int authenticate(char *user, char *pw)", redecompile=True)

        code = result.detail["code"]
        assert "char *user" in code
        assert "char *pw" in code

    def test_set_function_prototype_preserves_user_edits(self):
        """Dropping dec_variables discards renames and manual types; they must be restored."""
        proj, func = load()
        local = next(n for n in list_variable_names(require_cache(proj.kb, func.addr).codegen) if n.startswith("v"))
        set_variable_type(proj, func, local, "long long")
        rename_variable(proj, func, local, "counter")

        result = set_function_prototype(proj, func, "int authenticate(char *user, char *pw)", redecompile=True)
        code = result.detail["code"]
        assert "long long counter" in code


class TestComments(unittest.TestCase):
    def test_header_comment_rendered_once(self):
        proj, func = load()
        result = set_comment(proj, func.addr, "the auth check")

        assert result.detail["shown_in_pseudocode"] is True
        # the entry address renders from kb.comments; mirroring it would duplicate it
        assert text_of(proj, func).count("the auth check") == 1

    def test_comment_cleared_by_empty_string(self):
        proj, func = load()
        set_comment(proj, func.addr, "temporary")
        set_comment(proj, func.addr, "")

        assert func.addr not in proj.kb.comments
        assert "temporary" not in text_of(proj, func)

    def test_comment_kind_set_and_cleared(self):
        proj, func = load()
        result = set_comment(proj, func.addr, "the auth check", kind=CommentKind.REPEATABLE)
        assert result.detail["kind"] == "REPEATABLE"
        assert proj.kb.comments.kind_of(func.addr) == CommentKind.REPEATABLE

        # editing the text without a kind keeps the existing kind
        set_comment(proj, func.addr, "still the auth check")
        assert proj.kb.comments.kind_of(func.addr) == CommentKind.REPEATABLE

        # clearing the comment resets the kind to the default
        set_comment(proj, func.addr, "")
        assert func.addr not in proj.kb.comments.kinds
        assert proj.kb.comments.kind_of(func.addr) == CommentKind.FUNCTION

    def test_statement_comment_snaps_and_reports_placement(self):
        proj, func = load()
        codegen = require_cache(proj.kb, func.addr).codegen
        first = min(a for a, _ in codegen.map_addr_to_pos.items())

        result = set_comment(proj, first + 1, "loop over entries")
        assert result.detail["snapped_from"] == hex(first + 1)
        assert result.detail["rendered_inline"] is True
        assert "loop over entries" in text_of(proj, func)


class TestHooks(unittest.TestCase):
    def test_hooks_fire_before_mutation_in_order(self):
        """
        The regression guard for angr-management's refactor: hooks must fire before each mutation,
        with the old value still readable, and in the same order the GUI produces.
        """
        proj, func = load()
        hooks = RecordingHooks()

        rename_variable(proj, func, "a0", "user", hooks=hooks)
        rename_variable(proj, func, "sneaky", "backdoor_pw", hooks=hooks)
        rename_function(proj, func, "check_login", hooks=hooks)
        set_comment(proj, func.addr, "the auth check", hooks=hooks)

        kinds = [c[0] for c in hooks.calls]
        assert kinds == [
            "func_arg_renamed",
            "global_var_renamed",
            "function_renamed",
            "comment_changed",
        ]

        # each hook observed the OLD value, and the real argument index rather than a constant
        assert hooks.calls[0][1:] == (0, "a0", "user")
        assert hooks.calls[1][2:] == ("sneaky", "backdoor_pw")
        assert hooks.calls[2][1] == "authenticate"
        assert hooks.calls[3][2:] == ("", "the auth check", True, False)

    def test_retype_hooks(self):
        proj, func = load()
        hooks = RecordingHooks()
        local = next(n for n in list_variable_names(require_cache(proj.kb, func.addr).codegen) if n.startswith("v"))

        set_variable_type(proj, func, local, "long long", hooks=hooks)
        set_variable_type(proj, func, "a1", "long long *", hooks=hooks)
        set_function_prototype(proj, func, "int authenticate(char *a, char *b)", hooks=hooks)

        assert [c[0] for c in hooks.calls] == [
            "stack_var_retyped",
            "func_arg_retyped",
            "function_retyped",
        ]


class TestCacheSpill(unittest.TestCase):
    def test_edits_survive_cache_spill(self):
        """
        Guards the rule that operations re-fetch the cache by key.

        With a one-entry cache the DecompilationCache is evicted to LMDB and comes back as a
        different object, so an edit applied through a held reference would be lost.
        """
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions(analyze_callsites=True)

        cached = proj.kb.decompilations.cached
        if not hasattr(cached, "_cache_limit"):
            self.skipTest("decompilation cache spilling is disabled")
        cached._cache_limit = 1

        authenticate = proj.kb.functions["authenticate"]
        main = proj.kb.functions["main"]
        proj.analyses.Decompiler(authenticate)
        proj.analyses.Decompiler(main)  # evicts authenticate

        proj.analyses.Decompiler(authenticate)
        rename_variable(proj, authenticate, "a0", "user")
        proj.analyses.Decompiler(main)  # evicts authenticate again

        assert "user" in text_of(proj, authenticate)


if __name__ == "__main__":
    unittest.main()
