# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.gui.decompilation_workflows"  # pylint:disable=redefined-builtin

import os
import unittest

from rich.console import Console
from rich.syntax import Syntax

import angr
from angr.misc.testing import is_testing
from angr.sim_type import SimTypeInt, TypeRef

# `tests/gui` has no `__init__.py`. Under pytest's default `prepend` import mode the directory that
# goes on `sys.path` for a test module is its first ancestor without that marker, so this module
# gets `tests/gui` and never the repository root: `from tests.common import ...` here is a
# collection error unless an earlier test module happened to put the root on `sys.path` first, and
# one collection error fails a whole shard. Derive what this module needs instead.
# `tests/ailment/test_irsb.py` locates the binaries the same way.
test_location = os.path.join(os.path.dirname(__file__), "..", "..", "..", "binaries", "tests")

# Whether this is a batch run, in which case the decompiled code is not printed.
WORKER = is_testing or bool(os.environ.get("WORKER", None))


def print_decompilation_result(dec) -> None:
    if WORKER:
        return
    print("Decompilation result:")
    try:
        console = Console()
        console.print(Syntax(dec.codegen.text, "c", line_numbers=False))
    except Exception:  # pylint:disable=broad-exception-caught
        print(dec.codegen.text)


class TestDecompilationWorkflows(unittest.TestCase):
    """
    Tests for decompilation workflows in angr management (or any other GUI if anyone cares enough to create).
    """

    def test_decompiling_a_function_multiple_times(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "struct_access")
        proj = angr.Project(bin_path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions["main"]
        dec = proj.analyses.Decompiler(func, cfg=proj.kb.cfgs["CFGFast"])
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # decompile again, using decompilation cache
        dec_2 = proj.analyses.Decompiler(func, cfg=proj.kb.cfgs["CFGFast"])
        assert dec_2.codegen is not None and dec_2.codegen.text is not None
        print_decompilation_result(dec_2)

        assert dec.codegen.text == dec_2.codegen.text, "Decompilation results should be identical on multiple runs."

    def test_decompiling_function_with_renamed_struct_name(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "struct_access")
        proj = angr.Project(bin_path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions["main"]
        dec = proj.analyses.Decompiler(func, cfg=proj.kb.cfgs["CFGFast"])
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert dec.func.addr in dec.kb.dec_variables
        types = dec.kb.dec_variables["main"].types
        # let's rename a struct field
        new_type_name = "my_awesome_type"
        t = types["struct_0"]
        assert isinstance(t, TypeRef)
        assert len(t.type.fields) == 2
        t.type.name = new_type_name

        # decompile again, using decompilation cache
        dec_2 = proj.analyses.Decompiler(func, cfg=proj.kb.cfgs["CFGFast"])
        assert dec_2.codegen is not None and dec_2.codegen.text is not None
        print_decompilation_result(dec_2)

        assert new_type_name in dec_2.codegen.text, "Decompilation results should reflect the renamed struct type."

    def test_decompiling_function_with_renamed_struct_fields(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "struct_access")
        proj = angr.Project(bin_path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions["main"]
        dec = proj.analyses.Decompiler(func, cfg=proj.kb.cfgs["CFGFast"])
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert dec.func.addr in dec.kb.dec_variables
        types = dec.kb.dec_variables["main"].types
        # let's rename a struct field
        t = types["struct_0"]
        assert isinstance(t, TypeRef)
        assert len(t.type.fields) == 2
        new_field_name = "my_new_field_120"
        t.type.fields[new_field_name] = t.type.fields["field_120"]
        del t.type.fields["field_120"]

        # decompile again, using decompilation cache
        dec_2 = proj.analyses.Decompiler(func, cfg=proj.kb.cfgs["CFGFast"])
        assert dec_2.codegen is not None and dec_2.codegen.text is not None
        print_decompilation_result(dec_2)

        assert new_field_name in dec_2.codegen.text, "Decompilation results should reflect the renamed struct field."

    def test_decompiling_function_with_retyped_struct_field(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "struct_access")
        proj = angr.Project(bin_path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions["main"]
        dec = proj.analyses.Decompiler(func, cfg=proj.kb.cfgs["CFGFast"])
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert "struct struct_1 *field_120;" in dec.codegen.text

        assert dec.func.addr in dec.kb.dec_variables
        types = dec.kb.dec_variables["main"].types
        # let's type a struct field
        t = types["struct_0"]
        assert isinstance(t, TypeRef)
        assert len(t.type.fields) == 2
        assert "field_120" in t.type.fields
        t.type.fields["field_120"] = SimTypeInt(signed=True).with_arch(proj.arch)

        # decompile again, using decompilation cache
        dec_2 = proj.analyses.Decompiler(func, cfg=proj.kb.cfgs["CFGFast"])
        assert dec_2.codegen is not None and dec_2.codegen.text is not None
        print_decompilation_result(dec_2)

        assert "int field_120;" in dec_2.codegen.text, "Decompilation results should reflect the retyped struct field."
        assert "struct_1" not in dec_2.codegen.text


if __name__ == "__main__":
    unittest.main()
