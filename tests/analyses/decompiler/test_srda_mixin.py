#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr.ailment import Block
from angr.ailment.expression import Const, FunctionLikeMacro, VirtualVariable
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import Assignment, Return
from angr.analyses.decompiler.mixins import SRDAMixin
from angr.analyses.decompiler.variable_map import VariableMap
from angr.sim_type import SimTypeBottom


class TestSRDAMixin(unittest.TestCase):
    def test_vvar_type_of_macro_result(self):
        # synthetic AIL: nothing in angr calls get_vvar_type, so no binary reaches it
        proj = angr.load_shellcode(b"\xc3", "amd64")
        func = proj.kb.functions.function(addr=0, create=True)
        macro = FunctionLikeMacro(1, "format", [Const(2, 1, 64)], bits=64)
        vvar = VirtualVariable(3, 10, 64, VVC.REGISTER, oident=16)
        block = Block(0, 1, statements=[Assignment(4, vvar, macro, ins_addr=0), Return(5, [vvar], ins_addr=0)])
        graph = networkx.DiGraph()
        graph.add_node(block)
        variable_map = VariableMap()
        mixin = SRDAMixin(func, graph, proj, variable_map)
        assert mixin.get_vvar_type(vvar) is None

        # the macro's result type is kept in the variable map
        ty = SimTypeBottom(label="String")
        variable_map.set_returnty(macro, ty)
        assert mixin.get_vvar_type(vvar) is ty


if __name__ == "__main__":
    unittest.main()
