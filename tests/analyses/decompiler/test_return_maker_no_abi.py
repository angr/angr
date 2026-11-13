#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""What the decompiler does when the convention has no ABI for the type being returned.

A prototype recovered from a binary can name any return type, and SimCC.return_val raises
AngrTypeError for two kinds of them: a type wider than RETURN_VAL when the convention declares
no OVERFLOW_RETURN_VAL, and any struct, union or fixed-size array, which SimCC refuses whatever
its width. ReturnMaker must treat both like any other location the convention cannot name and
leave the return statement without an expression.

The struct the width tests return is wrapped in a TypeRef, as recovered prototypes name it.
A TypeRef is not a SimStruct, so it skips the aggregate refusal and reaches the width check.

The first two tests build the AIL graph by hand. The third decompiles a tracked AArch64 binary
with every function pinned to return such a struct, which reaches both this site and the one in
reaching definitions.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from types import SimpleNamespace
from typing import cast

import archinfo
import networkx

import angr
from angr import ailment
from angr.analyses.decompiler.return_maker import ReturnMaker
from angr.calling_conventions import SimCCAArch64, SimCCARM, SimCCRISCV64
from angr.errors import AngrTypeError
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimCppClass, SimStruct, SimTypeFunction, SimTypeInt, TypeRef
from tests.common import bin_location


class TestReturnMakerNoABI(unittest.TestCase):
    @staticmethod
    def _graph(arch, returnty, cc):
        manager = ailment.Manager()
        stmt = ailment.Stmt.Return(manager.next_atom(), [], ins_addr=0x1000)
        block = ailment.Block(0x1000, 4, statements=[stmt])
        graph = networkx.DiGraph()
        graph.add_node(block)
        prototype = SimTypeFunction([], returnty).with_arch(arch)
        function = SimpleNamespace(
            addr=0x1000,
            get_prototype=lambda _flavor: prototype,
            prototype_libname=None,
            calling_convention=cc,
        )
        return manager, graph, function

    def test_a_return_the_convention_cannot_place_keeps_the_function(self):
        arch = archinfo.ArchRISCV64()
        struct = SimStruct({"a": SimTypeInt(), "b": SimTypeInt(), "c": SimTypeInt()}, name="three_ints")
        returnty = TypeRef("st_1000_0", struct)
        manager, graph, function = self._graph(arch, returnty, SimCCRISCV64(arch))

        # RISC-V returns in a0 and declares no second return register, so a 12-byte struct is refused
        self.assertRaises(AngrTypeError, function.calling_convention.return_val, returnty, perspective_returned=True)

        ReturnMaker(manager, arch, function, graph)

        (block,) = graph.nodes()
        (stmt,) = block.statements
        assert isinstance(stmt, ailment.Stmt.Return)
        assert not stmt.ret_exprs

    def test_an_aggregate_return_no_convention_lays_out_keeps_the_function(self):
        # The aggregate refusal: SimCC raises for any aggregate whatever its width, so a recovered
        # class is refused on ARM even though SimCCARM declares a second return register. The class
        # has members, so return_val does not treat it as an opaque C++ class returned as an integer.
        arch = archinfo.ArchARM()
        returnty = SimCppClass(name="recovered", members={"a": SimTypeInt(), "b": SimTypeInt()})
        manager, graph, function = self._graph(arch, returnty, SimCCARM(arch))

        with self.assertRaises(AngrTypeError) as refusal:
            function.calling_convention.return_val(returnty, perspective_returned=True)
        assert "aggregate" in str(refusal.exception)

        ReturnMaker(manager, arch, function, graph)

        (block,) = graph.nodes()
        (stmt,) = block.statements
        assert isinstance(stmt, ailment.Stmt.Return)
        assert not stmt.ret_exprs


class TestNoABIReturnEndToEnd(unittest.TestCase):
    def test_a_return_no_convention_can_place_costs_no_function(self):
        # AArch64 returns in x0 and declares no second return register, so a 12-byte struct has
        # nowhere to go. PrototypeSource.USER keeps Clinic from recovering a scalar prototype over
        # the pinned one, which would leave the refusal unreached.
        path = os.path.join(bin_location, "tests", "aarch64", "func-chain-aarch64")
        project = angr.Project(path, auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True)
        struct = SimStruct({"a": SimTypeInt(), "b": SimTypeInt(), "c": SimTypeInt()}, name="three_ints")

        empty = []
        decompiled = 0
        for addr in sorted(cfg.functions):
            function = cfg.functions[addr]
            if function.is_plt or function.is_simprocedure or function.is_alignment:
                continue
            function.calling_convention = SimCCAArch64(project.arch)
            function.prototype = cast(
                SimTypeFunction, SimTypeFunction([], TypeRef(f"st_{addr:x}_0", struct)).with_arch(project.arch)
            )
            function.prototype_source = PrototypeSource.USER
            result = project.analyses.Decompiler(function, cfg=cfg.model)
            text = (result.codegen.text or "") if result.codegen else ""
            if text.strip():
                decompiled += 1
            else:
                empty.append(f"{function.name} at {addr:#x}")

        assert decompiled > 5, "the fixture stopped exercising this"
        assert not empty, f"decompiled to nothing: {empty}"


if __name__ == "__main__":
    unittest.main()
