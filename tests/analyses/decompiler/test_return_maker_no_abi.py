#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""What the decompiler does when the convention has no ABI for the type being returned.

A prototype recovered from a binary can name any return type at all, and typehoon names every
struct it recovers. RISC-V returns in a0 and declares no second return register, so a 12-byte
struct has nowhere to go and SimCCRISCV64 says so by raising. ReturnMaker used to let that out
and lose the whole function; it now reads it the way it reads every other location the convention
cannot name, and leaves the return statement without an expression.

The other refusal that reaches this site is the aggregate one, which SimCC raises for every
struct, union and fixed-size array whatever its width, so a convention that does declare a
second return register still gets there with a recovered class.

The first two tests need no binary: the statement, the block and the graph are the three things
ReturnMaker walks, and a prototype is a type. The third decompiles a tracked AArch64 binary
with every function pinned to return such a struct, which is what reaches both this site and
the one in reaching definitions at once.
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

        # the convention is asked the same question ReturnMaker asks, and refuses
        self.assertRaises(AngrTypeError, function.calling_convention.return_val, returnty, perspective_returned=True)

        ReturnMaker(manager, arch, function, graph)

        (block,) = graph.nodes()
        (stmt,) = block.statements
        assert isinstance(stmt, ailment.Stmt.Return)
        assert not stmt.ret_exprs

    def test_an_aggregate_return_no_convention_lays_out_keeps_the_function(self):
        # The other refusal that reaches this site. SimCC names no ABI for any aggregate at all,
        # whatever its width, and typehoon recovers a C++ class as readily as a struct -- so an ARM
        # function returning one is refused even though SimCCARM does declare a second return
        # register. One raise site, one message, and the same thing has to happen here.
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
        # The same refusal through the whole decompiler, on a binary the repository tracks.
        # AArch64 returns in x0 and declares no second return register, so a twelve-byte struct
        # has nowhere to go; type inference names every struct it recovers, and a name is what a
        # recovered prototype carries. Pinning the prototype is what makes the fixture exercise
        # it -- PrototypeSource.USER stops Clinic recovering a scalar over the top. Before this
        # was fixed, 11 of the 14 functions here decompiled to nothing at all.
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
