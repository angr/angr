from __future__ import annotations

import gzip
import json
import os
import tempfile
from unittest import TestCase, main

import pyvex

import angr
from angr import ailment, claripy
from angr.analyses.vm_deobfuscation.deobf_reader import (
    load_decompilation_input,
    project_options_from_dump,
    read_dump,
)
from angr.analyses.vm_deobfuscation.deobf_writer import dump_decompilation_input
from angr.knowledge_plugins.callsite_prototypes import CallsitePrototypeKind
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.knowledge_plugins.functions.function import Function, PrototypeSource
from angr.knowledge_plugins.propagations.prop_value import Detail, PropValue
from angr.sim_type import parse_signature
from tests.common import bin_location

BINARY = os.path.join(bin_location, "tests", "x86_64", "fauxware")
A = 0x7000_0000_0000_0000
STRIDE = 0x10000
PUTS_HOOK = 0x400100
PRINTF_HOOK = 0x400200


def _irsb(project, addr):
    return pyvex.IRSB.empty_block(
        project.arch,
        addr,
        statements=[pyvex.stmt.IMark(addr, 1, 0)],
        tyenv=pyvex.block.IRTypeEnv(project.arch, types=[]),
        nxt=pyvex.expr.Const(pyvex.const.U64(addr + STRIDE)),
        jumpkind="Ijk_Boring",
        size=1,
    )


def _producer(main_opts=None):
    """A deobfuscated-looking function with two hooked callees, built in a non-trivial edge order."""
    kwargs = {"auto_load_libs": False}
    if main_opts is not None:
        kwargs["main_opts"] = main_opts
    project = angr.Project(BINARY, **kwargs)
    project.factory._default_cc = angr.calling_conventions.SimCCMicrosoftAMD64
    # a stub with a guessed prototype and a display name, as the eval scripts hook printf
    project.hook(PRINTF_HOOK, angr.SIM_LIBRARIES.get("msvcr100.dll")[0].get_stub("printf", project.arch))
    project.hook(PUTS_HOOK, angr.SIM_PROCEDURES["libc"]["puts"]())

    model = project.kb.cfgs.new_model("decomp_graph")
    nodes = [
        CFGENode(A + i * STRIDE, 1, model, irsb=_irsb(project, A + i * STRIDE), function_address=A) for i in range(5)
    ]
    func = Function(project.kb.functions, A, "VM_1", None, is_simprocedure=False)
    func.calling_convention = project.factory.cc()
    project.kb.functions[A] = func
    _ = func.transition_graph

    puts = project.kb.functions.function(PUTS_HOOK, create=True)
    puts.is_simprocedure = True
    puts.set_prototype(None, parse_signature("int (f)(char *)", arch=project.arch), source=PrototypeSource.SIMPROC)
    puts.calling_convention = angr.calling_conventions.SimCCMicrosoftAMD64(project.arch)
    printf = project.kb.functions.function(PRINTF_HOOK, create=True)
    printf.is_simprocedure = True
    printf.name = "printf"
    printf.prototype = parse_signature("char * (f)(char *)", arch=project.arch)

    # predecessor orders that differ from source-node order
    func.transit_to(nodes[0], nodes[2])
    func.call_to(nodes[1], puts, nodes[3])
    func.transit_to(nodes[0], nodes[1])
    func.return_from_call(puts, nodes[3])
    func.transit_to(nodes[2], nodes[3])
    func.call_to(nodes[3], printf, nodes[4])
    func.return_from_call(printf, nodes[4])
    func.startpoint = nodes[0]
    func.mark_ret_site(nodes[4])
    func.normalized = True

    project.kb.labels[0x601040] = "vm_context"
    project.kb.callsite_prototypes.set_prototype(
        nodes[1].addr, project.factory.cc(), parse_signature("int (f)(char *, int)", arch=project.arch), manual=True
    )
    init_values = {
        "reg": [
            (
                project.arch.bp_offset,
                PropValue(
                    claripy.BVV(0x7FFF_FF00, 64),
                    offset_and_details={0: Detail(8, ailment.Expr.StackBaseOffset(None, 64, 0), None)},
                ),
            )
        ]
    }
    return project, func, init_values


def _dump(tmpdir, **kw):
    project, func, init_values = _producer(**kw)
    path = os.path.join(tmpdir, "dump.json.gz")
    dump_decompilation_input(
        func, project, path, ail_propagator_init_values=init_values, vm_deobfuscation=True, fail_fast=False
    )
    return project, func, path


class TestVMDeobFaithfulReplay(TestCase):
    def test_round_trip_restores_producer_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src, src_func, path = _dump(tmpdir)
            doc = read_dump(path)
            fresh = angr.Project(BINARY, **project_options_from_dump(doc))
            report = {}
            func, kwargs = load_decompilation_input(fresh, doc, report=report)

        assert report["graph_order"] == []
        assert kwargs["fail_fast"] is False
        assert kwargs["vm_deobfuscation"] is True
        (off, pv) = kwargs["ail_propagator_init_values"]["reg"][0]
        assert off == fresh.arch.bp_offset and pv.value.concrete_value == 0x7FFF_FF00
        assert pv.offset_and_details[0].expr.offset == 0 and pv.offset_and_details[0].size == 8

        assert fresh.factory._default_cc is angr.calling_conventions.SimCCMicrosoftAMD64
        hook = fresh.hooked_by(PRINTF_HOOK)
        assert hook.display_name == "printf" and hook.is_stub
        assert hook.prototype == src.hooked_by(PRINTF_HOOK).prototype

        for addr in (PUTS_HOOK, PRINTF_HOOK):
            want, got = src.kb.functions[addr], fresh.kb.functions[addr]
            assert got.name == want.name
            assert got.prototype == want.prototype
            assert got.prototype_source == want.prototype_source
            assert type(got.calling_convention) is type(want.calling_convention)
        # not upgraded to the library declaration
        assert len(fresh.kb.functions[PRINTF_HOOK].prototype.args) == 1
        assert fresh.kb.labels.get(0x601040) == "vm_context"

        site = A + STRIDE
        assert fresh.kb.callsite_prototypes.is_prototype_manual(site)
        assert fresh.kb.callsite_prototypes.get_prototype(
            site, kind=CallsitePrototypeKind.MANUAL
        ) == src.kb.callsite_prototypes.get_prototype(site, kind=CallsitePrototypeKind.MANUAL)

        def preds(f):
            g = f.transition_graph
            return {n.addr: [p.addr for p in g.predecessors(n)] for n in g.nodes()}

        assert preds(func) == preds(src_func)
        assert [n.addr for n in func.transition_graph.nodes()] == [n.addr for n in src_func.transition_graph.nodes()]

    def test_blob_loader_options_round_trip(self):
        opts = {"backend": "blob", "arch": "AMD64", "base_addr": 0x7FF7_0000_0000, "entry_point": 0x7FF7_0000_0010}
        with tempfile.TemporaryDirectory() as tmpdir:
            _, _, path = _dump(tmpdir, main_opts=opts)
            kwargs = project_options_from_dump(read_dump(path))
        assert kwargs["main_opts"] == opts
        assert kwargs["auto_load_libs"] is False

    def test_dumps_without_replay_state_still_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, _, path = _dump(tmpdir)
            doc = read_dump(path)
            for key in ("x_replay", "x_graph_order"):
                doc.pop(key)
            for callee in doc["callees"]:
                callee.pop("x_state")
            doc["function"].pop("x_state")
            legacy = os.path.join(tmpdir, "legacy.json.gz")
            with gzip.open(legacy, "wb") as fp:
                fp.write(json.dumps(doc).encode())
            fresh = angr.Project(BINARY, auto_load_libs=False)
            func, kwargs = load_decompilation_input(fresh, legacy)

        assert func.addr == A
        assert "ail_propagator_init_values" in kwargs and "x_ail_propagator_init_values" not in kwargs
        # the legacy path upgrades an argument-less prototype, but not a one-argument one
        assert len(fresh.kb.functions[PRINTF_HOOK].prototype.args) == 1


if __name__ == "__main__":
    main()
