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
from angr.analyses.vm_deobfuscation.deobf_schema import DeobfFormatError
from angr.analyses.vm_deobfuscation.deobf_writer import dump_decompilation_input
from angr.knowledge_plugins.callsite_prototypes import CallsitePrototypeKind
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.knowledge_plugins.functions.function import Function, PrototypeSource
from angr.knowledge_plugins.propagations.prop_value import Detail, PropValue
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypePointer, parse_signature
from tests.common import bin_location

BINARY = os.path.join(bin_location, "tests", "x86_64", "fauxware")
A = 0x7000_0000_0000_0000
STRIDE = 0x10000
PUTS_HOOK = 0x400100
PRINTF_HOOK = 0x400200
SCRIPT_HOOK = 0x400300


class ScriptOnlyHook(angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]):
    """Stands for a SimProcedure an eval script defines: recorded as __main__, which a replay cannot import."""

    ARGS_MISMATCH = True
    local_vars = ("seen",)

    def run(self, a, b):  # pylint:disable=arguments-differ
        return self.state.solver.Unconstrained("x", 64)


ScriptOnlyHook.__module__ = "__main__"

SCRIPT = """
import angr
open("ran", "w").close()


class ScriptOnlyHook(angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]):
    ARGS_MISMATCH = True

    def run(self, a, b):
        return helper()


def helper():
    return 0


raise SystemExit("the script body must not run")
"""


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
    # a guessed stub prototype: the function type itself unbound, its return type bound
    guessed = SimTypeFunction([SimTypePointer(SimTypeChar())], SimTypePointer(SimTypeChar()).with_arch(project.arch))
    printf.prototype = guessed

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


def _dump(tmpdir, script_hook=False, **kw):
    project, func, init_values = _producer(**kw)
    if script_hook:
        proto = parse_signature("long (f)(char *, int)", arch=project.arch)
        project.hook(SCRIPT_HOOK, ScriptOnlyHook(cc=project.factory.cc(), prototype=proto, display_name="png_inflate"))
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
        # not upgraded to the library declaration, and bound to the arch exactly where the producer's was
        proto = fresh.kb.functions[PRINTF_HOOK].prototype
        assert len(proto.args) == 1
        assert proto._arch is None and proto.args[0]._arch is None and proto.returnty._arch is not None
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

    def test_byte_code_regions_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project, func, init_values = _producer()
            project.byte_code_regions = [(0x601038, 0x601048)]
            project.vm_written_image_pages = [0x602000]
            path = os.path.join(tmpdir, "dump.json.gz")
            dump_decompilation_input(func, project, path, ail_propagator_init_values=init_values, vm_deobfuscation=True)
            doc = read_dump(path)
            fresh = angr.Project(BINARY, **project_options_from_dump(doc))
            load_decompilation_input(fresh, doc)
        assert fresh.byte_code_regions == [(0x601038, 0x601048)]
        assert fresh.vm_written_image_pages == [0x602000]

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

    def test_script_class_hook_replays_from_surrogate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src, _, path = _dump(tmpdir, script_hook=True)
            doc = read_dump(path)
            fresh = angr.Project(BINARY, **project_options_from_dump(doc))
            load_decompilation_input(fresh, doc)

        want, got = src.hooked_by(SCRIPT_HOOK), fresh.hooked_by(SCRIPT_HOOK)
        assert type(got) is not ScriptOnlyHook
        assert f"{type(got).__module__}:{type(got).__qualname__}" == "__main__:ScriptOnlyHook"
        assert isinstance(got, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"])
        assert got.ARGS_MISMATCH is True and got.local_vars == ("seen",)
        assert got.display_name == "png_inflate" and got.num_args == 2
        assert got.prototype == want.prototype and type(got.cc) is type(want.cc)

    def test_old_script_class_dump_loads_classes_from_script(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src, _, path = _dump(tmpdir, script_hook=True)
            doc = read_dump(path)
            for enc in doc["x_replay"]["hooks"]:
                enc.pop("cls_surrogate", None)
            with self.assertRaises(DeobfFormatError):
                load_decompilation_input(angr.Project(BINARY, **project_options_from_dump(doc)), doc)

            script = os.path.join(tmpdir, "script.py")
            with open(script, "w", encoding="utf-8") as fp:
                fp.write(SCRIPT)
            fresh = angr.Project(BINARY, **project_options_from_dump(doc))
            cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                load_decompilation_input(fresh, doc, script=script)
            finally:
                os.chdir(cwd)
            assert not os.path.exists(os.path.join(tmpdir, "ran"))

        got = fresh.hooked_by(SCRIPT_HOOK)
        assert type(got).__qualname__ == "ScriptOnlyHook" and type(got).__module__ == "__main__"
        assert got.ARGS_MISMATCH is True and got.run(None, None) == 0
        assert got.display_name == "png_inflate" and got.prototype == src.hooked_by(SCRIPT_HOOK).prototype


if __name__ == "__main__":
    main()
