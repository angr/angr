from __future__ import annotations

import gzip
import json
import os
import tempfile
from unittest import TestCase, main

import pyvex

import angr
from angr.analyses.calling_convention.fact_collector import FactCollector
from angr.analyses.vm_deobfuscation.deobf_reader import load_decompilation_input, project_options_from_dump, read_dump
from angr.analyses.vm_deobfuscation.deobf_writer import dump_decompilation_input
from angr.analyses.vm_deobfuscation.vm_deobfuscation import VMDeobfuscation, mark_return_endpoints
from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.knowledge_plugins.functions.function import Function
from tests.common import bin_location

BINARY = os.path.join(bin_location, "tests", "x86_64", "fauxware")
A = 0x7000_0000_0000_0000
# test rcx, rcx; je +5 / xor eax, eax; ret / mov rbx, [rsp+0x30]; add rsp, 0x20; pop rdi; mov eax, 0xc000000d; ret
ENTRY = bytes.fromhex("4885c97403")
RET0 = bytes.fromhex("31c0c3")
RET1 = bytes.fromhex("488b5c24304883c4205fb80d0000c0c3")


def _vm_function(endpoints=True, exclude=()):
    """A devirtualized function built like VM_1: CFGENodes over synthetic IRSBs, two rets."""
    project = angr.Project(BINARY, auto_load_libs=False)
    project.factory._default_cc = angr.calling_conventions.SimCCMicrosoftAMD64
    project.vm_deobfuscation = True
    model = project.kb.cfgs.new_model("decomp_graph")
    nodes = []
    for i, code in enumerate((ENTRY, RET0, RET1)):
        addr = A + i * 0x10000
        irsb = pyvex.lift(code, addr, project.arch)
        if i == 0:
            irsb.next = pyvex.expr.Const(pyvex.const.U64(A + 0x10000))
            irsb.statements[-1].dst = pyvex.const.U64(A + 0x20000)
        project.synthetic_irsbs[addr] = irsb
        nodes.append(CFGENode(addr, irsb.size, model, irsb=irsb, function_address=A))
    func = Function(project.kb.functions, A, "VM_1", None, is_simprocedure=False)
    func.calling_convention = project.factory.cc()
    project.kb.functions[A] = func
    _ = func.transition_graph
    func.transit_to(nodes[0], nodes[1])
    func.transit_to(nodes[0], nodes[2])
    func.startpoint = nodes[0]
    for n in nodes[1:]:
        func.mark_ret_site(n)
    if endpoints:
        mark_return_endpoints(func, {n.addr for n in nodes[1:]} - set(exclude))
    func.normalized = True
    return project, func


class TestVMReturnEndpoints(TestCase):
    def test_retval_size_read_at_cfgnode_endpoints(self):
        for endpoints, size in ((False, None), (True, 4)):
            project, func = _vm_function(endpoints=endpoints)
            project.analyses.VariableRecoveryFast(func)
            fc = project.analyses[FactCollector].prep()(func)
            assert fc.retval_size == size

    def test_ret_pops_of_synthetic_blocks(self):
        project, func = _vm_function()
        project.analyses.VariableRecoveryFast(func)
        fc = project.analyses[FactCollector].prep()(func)
        # the IRSB's own last instruction is measured, not re-lifted from memory at a synthetic address
        assert fc._ret_pops(func) == {0}

    def test_vm_exit_is_no_return_endpoint(self):
        _, func = _vm_function(exclude={A + 0x20000})
        assert [n.addr for n in func.endpoints_with_type["return"]] == [A + 0x10000]

    def test_native_ret(self):
        project = angr.Project(BINARY, auto_load_libs=False)
        model = project.kb.cfgs.new_model("t")
        irsb = pyvex.lift(RET0, A, project.arch)

        def node(vpc, irsb=irsb):
            return CFGENode(A, irsb.size, model, irsb=irsb, block_id=BlockID.new(A, (), "normal", vpc))

        assert VMDeobfuscation._is_native_ret(node(None))
        # a VM handler's ret leaves the VM
        assert not VMDeobfuscation._is_native_ret(node(0x4F1000))
        jmp = pyvex.lift(bytes.fromhex("eb00"), A, project.arch)
        assert not VMDeobfuscation._is_native_ret(node(None, jmp))

    def test_dump_round_trips_endpoints(self):
        assert self._round_trip(old_format=False, exclude={A + 0x20000}) == [A + 0x10000]

    def test_old_dump_loads_without_endpoints(self):
        # which rets are VM exits is not in an old dump
        assert self._round_trip(old_format=True) == []

    def _round_trip(self, old_format, exclude=()):
        project, func = _vm_function(exclude=exclude)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "dump.json.gz")
            dump_decompilation_input(func, project, path, vm_deobfuscation=True, fail_fast=False)
            if old_format:
                with gzip.open(path, "rt") as f:
                    doc = json.load(f)
                del doc["function"]["endpoints"]
                with gzip.open(path, "wt") as f:
                    json.dump(doc, f)
            doc = read_dump(path)
            fresh = angr.Project(BINARY, **project_options_from_dump(doc))
            loaded, _ = load_decompilation_input(fresh, doc)
        return sorted(n.addr for n in loaded.endpoints_with_type["return"])


if __name__ == "__main__":
    main()
