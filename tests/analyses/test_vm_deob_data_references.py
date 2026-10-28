from __future__ import annotations

import os
import tempfile
from unittest import TestCase, main

import pyvex

import angr
from angr.analyses.vm_deobfuscation.data_references import collect_data_references
from angr.analyses.vm_deobfuscation.deobf_reader import load_decompilation_input
from angr.analyses.vm_deobfuscation.deobf_writer import dump_decompilation_input
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort
from angr.knowledge_plugins.functions.function import Function
from tests.common import bin_location

BINARY = os.path.join(bin_location, "tests", "x86_64", "fauxware")
SYNTHETIC_ADDR = 0x7000_0000_0000_0000
WELCOME = 0x4008E0  # "Welcome to the admin console, trusted user!\n" in .rodata


def _irsb(project, statements, addr=SYNTHETIC_ADDR):
    return pyvex.IRSB.empty_block(
        project.arch,
        addr,
        statements=[pyvex.stmt.IMark(addr, 1, 0), *statements],
        tyenv=pyvex.block.IRTypeEnv(project.arch, types=["Ity_I64"]),
        nxt=pyvex.expr.Const(pyvex.const.U64(SYNTHETIC_ADDR + 0x10000)),
        jumpkind="Ijk_Boring",
        size=1,
    )


class TestVMDeobDataReferences(TestCase):
    def test_string_constant_in_deobfuscated_vex_becomes_string_memory_data(self):
        project = angr.Project(BINARY, auto_load_libs=False)
        model = project.kb.cfgs.new_model("deobf_graph")
        rdi = project.arch.registers["rdi"][0]
        rip = project.arch.registers["rip"][0]
        irsb = _irsb(
            project,
            [
                pyvex.stmt.Put(pyvex.expr.Const(pyvex.const.U64(WELCOME)), rdi),
                # the block's own jump target: no bytes behind it, must not become memory data
                pyvex.stmt.Put(pyvex.expr.Const(pyvex.const.U64(SYNTHETIC_ADDR + 0x10000)), rip),
            ],
        )
        node = CFGENode(SYNTHETIC_ADDR, 1, model, irsb=irsb)

        added = collect_data_references(project, project.kb, model, [node])

        assert added == [WELCOME]
        md = model.memory_data[WELCOME]
        assert md.sort == MemoryDataSort.String
        assert md.content.startswith(b"Welcome to the admin console")
        assert SYNTHETIC_ADDR + 0x10000 not in model.memory_data
        xrefs = project.kb.xrefs.get_xrefs_by_dst(WELCOME)
        assert {x.block_addr for x in xrefs} == {SYNTHETIC_ADDR}

    def test_reader_recomputes_string_memory_data_and_hands_its_model_to_the_decompiler(self):
        project = angr.Project(BINARY, auto_load_libs=False)
        model = project.kb.cfgs.new_model("deobf_graph")
        rdi = project.arch.registers["rdi"][0]
        irsb = _irsb(project, [pyvex.stmt.Put(pyvex.expr.Const(pyvex.const.U64(WELCOME)), rdi)])
        node = CFGENode(SYNTHETIC_ADDR, 1, model, irsb=irsb, function_address=SYNTHETIC_ADDR)
        func = Function(project.kb.functions, SYNTHETIC_ADDR, "VM_1", None, is_simprocedure=False)
        project.kb.functions[func.addr] = func
        func.register_node(True, node)
        func.startpoint = node
        func.mark_ret_site(node)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "dump.json.gz")
            dump_decompilation_input(func, project, path, vm_deobfuscation=True)
            fresh = angr.Project(BINARY, auto_load_libs=False)
            loaded, kwargs = load_decompilation_input(fresh, path)

        assert loaded.addr == SYNTHETIC_ADDR
        cfg = kwargs["cfg"]
        assert cfg is fresh.kb.cfgs["deobf_graph"]
        md = cfg.memory_data[WELCOME]
        assert md.sort == MemoryDataSort.String
        assert md.content.startswith(b"Welcome to the admin console")


if __name__ == "__main__":
    main()
