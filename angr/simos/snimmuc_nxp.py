from __future__ import annotations
from typing import TYPE_CHECKING

from io import BytesIO

from cle.backends import Blob

from angr.knowledge_base import KnowledgeBase
from .simos import SimOS

if TYPE_CHECKING:
    from angr import Project


class SimSnimmucNxp(SimOS):
    """
    This class implements the "OS" for a bare-metal firmware used at an imaginary company.
    """

    def __init__(self, project: Project, name=None, **kwargs):  # pylint:disable=unused-argument
        super().__init__(project, name=name)

    def configure_project(self):
        # pattern match the entry point to figure out if we support parsing this binary
        entry_bytes = self.project.loader.memory.load(self.project.entry, 3 * 4)
        if entry_bytes != b"\x94!\xff\xf0" b"|\x08\x02\xa6" b"\x90\x01\x00\x14":
            return

        entry_block = self.project.factory.block(self.project.entry)
        try:
            first_sync = next(
                iter(
                    [
                        idx
                        for idx, insn in enumerate(entry_block.disassembly.insns)
                        if insn.mnemonic in {"sync", "isync"}
                    ]
                )
            )
        except StopIteration:
            return

        # run this block and acquire initial registers for each function
        state = self.project.factory.blank_state(addr=self.project.entry)
        # set garbage value to key registers
        key_registers = ["r13", "r2", "r14", "r15", "r16"]
        GARBAGE = 0xDEADBEEF
        for key_reg in key_registers:
            setattr(state.regs, "_" + key_reg, GARBAGE)
        simgr = self.project.factory.simgr(state)
        simgr.step(num_inst=first_sync)
        if simgr.active and len(simgr.active) == 1:
            stepped_state = simgr.one_active
        else:
            return

        reg_values = {}
        for key_reg in key_registers:
            reg_values[key_reg] = getattr(stepped_state.regs, "_" + key_reg).concrete_value
            if reg_values[key_reg] in {None, GARBAGE}:
                # umm the register is not initialized. unsupported?
                return

        # TODO: Make them part of the ABI
        self.function_initial_registers = reg_values

        # load SDATA, SDATA2, and a few other regions
        mappings = {}

        # this is just CRAZY...
        # TODO: Better resilience
        tmp_kb = KnowledgeBase(self.project)
        self.project.analyses.CFG(
            regions=[(self.project.entry, self.project.entry + 180)], data_references=False, kb=tmp_kb
        )
        # take the last function
        func = tmp_kb.functions[self.project.entry]
        second_to_last_block = sorted(func.blocks, key=lambda x: x.addr)[-2]
        if second_to_last_block.vex.jumpkind != "Ijk_Call":
            return
        init_func_addr = second_to_last_block.vex.next
        if not isinstance(init_func_addr, int):
            return

        # lift one block
        init_func_block = self.project.factory.block(init_func_addr)
        if init_func_block.vex.jumpkind != "Ijk_Call":
            return

        section_init_func_addr = init_func_block.vex.next
        if not isinstance(section_init_func_addr, int):
            return

        self.project.analyses.CFG(
            regions=[(section_init_func_addr, section_init_func_addr + 0x324)], data_references=False, kb=tmp_kb
        )
        section_init_func = tmp_kb.functions[section_init_func_addr]

        sorted_blocks = sorted(section_init_func.blocks, key=lambda x: x.addr)
        sdata_section_init_call = sorted_blocks[25]
        if sdata_section_init_call.vex.jumpkind != "Ijk_Call":
            return
        sdata_section_init_func = sdata_section_init_call.vex.next
        if not isinstance(sdata_section_init_func, int):
            return

        # more pattern matching
        state = self.project.factory.blank_state(addr=sdata_section_init_func)
        for key_reg in ["r28", "r29", "r30"]:
            setattr(state.regs, "_" + key_reg, GARBAGE)
        simgr = self.project.factory.simgr(state)
        simgr.step()
        if simgr.active and len(simgr.active) == 1:
            stepped_state = simgr.one_active
        else:
            return

        sdata_reg_values = {}
        for key_reg in ["r28", "r29", "r30"]:
            sdata_reg_values[key_reg] = getattr(stepped_state.regs, "_" + key_reg).concrete_value
            if sdata_reg_values[key_reg] in {None, GARBAGE}:
                # umm the register is not initialized. unsupported?
                return

        mappings[sdata_reg_values["r30"]] = (sdata_reg_values["r29"], sdata_reg_values["r28"] - sdata_reg_values["r29"])

        # TODO: Implement support for SDATA2 and other sections
        # mappings = {
        #     0x60005850: (0x30A734, 0x60008D30 - 0x60005850),
        #     0x60011DA0: (0x3165EC, 0x60014580 - 0x60011DA0),
        #     0x60014580: (0x32AC48, 0x60061638 - 0x60014580),
        # }

        for mem_base, (source_addr, size) in mappings.items():
            backing = BytesIO()
            backing.write(self.project.loader.memory.load(source_addr, size))
            backing.seek(0)

            blob = Blob(
                binary=None,
                binary_stream=backing,
                base_addr=mem_base,
                offset=0,
                arch=self.project.arch,
            )
            self.project.loader.dynamic_load(blob)

        # FIXME: Use ret_offset from the calling convention
        self.project.arch.ret_offset = self.project.arch.registers["r3"][0]
