# pylint:disable=too-many-positional-arguments
from __future__ import annotations
import logging

from capstone.mips_const import (
    MIPS_REG_T7,
    MIPS_REG_T8,
    MIPS_REG_T9,
    MIPS_REG_RA,
    MIPS_REG_ZERO,
    MIPS_OP_REG,
    MIPS_OP_IMM,
)

import cle

from .resolver import IndirectJumpResolver

l = logging.getLogger(name=__name__)


class MipsElfGotResolver(IndirectJumpResolver):
    """
    A timeless indirect jump resolver that resolves GOT stub entries in MIPS ELF binaries.

    Reference: MIPS Assembly Language Programmer's Guide, Calling Position Independent Functions
    """

    def __init__(self, project):
        super().__init__(project, timeless=True)

        self._section_cache: dict[tuple[int, str], int] = {}
        self._simproc_cache: dict[str, int] | None = None

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        return jumpkind == "Ijk_Call" and addr == func_addr

    def resolve(  # pylint:disable=unused-argument
        self, cfg, addr, func_addr, block, jumpkind, func_graph_complete: bool = True, **kwargs
    ):
        # The stub must look like the following:
        #   585b80  lw      $t9, -0x7ff0($gp)
        #   585b84  move    $t7, $ra
        #   585b88  jalr    $t9
        #   585b8c  addiu   $t8, $zero, 0x84b

        obj = self.project.loader.find_object_containing(addr)
        if obj is None:
            return False, []
        if not isinstance(obj, cle.ELF):
            return False, []
        dynsym_addr = self._find_and_cache_section_addr(obj, ".dynsym")
        if dynsym_addr is None:
            return False, []

        dynstr_addr = self._find_and_cache_section_addr(obj, ".dynstr")
        if dynstr_addr is None:
            return False, []

        if block.size != 16:
            return False, []
        the_block = self.project.factory.block(block.addr, size=block.size)
        if len(the_block.capstone.insns) != 4:
            return False, []

        insn0 = the_block.capstone.insns[0]
        if not (
            insn0.insn.mnemonic == "lw"
            and insn0.insn.operands[0].type == MIPS_OP_REG
            and insn0.insn.operands[0].reg == MIPS_REG_T9
        ):
            return False, []

        insn1 = the_block.capstone.insns[1]
        if not (
            insn1.insn.mnemonic == "move"
            and insn1.insn.operands[0].type == MIPS_OP_REG
            and insn1.insn.operands[0].reg == MIPS_REG_T7
            and insn1.insn.operands[1].type == MIPS_OP_REG
            and insn1.insn.operands[1].reg == MIPS_REG_RA
        ):
            return False, []

        insn2 = the_block.capstone.insns[2]
        if not (
            insn2.insn.mnemonic == "jalr"
            and insn2.insn.operands[0].type == MIPS_OP_REG
            and insn2.insn.operands[0].reg == MIPS_REG_T9
        ):
            return False, []

        insn3 = the_block.capstone.insns[3]
        if not (
            insn3.insn.mnemonic == "addiu"
            and insn3.insn.operands[0].type == MIPS_OP_REG
            and insn3.insn.operands[0].reg == MIPS_REG_T8
            and insn3.insn.operands[1].type == MIPS_OP_REG
            and insn3.insn.operands[1].reg == MIPS_REG_ZERO
            and insn3.insn.operands[2].type == MIPS_OP_IMM
        ):
            return False, []

        dynsym_index = insn3.insn.operands[2].imm
        symbol_addr = dynsym_addr + dynsym_index * 16

        symbol_name_index = self.project.loader.memory.unpack_word(symbol_addr, size=4)
        symbol_name_addr = dynstr_addr + symbol_name_index
        symbol_name_bytes = self.project.loader.memory.load_null_terminated_bytes(symbol_name_addr, 512)

        try:
            symbol_name = symbol_name_bytes.strip(b"\x00").decode("ascii")
        except UnicodeDecodeError:
            return False, []

        symbol = obj.symbols_by_name.get(symbol_name, None)
        if symbol is None:
            return False, []

        if symbol.rebased_addr != func_addr:
            l.debug("Resolved target to %s @ %#x", symbol_name, symbol.rebased_addr)
            return True, [symbol.rebased_addr]

        # find out if there is a SimProcedure for this import symbol
        simproc_addr = self._cache_and_find_simproc_by_name(symbol_name)
        if simproc_addr is not None:
            l.debug("Resolved target to %s @ %#x", symbol_name, simproc_addr)
            return True, [simproc_addr]
        return False, []

    def _find_and_cache_section_addr(self, obj, section_name: str) -> int | None:
        cache_key = (obj.min_addr, section_name)
        if cache_key in self._section_cache:
            return self._section_cache[cache_key]

        for sec in obj.sections:
            if sec.name == section_name:
                # cache it
                self._section_cache[cache_key] = sec.vaddr
                return sec.vaddr
        return None

    def _cache_and_find_simproc_by_name(self, symbol_name: str) -> int | None:
        if self._simproc_cache is None:
            self._simproc_cache = {}
            for addr, simproc in self.project._sim_procedures.items():
                self._simproc_cache[simproc.display_name] = addr

        return self._simproc_cache.get(symbol_name)
