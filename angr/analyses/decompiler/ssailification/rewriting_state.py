from __future__ import annotations
from typing import Self

from ailment.statement import Statement, Assignment, Label
from ailment.expression import Phi, VirtualVariable
from ailment.block import Block

from angr.code_location import CodeLocation


class RewritingState:
    def __init__(
        self,
        loc: CodeLocation,
        arch,
        func,
        original_block: Block,
        registers: dict | None = None,
        phi_statements: list | None = None,
    ):
        self.loc = loc
        self.arch = arch
        self.func = func

        self.registers: dict = registers if registers is not None else {}
        self.original_block = original_block
        self.out_block = None
        self.phi_statements = phi_statements if phi_statements is not None else []

    def copy(self) -> RewritingState:
        state = RewritingState(
            self.loc,
            self.arch,
            self.func,
            self.original_block.original_size,
            registers=self.registers.copy(),
            phi_statements=self.phi_statements[::],
        )
        return state

    def merge(self, block: Block, udef_to_phiid: dict, phiid_to_loc: dict, *others: RewritingState) -> bool:
        merge_occurred = False

        merged_registers = {}

        all_regs: dict[int, int] = None
        diff_regoffsets: set[int] = set()
        for o in others:
            if all_regs is None:
                all_regs = o.registers.copy()
            else:
                for reg_offset, vvid in o.registers.items():
                    if reg_offset not in all_regs:
                        all_regs[reg_offset] = vvid
                    elif all_regs[reg_offset] != vvid:
                        diff_regoffsets.add(reg_offset)

        for o in others:
            for reg_offset, vvid in o.registers.items():
                if reg_offset not in diff_regoffsets:
                    merged_registers[reg_offset] = vvid
                    merge_occurred = True

        for reg_offset in sorted(diff_regoffsets):
            # replace it with phi variables
            assert ("reg", reg_offset) in udef_to_phiid

            phi_ids = udef_to_phiid[("reg", reg_offset)]
            phi_id = next(
                iter(id_ for id_ in phi_ids if phiid_to_loc[id_] == (self.loc.block_addr, self.loc.block_idx))
            )

            src_and_varids = []
            for o in others:
                if reg_offset in o.registers:
                    src_and_varids.append(((o.loc.block_addr, o.loc.block_idx), o.registers[reg_offset]))

            phi_var = Phi(
                None,
                64,  # FIXME: Can't assume 64-bit
                src_and_varids=src_and_varids,
            )
            phi_stmt = Assignment(
                None,
                VirtualVariable(None, phi_id, 64),
                phi_var,
                ins_addr=block.addr,
            )
            self.append_phi_statement(phi_stmt)
            merge_occurred = True

        return merge_occurred

    def append_statement(self, stmt: Statement):
        if self.out_block is None:
            self.out_block = Block(self.loc.block_addr, self.original_block.original_size, idx=self.loc.block_idx)
        self.out_block.statements.append(stmt)

    def append_phi_statement(self, stmt: Statement):
        self.phi_statements.append(stmt)

    def insert_phi_statements(self, cleanup: bool = True):
        if self.out_block is None or not self.phi_statements:
            return
        idx = 0
        while idx < len(self.out_block.statements):
            if not isinstance(self.out_block.statements[idx], Label):
                break
            idx += 1

        if idx >= len(self.out_block.statements):
            self.out_block.statements += self.phi_statements
        else:
            self.out_block.statements = (
                self.out_block.statements[:idx] + self.phi_statements + self.out_block.statements[idx:]
            )

        if cleanup:
            self.phi_statements = []
