from __future__ import annotations
from claripy import Annotation


class StackLocationAnnotation(Annotation):
    def __init__(self, offset):
        super().__init__()

        self.offset = offset

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return False

    def __hash__(self):
        return hash(("stack_location", self.offset))

    def __eq__(self, other):
        if not isinstance(other, StackLocationAnnotation):
            return False

        return self.offset == other.offset


class VariableSourceAnnotation(Annotation):
    def __init__(self, block_addr, stmt_idx, ins_addr):
        super().__init__()

        self.block_addr = block_addr
        self.stmt_idx = stmt_idx
        self.ins_addr = ins_addr

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return False

    def __hash__(self):
        return hash((self.block_addr, self.stmt_idx, self.ins_addr))

    def __eq__(self, other):
        if not isinstance(other, VariableSourceAnnotation):
            return False

        return (
            self.block_addr == other.block_addr and self.stmt_idx == other.stmt_idx and self.ins_addr == other.ins_addr
        )

    @staticmethod
    def from_state(state):
        return VariableSourceAnnotation(state.scratch.bbl_addr, state.scratch.stmt_idx, state.scratch.ins_addr)
