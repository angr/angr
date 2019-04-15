
from ...serializable import Serializable


class IndirectJump(Serializable):

    __slots__ = ("addr", "ins_addr", "func_addr", "jumpkind", "stmt_idx", "resolved_targets", "jumptable",
                 "jumptable_addr", "jumptable_entries", )

    def __init__(self, addr, ins_addr, func_addr, jumpkind, stmt_idx, resolved_targets=None, jumptable=False,
                 jumptable_addr=None, jumptable_entries=None):
        self.addr = addr
        self.ins_addr = ins_addr
        self.func_addr = func_addr
        self.jumpkind = jumpkind
        self.stmt_idx = stmt_idx
        self.resolved_targets = set() if resolved_targets is None else set(resolved_targets)
        self.jumptable = jumptable
        self.jumptable_addr = jumptable_addr
        self.jumptable_entries = jumptable_entries

    def __repr__(self):

        status = ""
        if self.jumptable:
            status = "jumptable"
            if self.jumptable_addr is not None:
                status += "@%#08x" % self.jumptable_addr
            if self.jumptable_entries is not None:
                status += " with %d entries" % len(self.jumptable_entries)

        return "<IndirectJump %#08x - ins %#08x%s>" % (self.addr, self.ins_addr, " " + status if status else "")
