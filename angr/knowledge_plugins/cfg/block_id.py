from __future__ import annotations


class BlockID:
    """
    A context-sensitive key for a SimRun object.
    """

    def __init__(self, addr: int, callsite_tuples: tuple[int, ...] | None, jump_type: str):
        self.addr = addr
        self.callsite_tuples = callsite_tuples
        self.jump_type = jump_type

        self._hash = None

    def callsite_repr(self):
        if self.callsite_tuples is None:
            return "None"

        s = []

        def format_addr(addr):
            return "None" if addr is None else hex(addr)

        for i in range(0, len(self.callsite_tuples), 2):
            s.append("@".join(map(format_addr, self.callsite_tuples[i : i + 2])))
        return " -> ".join(s)

    def __repr__(self):
        return f"<BlockID {self.addr:#08x} ({self.callsite_repr()}) % {self.jump_type}>"

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.callsite_tuples, self.addr, self.jump_type))
        return self._hash

    def __eq__(self, other):
        return (
            isinstance(other, BlockID)
            and self.addr == other.addr
            and self.callsite_tuples == other.callsite_tuples
            and self.jump_type == other.jump_type
        )

    def __ne__(self, other):
        return not self == other

    @staticmethod
    def new(addr, callstack_suffix, jumpkind):
        if jumpkind.startswith("Ijk_Sys") or jumpkind == "syscall":
            jump_type = "syscall"
        elif jumpkind in ("Ijk_Exit", "exit"):
            jump_type = "exit"
        else:
            jump_type = "normal"
        return BlockID(addr, callstack_suffix, jump_type)

    @property
    def func_addr(self):
        if self.callsite_tuples:
            return self.callsite_tuples[-1]
        return None
