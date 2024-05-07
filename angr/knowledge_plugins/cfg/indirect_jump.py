from ...serializable import Serializable


class IndirectJumpType:
    Jumptable_AddressLoadedFromMemory = 0
    Jumptable_AddressComputed = 1
    Vtable = 3
    Unknown = 255


class IndirectJump(Serializable):
    __slots__ = (
        "addr",
        "ins_addr",
        "func_addr",
        "jumpkind",
        "stmt_idx",
        "resolved_targets",
        "jumptable",
        "jumptable_addr",
        "jumptable_size",
        "jumptable_entry_size",
        "jumptable_entries",
        "type",
    )

    def __init__(
        self,
        addr: int,
        ins_addr: int,
        func_addr: int,
        jumpkind: str,
        stmt_idx: int,
        resolved_targets: list[int] | None = None,
        jumptable: bool = False,
        jumptable_addr: int | None = None,
        jumptable_size: int | None = None,
        jumptable_entry_size: int | None = None,
        jumptable_entries: list[int] | None = None,
        type_: int | None = IndirectJumpType.Unknown,
    ):
        self.addr = addr
        self.ins_addr = ins_addr
        self.func_addr = func_addr
        self.jumpkind = jumpkind
        self.stmt_idx = stmt_idx
        self.resolved_targets = set() if resolved_targets is None else set(resolved_targets)
        self.jumptable = jumptable
        self.jumptable_addr = jumptable_addr
        self.jumptable_size = jumptable_size
        self.jumptable_entry_size = jumptable_entry_size
        self.jumptable_entries = jumptable_entries
        self.type = type_

    def __repr__(self):
        status = ""
        if self.jumptable or self.jumptable_entries:
            if self.type == IndirectJumpType.Vtable:
                status = "vtable"
            else:
                status = "jumptable"
            if self.jumptable_addr is not None:
                status += "@%#08x" % self.jumptable_addr
            if self.jumptable_entries is not None:
                status += " with %d entries" % len(self.jumptable_entries)

        return "<IndirectJump {:#08x} - ins {:#08x}{}>".format(self.addr, self.ins_addr, " " + status if status else "")
