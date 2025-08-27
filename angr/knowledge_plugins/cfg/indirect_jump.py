from __future__ import annotations

from angr.serializable import Serializable


class IndirectJumpType:
    """
    The type of an indirect jump or call.
    """

    Jumptable_AddressLoadedFromMemory = 0
    Jumptable_AddressComputed = 1
    Vtable = 3
    Unknown = 255


class JumptableInfo:
    """
    Describes a jump table or a vtable.
    """

    __slots__ = ("addr", "entries", "entry_size", "size")

    def __init__(self, addr: int | None, size: int, entry_size: int, entries: list[int]):
        self.addr = addr
        self.size = size
        self.entry_size = entry_size
        self.entries = entries


class IndirectJump(Serializable):
    """
    Describes an indirect jump or call site.
    """

    __slots__ = (
        "addr",
        "func_addr",
        "ins_addr",
        "jumpkind",
        "jumptable",
        "jumptables",
        "resolved_targets",
        "stmt_idx",
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
        self.jumptables: list[JumptableInfo] = []
        if (
            jumptable_addr is not None
            and jumptable_size is not None
            and jumptable_entry_size is not None
            and jumptable_entries is not None
        ):
            self.add_jumptable(jumptable_addr, jumptable_size, jumptable_entry_size, jumptable_entries)
        self.type = type_

    def add_jumptable(
        self,
        addr: int | None,
        size: int,
        entry_size: int,
        entries: list[int],
        is_primary: bool = False,
    ) -> None:
        ji = JumptableInfo(addr, size, entry_size, entries)
        if is_primary:
            self.jumptables.insert(0, ji)
        else:
            self.jumptables.append(ji)

    # for compatibility convenience

    @property
    def jumptable_addr(self) -> int | None:
        if self.jumptables:
            return self.jumptables[0].addr
        return None

    @property
    def jumptable_size(self) -> int | None:
        if self.jumptables:
            return self.jumptables[0].size
        return None

    @property
    def jumptable_entry_size(self) -> int | None:
        if self.jumptables:
            return self.jumptables[0].entry_size
        return None

    @property
    def jumptable_entries(self) -> list[int] | None:
        if self.jumptables:
            return self.jumptables[0].entries
        return None

    def __repr__(self):
        status = ""
        if self.jumptable or self.jumptable_entries:
            status = "vtable" if self.type == IndirectJumpType.Vtable else "jumptable"
            if self.jumptable_addr is not None:
                status += f"@{self.jumptable_addr:#08x}"
            if self.jumptable_entries is not None:
                status += f" with {len(self.jumptable_entries)} entries"
            if len(self.jumptables) > 1:
                status += f" (+{len(self.jumptables)-1} jumptables)"

        return "<IndirectJump {:#08x} - ins {:#08x}{}>".format(self.addr, self.ins_addr, " " + status if status else "")
