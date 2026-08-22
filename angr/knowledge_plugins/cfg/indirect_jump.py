from __future__ import annotations

from dataclasses import dataclass

from angr.protos import cfg_pb2
from angr.serializable import Serializable


class IndirectJumpType:
    """
    The type of an indirect jump or call.
    """

    Jumptable_AddressLoadedFromMemory = 0
    Jumptable_AddressComputed = 1
    Vtable = 3
    Unknown = 255


@dataclass(frozen=True)
class JumptableResolutionEvidence:
    """Machine-readable provenance for a resolved jump table."""

    resolver: str
    proof: str

    def __post_init__(self) -> None:
        if not isinstance(self.resolver, str) or not self.resolver:
            raise ValueError("jump-table resolver must be a non-empty string")
        if not isinstance(self.proof, str) or not self.proof:
            raise ValueError("jump-table proof must be a non-empty string")

    def serialize_to_cmessage(self):
        cmsg = cfg_pb2.JumptableResolutionEvidence()
        cmsg.resolver = self.resolver
        cmsg.proof = self.proof
        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg) -> JumptableResolutionEvidence:
        return cls(cmsg.resolver, cmsg.proof)


class JumptableInfo:
    """
    Describes a jump table or a vtable.
    """

    __slots__ = ("addr", "entries", "entries_guessed", "entry_size", "resolution_evidence", "size")

    def __init__(
        self,
        addr: int | None,
        size: int,
        entry_size: int,
        entries: list[int],
        *,
        entries_guessed: bool = False,
        resolution_evidence: JumptableResolutionEvidence | None = None,
    ):
        self.addr = addr
        self.size = size
        self.entry_size = entry_size
        self.entries = entries
        self.entries_guessed = entries_guessed
        self.resolution_evidence = resolution_evidence

    def serialize_to_cmessage(self):
        cmsg = cfg_pb2.JumptableInfo()
        if self.addr is not None:
            cmsg.addr = self.addr
        cmsg.size = self.size
        cmsg.entry_size = self.entry_size
        cmsg.entries.extend(self.entries)
        cmsg.entries_guessed = self.entries_guessed
        if self.resolution_evidence is not None:
            cmsg.resolution_evidence.CopyFrom(self.resolution_evidence.serialize_to_cmessage())
        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg) -> JumptableInfo:
        addr = cmsg.addr if cmsg.HasField("addr") else None
        resolution_evidence = (
            JumptableResolutionEvidence.parse_from_cmessage(cmsg.resolution_evidence)
            if cmsg.HasField("resolution_evidence")
            else None
        )
        return cls(
            addr,
            cmsg.size,
            cmsg.entry_size,
            list(cmsg.entries),
            entries_guessed=cmsg.entries_guessed,
            resolution_evidence=resolution_evidence,
        )


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
        jumptable_entries_guessed: bool = False,
        type_: int | None = IndirectJumpType.Unknown,
        jumptable_resolution_evidence: JumptableResolutionEvidence | None = None,
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
            self.add_jumptable(
                jumptable_addr,
                jumptable_size,
                jumptable_entry_size,
                jumptable_entries,
                entries_guessed=jumptable_entries_guessed,
                resolution_evidence=jumptable_resolution_evidence,
            )
        self.type = type_

    def add_jumptable(
        self,
        addr: int | None,
        size: int,
        entry_size: int,
        entries: list[int],
        is_primary: bool = False,
        *,
        entries_guessed: bool = False,
        resolution_evidence: JumptableResolutionEvidence | None = None,
    ) -> None:
        ji = JumptableInfo(
            addr,
            size,
            entry_size,
            entries,
            entries_guessed=entries_guessed,
            resolution_evidence=resolution_evidence,
        )
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

    @property
    def jumptable_entries_guessed(self) -> bool | None:
        if self.jumptables:
            return self.jumptables[0].entries_guessed
        return None

    @property
    def jumptable_resolution_evidence(self) -> JumptableResolutionEvidence | None:
        if self.jumptables:
            return self.jumptables[0].resolution_evidence
        return None

    @classmethod
    def _get_cmsg(cls):
        return cfg_pb2.IndirectJump()

    def serialize_to_cmessage(self):
        cmsg = self._get_cmsg()
        cmsg.addr = self.addr
        cmsg.ins_addr = self.ins_addr
        cmsg.func_addr = self.func_addr
        cmsg.jumpkind = self.jumpkind
        cmsg.stmt_idx = self.stmt_idx
        cmsg.resolved_targets.extend(self.resolved_targets)
        cmsg.jumptable = self.jumptable
        for jt in self.jumptables:
            cmsg.jumptables.append(jt.serialize_to_cmessage())
        cmsg.type = self.type if self.type is not None else IndirectJumpType.Unknown
        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs) -> IndirectJump:
        obj = cls(
            addr=cmsg.addr,
            ins_addr=cmsg.ins_addr,
            func_addr=cmsg.func_addr,
            jumpkind=cmsg.jumpkind,
            stmt_idx=cmsg.stmt_idx,
            resolved_targets=list(cmsg.resolved_targets),
            jumptable=cmsg.jumptable,
            type_=cmsg.type,
        )
        for jt_cmsg in cmsg.jumptables:
            ji = JumptableInfo.parse_from_cmessage(jt_cmsg)
            obj.jumptables.append(ji)
        return obj

    def __repr__(self):
        status = ""
        if self.jumptable or self.jumptable_entries:
            status = "vtable" if self.type == IndirectJumpType.Vtable else "jumptable"
            if self.jumptable_addr is not None:
                status += f"@{self.jumptable_addr:#08x}"
            if self.jumptable_entries is not None:
                status += f" with {len(self.jumptable_entries)} entries"
            if len(self.jumptables) > 1:
                status += f" (+{len(self.jumptables) - 1} jumptables)"

        return "<IndirectJump {:#08x} - ins {:#08x}{}{})>".format(
            self.addr,
            self.ins_addr,
            " " + status if status else "",
            " <guessed>" if self.jumptable_entries_guessed else "",
        )
