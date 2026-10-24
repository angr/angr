from collections.abc import Sequence
from typing import Any

from .vexir import IrBlock

VEX_IRSB_MAX_SIZE: int
MAX_EXITS: int

def jumpkind_name(jk: int) -> str:
    """The pyvex enum string of an ``IRJumpKind`` int (``Ijk_INVALID`` for unknown values)."""

class Exit:
    """A conditional exit (``Ist_Exit``) of a lifted block."""

    stmt_idx: int
    ins_addr: int
    dst: int
    jumpkind: str

class DataRef:
    """A data reference collected by libpyvex; the attributes of ``pyvex.data_ref.DataRef``."""

    data_addr: int
    data_size: int
    data_type: int
    stmt_idx: int
    ins_addr: int
    data_type_str: str

class ConstVal:
    """A constant tmp value from lift-time constant propagation (``pyvex.const_val.ConstVal``)."""

    tmp: int
    stmt_idx: int
    value: int

class LiftSummary:
    """
    Statement-less summary of one lifted block, read straight from libpyvex's ``VEXLiftResult``: what CFGFast's
    main scan consumes from ``Block.vex_nostmt`` without a pyvex IRSB. ``next`` is the constant default-exit
    target or None; ``next_tmp`` is the tmp a non-constant default exit reads. The settable fields are the ones
    ``CFGFast._generate_cfgnode`` rewrites when it shrinks a block at a prologue-derived function start.
    """

    addr: int
    size: int
    jumpkind: str
    next: int | None
    next_tmp: int | None
    is_noop_block: bool
    instructions: int
    instruction_addresses: tuple[int, ...]
    exits: list[Exit]
    exit_statements: tuple[tuple[int, int, Exit], ...]
    default_exit_target: int | None
    data_refs: list[DataRef]
    const_vals: list[ConstVal]
    statements: None
    has_statements: bool

    def conditional_successors(self, branch_delay_slot: bool) -> list[tuple[int, int, int, str]]:
        """
        The conditional successors as ``CFGFast._scan_irsb`` enumerates them from a statement-less IRSB:
        (stmt_idx, branch instruction address, target, jumpkind), with delay-slot attribution and VEX-artifact
        exits (a non-final Boring exit back to its own instruction) dropped.
        """

class VexLifter:
    """
    Lifts blocks straight from the loader's backer buffers into ``LiftSummary`` objects by calling libpyvex's
    ``vex_lift`` with the policy of ``CFGFast._lift`` -> ``Block.vex_nostmt``.
    """

    def __init__(
        self,
        vex_arch: str,
        vex_archinfo: dict[str, Any],
        is_arm: bool,
        backers: Sequence[tuple[int, Any]],
        lock: Any,
    ) -> None:
        """
        :param vex_arch:        ``arch.vex_arch``.
        :param vex_archinfo:    ``arch.vex_archinfo``.
        :param is_arm:          Whether addresses carry a THUMB bit (``archinfo.ArchARM``).
        :param backers:         (start, buffer) pairs sorted by start, i.e. ``memory_ro_view._flattened_backers``.
        :param lock:            ``pyvex.lifting.libvex._libvex_lock``.
        """

    def lift(
        self,
        addr: int,
        max_size: int,
        initial_regs: list[tuple[int, int, int]] | None = None,
        const_prop: bool = False,
    ) -> tuple[LiftSummary, bytes | None] | None:
        """
        Lift and summarize the block at ``addr`` with at most ``max_size`` bytes. Returns None when the block must
        take the Python lifting path (``last_fallback`` says why). The bytes are the block's bytes when they lie
        within one backer.
        """

    def lift_jumpkind(self, addr: int) -> str | None:
        """
        The jumpkind of ``CFGBase._lift(addr).vex`` (the defaults of ``factory.block``), or None when the block must
        take the Python lifting path.
        """

    def lift_ir(
        self,
        addr: int,
        max_size: int,
        opt_level: int = 1,
        cross_insn_opt: bool = False,
        strict_block_end: bool = False,
        hooks: Any = None,
        stop_points: Any = None,
    ) -> IrBlock | None:
        """
        ``factory.block(addr, size=max_size, ...).vex`` as a statement-level ``IrBlock`` (the engine's block cache
        aside), or None when the block must take the Python lifting path. ``hooks`` and ``stop_points`` are tested
        with ``in`` for the stop-point cut.
        """

    @property
    def last_fallback(self) -> str | None: ...
    def load(self, addr: int, n: int) -> bytes | None:
        """``memory_ro_view.load(addr, n)`` when the range lies within one backer."""

    @property
    def backer_count(self) -> int: ...

def register_readonly_region(start: int, size: int, content: Any) -> bool:
    """libpyvex ``register_readonly_region``; ``content`` is kept alive until ``deregister_all_readonly_regions``."""

def deregister_all_readonly_regions() -> None: ...
def register_initial_register_value(offset: int, size: int, value: int) -> bool: ...
def reset_initial_register_values() -> bool: ...
