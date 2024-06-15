# FIXME:
#     - Eliminate Vex references where possible
#     - Consider moving pieces of lifter classes to higher abstraction layer
#       to reduce duplication with Vex
#     - Fix default_exit_target
#     - Fix/remove NotImplementedError's

import logging
from typing import Optional
from collections.abc import Iterable, Sequence

import archinfo
from archinfo import ArchARM, ArchPcode
import cle
from cachetools import LRUCache

# FIXME: Reusing these errors from pyvex for compatibility. Eventually these
# should be refactored to use common error classes.
from pyvex.errors import PyVEXError, SkipStatementsError, LiftingException

from .behavior import BehaviorFactory
from ..engine import SimEngineBase
from ...state_plugins.inspect import BP_AFTER, BP_BEFORE
from ...sim_state import SimState
from ...misc.ux import once
from ...errors import SimEngineError, SimTranslationError, SimError
from ... import sim_options as o
from ...block import DisassemblerBlock, DisassemblerInsn


try:
    import pypcode
except ImportError:
    pypcode = None


l = logging.getLogger(__name__)

IRSB_MAX_SIZE = 400
IRSB_MAX_INST = 99
MAX_INSTRUCTIONS = 99999
MAX_BYTES = 5000


class ExitStatement:
    """
    This class exists to ease compatibility with CFGFast's processing of
    exit_statements. See _scan_irsb method.
    """

    __slots__ = ("dst", "jumpkind")

    dst: int | None
    jumpkind: str

    def __init__(self, dst: int | None, jumpkind: str):
        self.dst = dst
        self.jumpkind = jumpkind


class PcodeDisassemblerBlock(DisassemblerBlock):
    """
    Helper class to represent a block of disassembled target architecture
    instructions
    """


class PcodeDisassemblerInsn(DisassemblerInsn):
    """
    Helper class to represent a disassembled target architecture instruction
    """

    def __init__(self, pcode_insn):
        self.insn = pcode_insn

    @property
    def size(self) -> int:
        return self.insn.length

    @property
    def address(self) -> int:
        return self.insn.addr.offset

    @property
    def mnemonic(self) -> str:
        return self.insn.mnem

    @property
    def op_str(self) -> str:
        return self.insn.body


class IRSB:
    """
    IRSB stands for *Intermediate Representation Super-Block*. An IRSB in is a
    single-entry, multiple-exit code block.

    :ivar arch:             The architecture this block is lifted under
    :vartype arch:          :class:`archinfo.Arch`
    :ivar statements:       The statements in this block
    :vartype statements:    list of :class:`IRStmt`
    :ivar next:             The expression for the default exit target of this block
    :vartype next:          :class:`IRExpr`
    :ivar int offsIP:       The offset of the instruction pointer in the VEX guest state
    :ivar int stmts_used:   The number of statements in this IRSB
    :ivar str jumpkind:     The type of this block's default jump (call, boring, syscall, etc) as a VEX enum string
    :ivar bool direct_next: Whether this block ends with a direct (not indirect) jump or branch
    :ivar int size:         The size of this block in bytes
    :ivar int addr:         The address of this basic block, i.e. the address in the first IMark
    """

    __slots__ = (
        "_direct_next",
        "_exit_statements",
        "_instruction_addresses",
        "_ops",
        "_size",
        "_statements",
        "_disassembly",
        "addr",
        "arch",
        "behaviors",
        "data_refs",
        "default_exit_target",
        "jumpkind",
        "next",
    )

    _direct_next: bool | None
    _exit_statements: Sequence[tuple[int, int, ExitStatement]]
    _instruction_addresses: Sequence[int] | None
    _ops: Sequence["pypcode.PcodeOp"]  # FIXME: Merge into _statements
    _size: int | None
    _statements: Iterable  # Note: currently unused
    _disassembly: PcodeDisassemblerBlock | None
    addr: int
    arch: archinfo.Arch
    behaviors: BehaviorFactory | None
    data_refs: Sequence  # Note: currently unused
    default_exit_target: Optional  # Note: currently used
    jumpkind: str | None
    next: int | None

    # The following constants shall match the defs in pyvex.h
    MAX_EXITS = 400
    MAX_DATA_REFS = 2000

    def __init__(
        self,
        data: str | bytes | None,
        mem_addr: int,
        arch: archinfo.Arch,
        max_inst: int | None = None,
        max_bytes: int | None = None,
        bytes_offset: int = 0,
        traceflags: int = 0,
        opt_level: int = 1,
        num_inst: int | None = None,
        num_bytes: int | None = None,
        strict_block_end: bool = False,
        skip_stmts: bool = False,
        collect_data_refs: bool = False,
    ) -> None:
        """
        :param data:                The bytes to lift. Can be either a string of bytes or a cffi buffer object.
                                    You may also pass None to initialize an empty IRSB.
        :param int mem_addr:        The address to lift the data at.
        :param arch:                The architecture to lift the data as.
        :param max_inst:            The maximum number of instructions to lift. (See note below)
        :param max_bytes:           The maximum number of bytes to use.
        :param num_inst:            Replaces max_inst if max_inst is None. If set to None as well, no instruction limit
                                    is used.
        :param num_bytes:           Replaces max_bytes if max_bytes is None. If set to None as well, no  byte limit is
                                    used.
        :param bytes_offset:        The offset into `data` to start lifting at. Note that for ARM THUMB mode, both
                                    `mem_addr` and `bytes_offset` must be odd (typically `bytes_offset` is set to 1).
        :param traceflags:          Unused by P-Code lifter
        :param opt_level:           Unused by P-Code lifter
        :param strict_block_end:    Unused by P-Code lifter

        .. note:: Explicitly specifying the number of instructions to lift (`max_inst`) may not always work
                  exactly as expected. For example, on MIPS, it is meaningless to lift a branch or jump
                  instruction without its delay slot. VEX attempts to Do The Right Thing by possibly decoding
                  fewer instructions than requested. Specifically, this means that lifting a branch or jump
                  on MIPS as a single instruction (`max_inst=1`) will result in an empty IRSB, and subsequent
                  attempts to run this block will raise `SimIRSBError('Empty IRSB passed to SimIRSB.')`.

        .. note:: If no instruction and byte limit is used, the lifter will continue lifting the block until the block
                  ends properly or until it runs out of data to lift.
        """
        if max_inst is None:
            max_inst = num_inst
        if max_bytes is None:
            max_bytes = num_bytes

        self._direct_next = None
        self._exit_statements = []
        self._instruction_addresses = None
        self._ops = []
        self._size = None
        self._statements = []
        self.addr = mem_addr
        self.arch = arch
        self.behaviors = None
        self.data_refs = ()
        self.default_exit_target = None
        self.jumpkind = None
        self.next = None
        self._disassembly = None

        if data is not None:
            # This is the slower path (because we need to call _from_py() to copy the content in the returned IRSB to
            # the current IRSB instance. You should always call `lift()` directly. This method is kept for compatibility
            # concerns.
            irsb = lift(
                data,
                mem_addr,
                arch,
                max_bytes=max_bytes,
                max_inst=max_inst,
                bytes_offset=bytes_offset,
                opt_level=opt_level,
                traceflags=traceflags,
                strict_block_end=strict_block_end,
                skip_stmts=skip_stmts,
                collect_data_refs=collect_data_refs,
            )
            self._from_py(irsb)

    @staticmethod
    def empty_block(
        arch: archinfo.Arch,
        addr: int,
        statements: Sequence | None = None,
        nxt: int | None = None,
        tyenv=None,  # Unused, kept for compatibility
        jumpkind: str | None = None,
        direct_next: bool | None = None,
        size: int | None = None,
    ) -> "IRSB":
        block = IRSB(None, addr, arch)
        block._set_attributes(statements, nxt, tyenv, jumpkind, direct_next, size=size)
        return block

    @property
    def has_statements(self) -> bool:
        return self.statements is not None and self.statements

    @property
    def exit_statements(self) -> Sequence[tuple[int, int, ExitStatement]]:
        return self._exit_statements

    def copy(self) -> "IRSB":
        """
        Copy by creating an empty IRSB and then filling in the leftover
        attributes. Copy is made as deep as possible
        """
        new = IRSB.empty_block(
            arch=self.arch,
            addr=self.addr,
        )

        new._set_attributes(
            nxt=self.next,
            jumpkind=self.jumpkind,
            direct_next=self.direct_next,
            ops=self._ops[:],
        )

        return new

    def extend(self, extendwith: "IRSB") -> "IRSB":
        """
        Appends an irsb to the current irsb. The irsb that is appended is invalidated.
        The appended irsb's jumpkind and default exit are used.
        :param extendwith: The IRSB to append to this IRSB
        """
        self._set_attributes(
            nxt=extendwith.next,
            jumpkind=extendwith.jumpkind,
            direct_next=extendwith.direct_next,
            ops=self._ops + extendwith._ops,
        )

        self._disassembly = None
        return self

    def invalidate_direct_next(self) -> None:
        self._direct_next = None

    def pp(self) -> None:
        """
        Pretty-print the IRSB to stdout.
        """
        print(self._pp_str())

    def __repr__(self) -> str:
        return "IRSB <0x{:x} bytes, {} ins., {}> at 0x{:x}".format(
            self.size,
            self.instructions,
            self.arch,
            self.addr,
        )

    def __str__(self) -> str:
        return self._pp_str()

    #
    # simple properties useful for analysis
    #

    @property
    def tyenv(self):
        # FIXME: Here for compatibility. Remove.
        return None

    @property
    def stmts_used(self) -> int:
        if self.statements is None:
            return 0
        return len(self.statements)

    @property
    def offsIP(self) -> int:
        return self.arch.ip_offset

    @property
    def direct_next(self) -> bool:
        if self._direct_next is None:
            self._direct_next = self._is_defaultexit_direct_jump()
        return self._direct_next

    @property
    def expressions(self):
        """
        Return an iterator of all expressions contained in the IRSB.
        """
        raise NotImplementedError()

    # FIXME: Rename this to num_instructions or something + fix pyvex IRSB.
    @property
    def instructions(self) -> int:
        """
        The number of instructions in this block
        """
        return len(self.instruction_addresses)

    @property
    def instruction_addresses(self) -> Sequence[int]:
        """
        Addresses of instructions in this block.
        """
        if self._instruction_addresses is None:
            self._instruction_addresses = []
            for op in self._ops:
                if op.opcode == pypcode.OpCode.IMARK:
                    for vn in op.inputs:
                        self._instruction_addresses.append(vn.offset)
        return self._instruction_addresses

    @property
    def size(self) -> int:
        """
        The size of this block, in bytes
        """
        assert self._size is not None
        return self._size

    @property
    def operations(self):
        """
        A list of all operations done by the IRSB, as libVEX enum names
        """
        raise NotImplementedError()

    @property
    def all_constants(self):
        """
        Returns all constants in the block (including incrementing of the program counter) as
        :class:`pyvex.const.IRConst`.
        """
        raise NotImplementedError()

    @property
    def constants(self):
        """
        The constants (excluding updates of the program counter) in the IRSB as :class:`pyvex.const.IRConst`.
        """
        raise NotImplementedError()

    @property
    def constant_jump_targets(self):
        """
        A set of the static jump targets of the basic block.
        """
        exits = set()

        if self.exit_statements:
            for _, _, stmt in self.exit_statements:
                if stmt.dst is not None:
                    exits.add(stmt.dst)

        if self.next is not None:
            exits.add(self.next)

        return exits

    @property
    def constant_jump_targets_and_jumpkinds(self):
        """
        A dict of the static jump targets of the basic block to their jumpkind.
        """
        exits = {}

        if self.exit_statements:
            for _, _, stmt in self.exit_statements:
                if stmt.dst is not None:
                    exits[stmt.dst] = stmt.jumpkind

        if self.next is not None:
            exits[self.next] = self.jumpkind

        return exits

    #
    # private methods
    #

    def _pp_str(self) -> str:
        """
        Return the pretty-printed IRSB.
        """
        sa = []
        sa.append("IRSB {")
        for i, op in enumerate(self._ops):
            if op.opcode == pypcode.OpCode.IMARK:
                for vn in op.inputs[:]:
                    sa.append(f"   {i:02d} | ------ {vn.offset:08x}, {vn.size} ------")
            else:
                sa.append(f"   {i:02d} | {pypcode.PcodePrettyPrinter.fmt_op(op)}")

        if isinstance(self.next, int):
            next_str = "%x" % self.next
        else:
            next_str = str(self.next)
        sa.append(f"   NEXT: {next_str}; {self.jumpkind}")
        sa.append("}")
        return "\n".join(sa)

    def _is_defaultexit_direct_jump(self) -> bool:
        """
        Checks if the default of this IRSB a direct jump or not.
        """
        if self.jumpkind not in ("Ijk_InvalICache", "Ijk_Boring", "Ijk_Call"):
            return False
        return self.default_exit_target is not None

    def _set_attributes(
        self: "IRSB",
        statements: Iterable = None,
        nxt: int | None = None,
        tyenv=None,  # Unused, kept for compatibility
        jumpkind: str | None = None,
        direct_next: bool | None = None,
        size: int | None = None,
        ops: Sequence["pypcode.PcodeOp"] | None = None,
        instruction_addresses: Iterable[int] | None = None,
        exit_statements: Sequence[tuple[int, int, ExitStatement]] = None,
        default_exit_target: Optional = None,
    ) -> None:
        # pylint: disable=unused-argument
        self._statements = statements if statements is not None else []
        self.next = nxt
        self.jumpkind = jumpkind
        self._direct_next = direct_next
        self._size = size
        self._ops = ops or []
        self._instruction_addresses = instruction_addresses
        self._exit_statements = exit_statements or []
        self.default_exit_target = default_exit_target

    def _from_py(self, irsb: "IRSB") -> None:
        self._set_attributes(
            irsb.statements,
            irsb.next,
            None,
            irsb.jumpkind,
            irsb.direct_next,
            irsb.size,
            ops=irsb._ops,
            instruction_addresses=irsb._instruction_addresses,
            exit_statements=irsb.exit_statements,
            default_exit_target=irsb.default_exit_target,
        )

    @property
    def statements(self) -> Iterable:
        # FIXME: For compatibility, may want to implement Ist_IMark and
        # pyvex.IRStmt.Exit to ease analyses.
        l.debug("Returning empty statements list!")
        return []
        # return self._statements

    @property
    def disassembly(self) -> PcodeDisassemblerBlock:
        return self._disassembly


class Lifter:
    """
    A lifter is a class of methods for processing a block.

    :ivar data:             The bytes to lift as either a python string of bytes or a cffi buffer object.
    :ivar bytes_offset:     The offset into `data` to start lifting at.
    :ivar max_bytes:        The maximum number of bytes to lift. If set to None, no byte limit is used.
    :ivar max_inst:         The maximum number of instructions to lift. If set to None, no instruction limit is used.
    :ivar opt_level:        Unused by P-Code lifter
    :ivar traceflags:       Unused by P-Code lifter
    :ivar allow_arch_optimizations: Unused by P-Code lifter
    :ivar strict_block_end: Unused by P-Code lifter
    :ivar skip_stmts:       Unused by P-Code lifter
    """

    REQUIRE_DATA_C = False
    REQUIRE_DATA_PY = False

    __slots__ = (
        "data",
        "bytes_offset",
        "opt_level",
        "traceflags",
        "allow_arch_optimizations",
        "strict_block_end",
        "collect_data_refs",
        "max_inst",
        "max_bytes",
        "skip_stmts",
        "irsb",
        "arch",
        "addr",
    )

    data: str | bytes | None
    bytes_offset: int | None
    opt_level: int
    traceflags: int | None
    allow_arch_optimizations: bool | None
    strict_block_end: bool | None
    collect_data_refs: bool
    max_inst: int | None
    max_bytes: int | None
    skip_stmts: bool
    irsb: IRSB
    arch: archinfo.Arch
    addr: int

    def __init__(self, arch: archinfo.Arch, addr: int):
        self.arch = arch
        self.addr = addr
        self.data = None
        self.bytes_offset = None
        self.opt_level = 1
        self.traceflags = None
        self.allow_arch_optimizations = None
        self.strict_block_end = None
        self.collect_data_refs = False
        self.max_inst = None
        self.max_bytes = None
        self.skip_stmts = False
        self.irsb = None

    def _lift(
        self,
        data: str | bytes | None,
        bytes_offset: int | None = None,
        max_bytes: int | None = None,
        max_inst: int | None = None,
        opt_level: int = 1,
        traceflags: int | None = None,
        allow_arch_optimizations: bool | None = None,
        strict_block_end: bool | None = None,
        skip_stmts: bool = False,
        collect_data_refs: bool = False,
    ) -> IRSB:
        """
        Wrapper around the `lift` method on Lifters. Should not be overridden in child classes.

        :param data:                The bytes to lift as either a python string of bytes or a cffi buffer object.
        :param bytes_offset:        The offset into `data` to start lifting at.
        :param max_bytes:           The maximum number of bytes to lift. If set to None, no byte limit is used.
        :param max_inst:            The maximum number of instructions to lift. If set to None, no instruction limit is
                                    used.
        :param opt_level:           Unused by P-Code lifter
        :param traceflags:          Unused by P-Code lifter
        :param allow_arch_optimizations: Unused by P-Code lifter
        :param strict_block_end:    Unused by P-Code lifter
        :param skip_stmts:          Unused by P-Code lifter
        :param collect_data_refs:   Unused by P-Code lifter
        """
        irsb = IRSB.empty_block(self.arch, self.addr)
        self.data = data
        self.bytes_offset = bytes_offset
        self.opt_level = opt_level
        self.traceflags = traceflags
        self.allow_arch_optimizations = allow_arch_optimizations
        self.strict_block_end = strict_block_end
        self.collect_data_refs = collect_data_refs
        self.max_inst = max_inst
        self.max_bytes = max_bytes
        self.skip_stmts = skip_stmts
        self.irsb = irsb
        self.lift()
        return self.irsb

    def lift(self) -> None:
        """
        Lifts the data using the information passed into _lift. Should be overridden in child classes.

        Should set the lifted IRSB to self.irsb.
        If a lifter raises a LiftingException on the data, this signals that the lifter cannot lift this data and arch
        and the lifter is skipped.
        If a lifter can lift any amount of data, it should lift it and return the lifted block with a jumpkind of
        Ijk_NoDecode, signalling to pyvex that other lifters should be used on the undecodable data.

        """
        raise NotImplementedError()


# pylint:disable=unused-argument
def lift(
    data: str | bytes | None,
    addr: int,
    arch: archinfo.Arch,
    max_bytes: int | None = None,
    max_inst: int | None = None,
    bytes_offset: int = 0,
    opt_level: int = 1,
    traceflags: int = 0,
    strict_block_end: bool = True,
    inner: bool = False,
    skip_stmts: bool = False,
    collect_data_refs: bool = False,
) -> IRSB:
    """
    Lift machine code in `data` to a P-code IRSB.

    If a lifter raises a LiftingException on the data, it is skipped.
    If it succeeds and returns a block with a jumpkind of Ijk_NoDecode, all of the lifters are tried on the rest
    of the data and if they work, their output is appended to the first block.

    :param arch:            The arch to lift the data as.
    :param addr:            The starting address of the block. Effects the IMarks.
    :param data:            The bytes to lift as either a python string of bytes or a cffi buffer object.
    :param max_bytes:       The maximum number of bytes to lift. If set to None, no byte limit is used.
    :param max_inst:        The maximum number of instructions to lift. If set to None, no instruction limit is used.
    :param bytes_offset:    The offset into `data` to start lifting at.
    :param opt_level:       Unused by P-Code lifter
    :param traceflags:      Unused by P-Code lifter

    .. note:: Explicitly specifying the number of instructions to lift (`max_inst`) may not always work
              exactly as expected. For example, on MIPS, it is meaningless to lift a branch or jump
              instruction without its delay slot. VEX attempts to Do The Right Thing by possibly decoding
              fewer instructions than requested. Specifically, this means that lifting a branch or jump
              on MIPS as a single instruction (`max_inst=1`) will result in an empty IRSB, and subsequent
              attempts to run this block will raise `SimIRSBError('Empty IRSB passed to SimIRSB.')`.

    .. note:: If no instruction and byte limit is used, the lifter will continue lifting the block until the block
              ends properly or until it runs out of data to lift.
    """
    if max_bytes is not None and max_bytes <= 0:
        raise PyVEXError("Cannot lift block with no data (max_bytes <= 0)")

    if not data:
        raise PyVEXError("Cannot lift block with no data (data is empty)")

    if isinstance(data, str):
        raise TypeError("Cannot pass unicode string as data to lifter")

    if isinstance(data, bytes):
        # py_data = data
        # c_data = None
        allow_arch_optimizations = False
    else:
        if max_bytes is None:
            raise PyVEXError("Cannot lift block with ffi pointer and no size (max_bytes is None)")
        # c_data = data
        # py_data = None
        allow_arch_optimizations = True

    # In order to attempt to preserve the property that
    # VEX lifts the same bytes to the same IR at all times when optimizations are disabled
    # we hack off all of VEX's non-IROpt optimizations when opt_level == -1.
    # This is intended to enable comparisons of the lifted IR between code that happens to be
    # found in different contexts.
    if opt_level < 0:
        allow_arch_optimizations = False
        opt_level = 0

    u_data = data
    try:
        final_irsb = PcodeLifter(arch, addr)._lift(
            u_data,
            bytes_offset,
            max_bytes,
            max_inst,
            opt_level,
            traceflags,
            allow_arch_optimizations,
            strict_block_end,
            skip_stmts,
            collect_data_refs,
        )
    except SkipStatementsError:
        assert skip_stmts is True
        final_irsb = PcodeLifter(arch, addr)._lift(
            u_data,
            bytes_offset,
            max_bytes,
            max_inst,
            opt_level,
            traceflags,
            allow_arch_optimizations,
            strict_block_end,
            skip_stmts=False,
            collect_data_refs=collect_data_refs,
        )
    except LiftingException as ex:
        l.debug("Lifting Exception: %s", ex)
        final_irsb = IRSB.empty_block(
            arch,
            addr,
            size=0,
            nxt=addr,
            jumpkind="Ijk_NoDecode",
        )
        final_irsb.invalidate_direct_next()
        return final_irsb

    if final_irsb.size > 0 and final_irsb.jumpkind == "Ijk_NoDecode":
        # We have decoded a few bytes before we hit an undecodeable instruction.

        # Determine if this is an intentional NoDecode, like the ud2 instruction on AMD64
        # FIXME:
        # nodecode_addr_expr = final_irsb.next
        # if type(nodecode_addr_expr) is Const:
        #     nodecode_addr = nodecode_addr_expr.con.value
        #     next_irsb_start_addr = addr + final_irsb.size
        #     if nodecode_addr != next_irsb_start_addr:
        #         # The last instruction of the IRSB has a non-zero length. This is an intentional NoDecode.
        #         # The very last instruction has been decoded
        #         final_irsb.jumpkind = "Ijk_NoDecode"
        #         final_irsb.next = final_irsb.next
        #         final_irsb.invalidate_direct_next()
        #         return final_irsb

        # Decode more bytes
        if skip_stmts:
            # When gymrat will be invoked, we will merge future basic blocks to the current basic block. In this case,
            # statements are usually required.
            # TODO: In the future, we may further optimize it to handle cases where getting statements in gymrat is not
            # TODO: required.
            return lift(
                data,
                addr,
                arch,
                max_bytes=max_bytes,
                max_inst=max_inst,
                bytes_offset=bytes_offset,
                opt_level=opt_level,
                traceflags=traceflags,
                strict_block_end=strict_block_end,
                skip_stmts=False,
                collect_data_refs=collect_data_refs,
            )

        next_addr = addr + final_irsb.size
        if max_bytes is not None:
            max_bytes -= final_irsb.size
        if isinstance(data, (str, bytes, bytearray)):
            data_left = data[final_irsb.size :]
        else:
            data_left = data + final_irsb.size
        if max_inst is not None:
            max_inst -= final_irsb.instructions
        if (max_bytes is None or max_bytes > 0) and (max_inst is None or max_inst > 0) and data_left:
            more_irsb = lift(
                data_left,
                next_addr,
                arch,
                max_bytes=max_bytes,
                max_inst=max_inst,
                bytes_offset=bytes_offset,
                opt_level=opt_level,
                traceflags=traceflags,
                strict_block_end=strict_block_end,
                inner=True,
                skip_stmts=False,
                collect_data_refs=collect_data_refs,
            )
            if more_irsb.size:
                # Successfully decoded more bytes
                final_irsb.extend(more_irsb)
        elif max_bytes == 0:
            # We have no more bytes left. Mark the jumpkind of the IRSB as Ijk_Boring
            if final_irsb.size > 0 and final_irsb.jumpkind == "Ijk_NoDecode":
                final_irsb.jumpkind = "Ijk_Boring"
                final_irsb.next = final_irsb.addr + final_irsb.size

    return final_irsb


class PcodeBasicBlockLifter:
    """
    Lifts basic blocks to P-code
    """

    context: "pypcode.Context"
    behaviors: BehaviorFactory

    def __init__(self, arch: archinfo.Arch):
        if isinstance(arch, ArchPcode):
            langid = arch.name
        else:
            archinfo_to_lang_map = {
                "X86": "x86:LE:32:default",
                "AMD64": "x86:LE:64:default",
                "AVR8": "avr8:LE:16:atmega256",
            }
            if arch.name not in archinfo_to_lang_map:
                l.error("Unknown mapping of %s to pcode languge id", arch.name)
                raise NotImplementedError()
            langid = archinfo_to_lang_map[arch.name]

        self.context = pypcode.Context(langid)
        self.behaviors = BehaviorFactory()

    def lift(
        self,
        irsb: IRSB,
        baseaddr: int,
        data: bytes | bytearray,
        bytes_offset: int = 0,
        max_bytes: int | None = None,
        max_inst: int | None = None,
        branch_delay_slot: bool = False,
        is_sparc32: bool = False,
    ) -> None:
        assert irsb.addr == baseaddr
        assert bytes_offset < len(data)

        if max_bytes is None or max_bytes > MAX_BYTES:
            max_bytes = min(len(data) - bytes_offset, MAX_BYTES)
        if max_inst is None or max_inst > MAX_INSTRUCTIONS:
            max_inst = MAX_INSTRUCTIONS

        irsb.behaviors = self.behaviors  # FIXME

        # Translate
        sliced_data = bytes(data[bytes_offset : bytes_offset + max_bytes])

        if is_sparc32:
            # workaround to handle SPARC V8 decoding before having a SPARC V8 Sleigh file
            # replace all  jmpl xxx; rett xxx sequences with rett xxx; nop;
            nop_seq = b"\x01\x00\x00\x00"
            jmpl_seqs = [
                b"\x81\xc4\x40\x00",
                b"\x81\xc4\x80\x00",
            ]
            rett_seqs = [b"\x81\xcc\x80\x00", b"\x81\xcc\xa0\x04"]
            for jmpl_seq in jmpl_seqs:
                for rett_seq in rett_seqs:
                    seq = jmpl_seq + rett_seq
                    index = sliced_data.find(seq)
                    while index >= 0:
                        sliced_data = sliced_data[:index] + rett_seq + nop_seq + sliced_data[index + 8 :]
                        index = sliced_data.find(seq)

        sliced_data = bytes(sliced_data)

        # Post-process block to mark exits and next block
        next_block = None
        irsb._instruction_addresses = []
        fallthru_addr = irsb.addr

        try:
            translation = self.context.translate(
                sliced_data,
                irsb.addr,
                max_instructions=max_inst,
                max_bytes=max_bytes,
                flags=pypcode.TranslateFlags.BB_TERMINATING,
            )
            irsb._ops = translation.ops

            last_decode_addr = irsb.addr
            last_imark_idx = 0
            for op_idx, op in enumerate(irsb._ops):
                if op.opcode == pypcode.OpCode.IMARK:
                    irsb._instruction_addresses.extend([vn.offset for vn in op.inputs])
                    last_decode_addr = op.inputs[0].offset
                    fallthru_addr = op.inputs[-1].offset + op.inputs[-1].size
                    last_imark_idx = op_idx
                    continue

                if op.opcode in {pypcode.OpCode.BRANCH, pypcode.OpCode.CBRANCH} and op.inputs[0].space.name == "const":
                    # P-code relative branch (op_idx + op.inputs[0].offset)
                    # Note: We only model these in execution
                    continue

                if op.opcode == pypcode.OpCode.CBRANCH:
                    irsb._exit_statements.append(
                        (last_decode_addr, op_idx - last_imark_idx, ExitStatement(op.inputs[0].offset, "Ijk_Boring"))
                    )
                elif op.opcode == pypcode.OpCode.BRANCH:
                    if next_block is None:
                        next_block = (op.inputs[0].offset, "Ijk_Boring")
                elif op.opcode == pypcode.OpCode.BRANCHIND:
                    if next_block is None:
                        next_block = (None, "Ijk_Boring")
                elif op.opcode == pypcode.OpCode.CALL:
                    if next_block is None:
                        next_block = (op.inputs[0].offset, "Ijk_Call")
                elif op.opcode == pypcode.OpCode.CALLIND:
                    if next_block is None:
                        next_block = (None, "Ijk_Call")
                elif op.opcode == pypcode.OpCode.RETURN:
                    if next_block is None:
                        next_block = (None, "Ijk_Ret")

            # FIXME: Do this lazily
            disasm = self.context.disassemble(
                sliced_data,
                irsb.addr,
                max_instructions=max_inst,
                max_bytes=fallthru_addr - irsb.addr,
            )
            irsb._disassembly = PcodeDisassemblerBlock(
                addr=irsb.addr,
                insns=[PcodeDisassemblerInsn(ins) for ins in disasm.instructions],
                thumb=False,
                arch=irsb.arch,
            )

        except (pypcode.BadDataError, pypcode.UnimplError):
            next_block = (fallthru_addr, "Ijk_NoDecode")
        except (pypcode.LowlevelError, IndexError):
            # FIXME:
            # - IndexError: Give more data
            # - pypcode.LowlevelError: Sometimes a decoding failure
            next_block = (irsb.addr, "Ijk_NoDecode")

        if next_block is None:
            next_block = (fallthru_addr, "Ijk_Boring")

        irsb._size = fallthru_addr - irsb.addr
        irsb.next, irsb.jumpkind = next_block


class PcodeLifter(Lifter):
    """
    Handles calling into pypcode to lift a block
    """

    _lifter_cache = {}

    def lift(self) -> None:
        if self.arch not in PcodeLifter._lifter_cache:
            PcodeLifter._lifter_cache[self.arch] = PcodeBasicBlockLifter(self.arch)
        lifter = PcodeLifter._lifter_cache[self.arch]
        lifter.lift(
            self.irsb,
            self.addr,
            self.data,
            bytes_offset=self.bytes_offset,
            max_inst=self.max_inst,
            max_bytes=self.max_bytes,
            branch_delay_slot=self.arch.branch_delay_slot,
            is_sparc32="sparc:" in self.arch.name and self.arch.bits == 32,
        )

        if self.irsb.size == 0:
            l.debug("raising lifting exception")
            raise LiftingException("pypcode: could not decode any instructions @ 0x%x" % self.addr)


class PcodeLifterEngineMixin(SimEngineBase):
    """
    Lifter mixin to lift from machine code to P-Code.
    """

    def __init__(
        self,
        project=None,
        use_cache: bool | None = None,
        cache_size: int = 50000,
        default_opt_level: int = 1,
        selfmodifying_code: bool | None = None,
        single_step: bool = False,
        default_strict_block_end: bool = False,
        **kwargs,
    ):
        super().__init__(project, **kwargs)

        self._use_cache = use_cache
        self._default_opt_level = default_opt_level
        self._cache_size = cache_size
        self.selfmodifying_code = selfmodifying_code
        self._single_step = single_step
        self.default_strict_block_end = default_strict_block_end

        if self._use_cache is None:
            if self.project is not None:
                self._use_cache = self.project._translation_cache
            else:
                self._use_cache = False
        if self.selfmodifying_code is None:
            if self.project is not None:
                self.selfmodifying_code = self.project.selfmodifying_code
            else:
                self.selfmodifying_code = False

        # block cache
        self._block_cache = None
        self._block_cache_hits = 0
        self._block_cache_misses = 0
        self._initialize_block_cache()

    def _initialize_block_cache(self) -> None:
        self._block_cache = LRUCache(maxsize=self._cache_size)
        self._block_cache_hits = 0
        self._block_cache_misses = 0

    def clear_cache(self) -> None:
        self._block_cache = LRUCache(maxsize=self._cache_size)
        self._block_cache_hits = 0
        self._block_cache_misses = 0

    # FIXME: Consider moving to higher abstraction layer to reduce duplication with vex
    def lift_vex(
        self,
        addr: int | None = None,
        state: SimState | None = None,
        clemory: cle.Clemory | None = None,
        insn_bytes: bytes | None = None,
        arch: archinfo.Arch | None = None,
        size: int | None = None,
        num_inst: int | None = None,
        traceflags: int = 0,
        thumb: bool = False,
        extra_stop_points: Iterable[int] | None = None,
        opt_level: int | None = None,
        strict_block_end: bool | None = None,
        skip_stmts: bool = False,
        collect_data_refs: bool = False,
        load_from_ro_regions: bool = False,
        cross_insn_opt: bool | None = None,
    ):
        """
        Temporary compatibility interface for integration with block code.
        """
        return self.lift_pcode(
            addr,
            state,
            clemory,
            insn_bytes,
            arch,
            size,
            num_inst,
            traceflags,
            thumb,
            extra_stop_points,
            opt_level,
            strict_block_end,
            skip_stmts,
            collect_data_refs,
            load_from_ro_regions,
            cross_insn_opt,
        )

    def lift_pcode(
        self,
        addr: int | None = None,
        state: SimState | None = None,
        clemory: cle.Clemory | None = None,
        insn_bytes: bytes | None = None,
        arch: archinfo.Arch | None = None,
        size: int | None = None,
        num_inst: int | None = None,
        traceflags: int = 0,
        thumb: bool = False,
        extra_stop_points: Iterable[int] | None = None,
        opt_level: int | None = None,
        strict_block_end: bool | None = None,
        skip_stmts: bool = False,
        collect_data_refs: bool = False,
        load_from_ro_regions: bool = False,
        cross_insn_opt: bool | None = None,
    ):
        """
        Lift an IRSB.

        There are many possible valid sets of parameters. You at the very least must pass some
        source of data, some source of an architecture, and some source of an address.

        Sources of data in order of priority: insn_bytes, clemory, state

        Sources of an address, in order of priority: addr, state

        Sources of an architecture, in order of priority: arch, clemory, state

        :param state:           A state to use as a data source.
        :param clemory:         A cle.memory.Clemory object to use as a data source.
        :param addr:            The address at which to start the block.
        :param thumb:           Whether the block should be lifted in ARM's THUMB mode.
        :param opt_level:       Unused for P-Code lifter
        :param insn_bytes:      A string of bytes to use as a data source.
        :param size:            The maximum size of the block, in bytes.
        :param num_inst:        The maximum number of instructions.
        :param traceflags:      Unused by P-Code lifter
        :param strict_block_end: Unused by P-Code lifter
        :param load_from_ro_regions: Unused by P-Code lifter
        """
        if cross_insn_opt:
            l.debug("cross_insn_opt is ignored for p-code lifter")
        if load_from_ro_regions:
            l.debug("load_from_ro_regions is ignored for p-code lifter")

        # phase 0: sanity check
        if not state and not clemory and not insn_bytes:
            raise ValueError("Must provide state or clemory or insn_bytes!")
        if not state and not clemory and not arch:
            raise ValueError("Must provide state or clemory or arch!")
        if addr is None and not state:
            raise ValueError("Must provide state or addr!")
        if arch is None:
            arch = clemory._arch if clemory else state.arch
        if arch.name.startswith("MIPS") and self._single_step:
            l.error("Cannot specify single-stepping on MIPS.")
            self._single_step = False

        # phase 1: parameter defaults
        if addr is None:
            addr = state.solver.eval(state._ip)
        if size is not None:
            size = min(size, IRSB_MAX_SIZE)
        if size is None:
            size = IRSB_MAX_SIZE
        if num_inst is not None:
            num_inst = min(num_inst, IRSB_MAX_INST)
        if num_inst is None and self._single_step:
            num_inst = 1
        if opt_level is None:
            if state and o.OPTIMIZE_IR in state.options:
                opt_level = 1
            else:
                opt_level = self._default_opt_level
        if strict_block_end is None:
            strict_block_end = self.default_strict_block_end
        if self.selfmodifying_code:
            if opt_level > 0:
                if once("vex-engine-smc-opt-warning"):
                    l.warning(
                        "Self-modifying code is not always correctly optimized by"
                        " PyVEX. To guarantee correctness, VEX optimizations have been"
                        " disabled."
                    )
                opt_level = 0
                if state and o.OPTIMIZE_IR in state.options:
                    state.options.remove(o.OPTIMIZE_IR)
        if skip_stmts is not True:
            skip_stmts = False

        have_patches = self.project and self.project.kb.patches.items()
        use_cache = self._use_cache and not (skip_stmts or collect_data_refs or have_patches or state)

        # phase 2: thumb normalization
        thumb = int(thumb)
        if isinstance(arch, ArchARM):
            if addr % 2 == 1:
                thumb = 1
            if thumb:
                addr &= ~1
        elif thumb:
            l.error("thumb=True passed on non-arm architecture!")
            thumb = 0

        # phase 3: check cache
        cache_key = None
        if use_cache:
            cache_key = (
                addr,
                insn_bytes,
                size,
                num_inst,
                thumb,
                opt_level,
                strict_block_end,
            )
            if cache_key in self._block_cache:
                self._block_cache_hits += 1
                irsb = self._block_cache[cache_key]
                stop_point = self._first_stoppoint(irsb, extra_stop_points)
                if stop_point is None:
                    return irsb
                else:
                    size = stop_point - addr
                    # check the cache again
                    cache_key = (
                        addr,
                        insn_bytes,
                        size,
                        num_inst,
                        thumb,
                        opt_level,
                        strict_block_end,
                    )
                    if cache_key in self._block_cache:
                        self._block_cache_hits += 1
                        return self._block_cache[cache_key]
                    else:
                        self._block_cache_misses += 1
            else:
                # a special case: `size` is used as the maximum allowed size
                tmp_cache_key = (
                    addr,
                    insn_bytes,
                    IRSB_MAX_SIZE,
                    num_inst,
                    thumb,
                    opt_level,
                    strict_block_end,
                )
                try:
                    irsb = self._block_cache[tmp_cache_key]
                    if irsb.size <= size:
                        self._block_cache_hits += 1
                        return self._block_cache[tmp_cache_key]
                except KeyError:
                    self._block_cache_misses += 1

        # vex_lift breakpoints only triggered when the cache isn't used
        if state:
            state._inspect("vex_lift", BP_BEFORE, mem_read_address=addr, mem_read_length=size)

        # phase 4: get bytes
        if insn_bytes is not None:
            buff, size = insn_bytes, len(insn_bytes)
        else:
            buff, size, _ = self._load_bytes(addr, size, state, clemory)

        if not buff or size == 0:
            raise SimEngineError("No bytes in memory for block starting at %#x." % addr)

        # phase 5: lift to pcode
        l.debug("Creating pcode.IRSB of arch %s at %#x", arch.name, addr)
        try:
            for subphase in range(2):
                irsb = lift(
                    buff,
                    addr + thumb,
                    arch,
                    max_bytes=size,
                    max_inst=num_inst,
                    bytes_offset=thumb,
                    traceflags=traceflags,
                    opt_level=opt_level,
                    strict_block_end=strict_block_end,
                    skip_stmts=skip_stmts,
                    collect_data_refs=collect_data_refs,
                )

                if subphase == 0 and irsb.statements is not None:
                    # check for possible stop points
                    stop_point = self._first_stoppoint(irsb, extra_stop_points)
                    if stop_point is not None:
                        size = stop_point - addr
                        continue

                if use_cache:
                    self._block_cache[cache_key] = irsb
                if state:
                    state._inspect(
                        "vex_lift",
                        BP_AFTER,
                        mem_read_address=addr,
                        mem_read_length=size,
                    )
                return irsb

        # phase x: error handling
        except PyVEXError as e:
            l.debug("Translation error at %#x", addr)
            raise SimTranslationError("Unable to translate bytecode") from e

    def _load_bytes(
        self, addr: int, max_size: int, state: SimState | None = None, clemory: cle.Clemory | None = None
    ) -> tuple[bytes, int, int]:
        if clemory is None and state is None:
            raise SimEngineError("state and clemory cannot both be None in _load_bytes().")

        buff, size, offset = b"", 0, 0

        # XXX: Prioritize loading from patched state, if we have patches
        have_patches = self.project and self.project.kb.patches.items()
        if state is None and have_patches:
            state = self.project.kb.patches.patched_entry_state

        load_from_state = self.selfmodifying_code or have_patches

        # skip loading from the clemory if we're using the ultra page
        # TODO: is this a good change? it neuters lookback optimizations
        # we can try concrete loading the full page but that has drawbacks too...
        # if state is not None and issubclass(getattr(state.memory, 'PAGE_TYPE', object), UltraPage):
        #    load_from_state = True

        # Load from the clemory if we can
        if not load_from_state or not state:
            if isinstance(clemory, cle.Clemory):
                try:
                    start, backer = next(clemory.backers(addr))
                except StopIteration:
                    pass
                else:
                    if start <= addr:
                        offset = addr - start
                        if isinstance(backer, (bytes, bytearray)):
                            avail = len(backer) - offset
                            size = min(avail, max_size)
                            buff = backer[offset : offset + size]
                        elif isinstance(backer, list):
                            raise SimTranslationError(
                                "Cannot lift block for arch with strange byte width. If you think you ought to be able "
                                "to, open an issue."
                            )
                        else:
                            raise TypeError("Unsupported backer type %s." % type(backer))
            elif state:
                if state.memory.SUPPORTS_CONCRETE_LOAD:
                    buff = state.memory.concrete_load(addr, max_size)
                else:
                    buff = state.solver.eval(state.memory.load(addr, max_size, inspect=False), cast_to=bytes)
                size = len(buff)

        # If that didn't work and if load_from_state is enabled, try to load from the state
        if load_from_state and state and size == 0:
            if state.memory.SUPPORTS_CONCRETE_LOAD:
                buff = state.memory.concrete_load(addr, max_size)
            else:
                buff = state.solver.eval(state.memory.load(addr, max_size, inspect=False), cast_to=bytes)
            size = len(buff)
            if self.selfmodifying_code and size < min(max_size, 10):  # arbitrary metric for doing the slow path
                l.debug("SMC slow path")
                buff_lst = []
                symbolic_warned = False
                for i in range(max_size):
                    try:
                        byte = state.memory.load(addr + i, 1, inspect=False)
                        if byte.symbolic and not symbolic_warned:
                            symbolic_warned = True
                            l.warning("Executing symbolic code at %#x", addr + i)
                        buff_lst.append(state.solver.eval(byte))
                    except SimError:
                        break

                buff = bytes(buff_lst)
                size = len(buff)

        size = min(max_size, size)
        return buff, size, offset

    def _first_stoppoint(self, irsb: IRSB, extra_stop_points: Sequence[int] | None = None) -> int | None:
        """
        Enumerate the imarks in the block. If any of them (after the first one) are at a stop point, returns the address
        of the stop point. None is returned otherwise.
        """
        if extra_stop_points is None and self.project is None:
            return None

        first_imark = True
        for addr in irsb.instruction_addresses:
            if not first_imark:
                if self.__is_stop_point(addr, extra_stop_points):
                    # could this part be moved by pyvex?
                    return addr
            first_imark = False
        return None

    def __is_stop_point(self, addr: int, extra_stop_points: Sequence[int] | None = None) -> bool:
        if self.project is not None and addr in self.project._sim_procedures:
            return True
        elif extra_stop_points is not None and addr in extra_stop_points:
            return True
        return False

    def __getstate__(self):
        ostate = super().__getstate__()
        s = {
            "_use_cache": self._use_cache,
            "_default_opt_level": self._default_opt_level,
            "selfmodifying_code": self.selfmodifying_code,
            "_single_step": self._single_step,
            "_cache_size": self._cache_size,
            "default_strict_block_end": self.default_strict_block_end,
        }

        return (s, ostate)

    def __setstate__(self, state):
        s, ostate = state
        self._use_cache = s["_use_cache"]
        self._default_opt_level = s["_default_opt_level"]
        self.selfmodifying_code = s["selfmodifying_code"]
        self._single_step = s["_single_step"]
        self._cache_size = s["_cache_size"]
        self.default_strict_block_end = s["default_strict_block_end"]

        # rebuild block cache
        self._initialize_block_cache()
        super().__setstate__(ostate)
