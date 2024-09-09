# pylint:disable=wrong-import-position,wrong-import-order
from __future__ import annotations
import enum
from typing import TYPE_CHECKING
from collections.abc import Sequence
import logging
import functools
from collections import defaultdict, OrderedDict

import pyvex
import claripy
from archinfo.arch_arm import is_arm_arch

from .... import sim_options as o
from .... import BP, BP_BEFORE, BP_AFTER
from ....misc.ux import once
from ....code_location import CodeLocation
from ....concretization_strategies import SimConcretizationStrategyAny
from ....knowledge_plugins.cfg import IndirectJump, IndirectJumpType
from ....engines.vex.claripy import ccall
from ....engines.light import SimEngineLightVEXMixin, SimEngineLight, SpOffset, RegisterOffset
from ....errors import AngrError, SimError
from ....blade import Blade
from ....annocfg import AnnotatedCFG
from ....exploration_techniques.slicecutor import Slicecutor
from ....exploration_techniques.local_loop_seer import LocalLoopSeer
from ....exploration_techniques.explorer import Explorer
from ....utils.constants import DEFAULT_STATEMENT
from ...propagator.vex_vars import VEXReg
from .resolver import IndirectJumpResolver
from .propagator_utils import PropagatorLoadCallback

try:
    from ....engines import pcode
except ImportError:
    pcode = None

if TYPE_CHECKING:
    from angr import SimState
    from angr.knowledge_plugins import Function

l = logging.getLogger(name=__name__)


class NotAJumpTableNotification(AngrError):
    """
    Exception raised to indicate this is not (or does not appear to be) a jump table.
    """


class UninitReadMeta:
    """
    Uninitialized read remapping details.
    """

    uninit_read_base = 0xC000000


class AddressTransformationTypes(int, enum.Enum):
    """
    Address transformation operations.
    """

    Assignment = 0
    SignedExtension = 1
    UnsignedExtension = 2
    Truncation = 3
    Or1 = 4
    ShiftLeft = 5
    ShiftRight = 6
    Add = 7
    Load = 8


class AddressTransformation:
    """
    Describe and record an address transformation operation.
    """

    def __init__(self, op: AddressTransformationTypes, operands: list, first_load: bool = False):
        self.op = op
        self.operands = operands
        self.first_load = first_load

    def __repr__(self):
        return f"<Transformation: {self.op} {self.operands}>"


class AddressOperand:
    """
    The class for the singleton class AddressSingleton. It represents the address being transformed before using as an
    indirect jump target.
    """

    def __repr__(self):
        return "ADDR"


AddressSingleton = AddressOperand()


class Tmp:
    """
    For modeling Tmp variables.
    """

    def __init__(self, tmp_idx):
        self.tmp_idx = tmp_idx


class JumpTargetBaseAddr:
    """
    Model for jump targets and their data origin.
    """

    def __init__(self, stmt_loc, stmt, tmp, base_addr=None, tmp_1=None):
        self.stmt_loc = stmt_loc
        self.stmt = stmt
        self.tmp: int = tmp
        self.tmp_1 = tmp_1
        self.base_addr: int = base_addr

        assert base_addr is not None or tmp_1 is not None

    @property
    def base_addr_available(self):
        return self.base_addr is not None


#
# Constant register resolving support
#


class ConstantValueManager:
    """
    Manages the loading of registers who hold constant values.
    """

    __slots__ = (
        "project",
        "kb",
        "func",
        "mapping",
    )

    def __init__(self, project, kb, func: Function):
        self.project = project
        self.kb = kb
        self.func = func

        self.mapping = None

    def reg_read_callback(self, state: SimState):
        if not self.mapping:
            self._build_mapping()

        codeloc = CodeLocation(state.scratch.bbl_addr, state.scratch.stmt_idx, ins_addr=state.scratch.ins_addr)
        if codeloc in self.mapping:
            reg_read_offset = state.inspect.reg_read_offset
            if isinstance(reg_read_offset, claripy.ast.BV) and reg_read_offset.op == "BVV":
                reg_read_offset = reg_read_offset.args[0]
            variable = VEXReg(reg_read_offset, state.inspect.reg_read_length)
            if variable in self.mapping[codeloc]:
                state.inspect.reg_read_expr = self.mapping[codeloc][variable]

    def _build_mapping(self):
        # constant propagation
        l.debug("JumpTable: Propagating for %r.", self.func)
        prop = self.project.analyses[PropagatorAnalysis].prep()(
            func=self.func,
            only_consts=True,
            vex_cross_insn_opt=True,
            load_callback=PropagatorLoadCallback(self.project).propagator_load_callback,
            cache_results=True,
            key_prefix="cfg_intermediate",
        )
        self.mapping = prop.replacements


#
# Jump table pre-check
#

_x86_ct = ccall.data["X86"]["CondTypes"]
_amd64_ct = ccall.data["AMD64"]["CondTypes"]
EXPECTED_COND_TYPES = {
    "X86": {
        _x86_ct["CondB"],
        _x86_ct["CondNB"],
        _x86_ct["CondBE"],
        _x86_ct["CondNBE"],
        _x86_ct["CondL"],
        _x86_ct["CondNL"],
        _x86_ct["CondLE"],
        _x86_ct["CondNLE"],
    },
    "AMD64": {
        _amd64_ct["CondB"],
        _amd64_ct["CondNB"],
        _amd64_ct["CondBE"],
        _amd64_ct["CondNBE"],
        _amd64_ct["CondL"],
        _amd64_ct["CondNL"],
        _amd64_ct["CondLE"],
        _amd64_ct["CondNLE"],
    },
    "ARM": {
        ccall.ARMCondHS,
        ccall.ARMCondLO,
        ccall.ARMCondHI,
        ccall.ARMCondLS,
        ccall.ARMCondGE,
        ccall.ARMCondLT,
        ccall.ARMCondGT,
        ccall.ARMCondLE,
    },
    "AARCH64": {
        ccall.ARM64CondCS,
        ccall.ARM64CondCC,
        ccall.ARM64CondHI,
        ccall.ARM64CondLS,
        ccall.ARM64CondGE,
        ccall.ARM64CondLT,
        ccall.ARM64CondGT,
        ccall.ARM64CondLE,
    },
}


class JumpTableProcessorState:
    """
    The state used in JumpTableProcessor.
    """

    __slots__ = (
        "arch",
        "_registers",
        "_stack",
        "_tmpvar_source",
        "is_jumptable",
        "stmts_to_instrument",
        "regs_to_initialize",
    )

    def __init__(self, arch):
        self.arch = arch

        self._registers = {}
        self._stack = {}
        self._tmpvar_source = {}  # a mapping from temporary variables to their origins

        self.is_jumptable = None  # is the current slice representing a jump table?
        self.stmts_to_instrument = []  # Store/Put statements that we should instrument
        self.regs_to_initialize = []  # registers that we should initialize


class RegOffsetAnnotation(claripy.Annotation):
    """
    Register Offset annotation.
    """

    __slots__ = ("reg_offset",)

    def __init__(self, reg_offset: RegisterOffset):
        self.reg_offset = reg_offset

    @property
    def relocatable(self):
        return False

    @property
    def eliminatable(self):
        return False


class JumpTableProcessor(
    SimEngineLightVEXMixin,
    SimEngineLight,
):  # pylint:disable=abstract-method
    """
    Implements a simple and stupid data dependency tracking for stack and register variables.

    Also determines which statements to instrument during static execution of the slice later. For example, the
    following example is not uncommon in non-optimized binaries::

            mov  [rbp+var_54], 1
        loc_4051a6:
            cmp  [rbp+var_54], 6
            ja   loc_405412 (default)
        loc_4051b0:
            mov  eax, [rbp+var_54]
            mov  rax, qword [rax*8+0x223a01]
            jmp  rax

    We want to instrument the first instruction and replace the constant 1 with a symbolic variable, otherwise we will
    not be able to recover all jump targets later in block 0x4051b0.
    """

    def __init__(self, project, indirect_jump_node_pred_addrs: set[int], bp_sp_diff=0x100):
        super().__init__()
        self.project = project
        self._bp_sp_diff = bp_sp_diff  # bp - sp
        self._tsrc = set()  # a scratch variable to store source information for values
        self._indirect_jump_node_pred_addrs = indirect_jump_node_pred_addrs

        self._SPOFFSET_BASE = claripy.BVS("SpOffset", self.project.arch.bits, explicit_name=True)
        self._REGOFFSET_BASE: dict[int, claripy.ast.BV] = {}

    def _top(self, size: int):
        return None

    def _is_top(self, expr) -> bool:
        return expr is None

    @staticmethod
    def _is_spoffset(expr) -> bool:
        return "SpOffset" in expr.variables

    def _get_spoffset_expr(self, sp_offset: SpOffset) -> claripy.ast.BV:
        return self._SPOFFSET_BASE.annotate(RegOffsetAnnotation(sp_offset))

    @staticmethod
    def _extract_spoffset_from_expr(expr: claripy.ast.Base) -> SpOffset | None:
        if expr.op == "BVS":
            for anno in expr.annotations:
                if isinstance(anno, RegOffsetAnnotation):
                    return anno.reg_offset
        elif expr.op == "__add__":
            if len(expr.args) == 1:
                return JumpTableProcessor._extract_spoffset_from_expr(expr.args[0])
            if len(expr.args) == 2 and expr.args[1].op == "BVV":
                sp_offset = JumpTableProcessor._extract_spoffset_from_expr(expr.args[0])
                if sp_offset is not None:
                    delta = expr.args[1].concrete_value
                    sp_offset += delta
                    return sp_offset
        elif expr.op == "__and__" and len(expr.args) == 2 and expr.args[1].op == "BVV":
            # ignore all masking on SpOffsets
            return JumpTableProcessor._extract_spoffset_from_expr(expr.args[0])
        return None

    @staticmethod
    def _is_registeroffset(expr) -> bool:
        return "RegisterOffset" in expr.variables

    def _get_regoffset_expr(self, reg_offset: RegisterOffset, bits: int) -> claripy.ast.BV:
        if bits not in self._REGOFFSET_BASE:
            self._REGOFFSET_BASE[bits] = claripy.BVS("RegisterOffset", bits, explicit_name=True)
        return self._REGOFFSET_BASE[bits].annotate(RegOffsetAnnotation(reg_offset))

    @staticmethod
    def _extract_regoffset_from_expr(expr: claripy.ast.Base) -> RegisterOffset | None:
        if expr.op == "BVS":
            for anno in expr.annotations:
                if isinstance(anno, RegOffsetAnnotation):
                    return anno.reg_offset
        elif expr.op == "__add__":
            if len(expr.args) == 1:
                return JumpTableProcessor._extract_regoffset_from_expr(expr.args[0])
            if len(expr.args) == 2 and expr.args[1].op == "BVV":
                reg_offset = JumpTableProcessor._extract_regoffset_from_expr(expr.args[0])
                if reg_offset is not None:
                    delta = expr.args[1].concrete_value
                    reg_offset += delta
                    return reg_offset
        elif expr.op == "__and__" and len(expr.args) == 2 and expr.args[1].op == "BVV":
            # ignore all masking on SpOffsets
            return JumpTableProcessor._extract_spoffset_from_expr(expr.args[0])
        return None

    def _handle_WrTmp(self, stmt):
        self._tsrc = set()
        super()._handle_WrTmp(stmt)

        if self._tsrc:
            self.state._tmpvar_source[stmt.tmp] = self._tsrc

    def _handle_Put(self, stmt):
        self._tsrc = set()
        offset = stmt.offset
        data = self._expr(stmt.data)
        r = (self._tsrc, data) if self._tsrc is not None else ((self.block.addr, self.stmt_idx), data)
        self.state._registers[offset] = r

    def _handle_Store(self, stmt):
        self._tsrc = set()
        addr = self._expr(stmt.addr)
        data = self._expr(stmt.data)

        if addr is None:
            return

        if isinstance(addr, SpOffset):
            self.state._stack[addr.offset] = ((self.block.addr, self.stmt_idx), data)

    def _handle_RdTmp(self, expr):
        v = super()._handle_RdTmp(expr)
        if expr.tmp in self.state._tmpvar_source:
            self._tsrc |= set(self.state._tmpvar_source[expr.tmp])
        return v

    def _handle_Get(self, expr):
        if expr.offset == self.arch.bp_offset:
            v = self._get_spoffset_expr(SpOffset(self.arch.bits, self._bp_sp_diff))
        elif expr.offset == self.arch.sp_offset:
            v = self._get_spoffset_expr(SpOffset(self.arch.bits, 0))
        else:
            if expr.offset in self.state._registers:
                self._tsrc |= set(self.state._registers[expr.offset][0])
                v = self.state._registers[expr.offset][1]
            else:
                # the register does not exist
                # we initialize it here
                v = RegisterOffset(expr.result_size(self.tyenv), expr.offset, 0)
                v = self._get_regoffset_expr(v, expr.result_size(self.tyenv))
                src = (self.block.addr, self.stmt_idx)
                self._tsrc.add(src)
                self.state._registers[expr.offset] = ([src], v)

        # make sure the size matches
        # note that this is sometimes incorrect. for example, we do not differentiate between reads at ah and al...
        # but it should be good enough for now (without switching state._registers to a real SimMemory, which will
        # surely slow down stuff quite a bit)
        if v is not None:
            bits = expr.result_size(self.tyenv)
            if v.size() > bits:
                v = v[bits - 1 : 0]
            elif v.size() < bits:
                v = claripy.ZeroExt(bits - v.size(), v)
        return v

    def _handle_function(self, expr):  # pylint:disable=unused-argument,no-self-use
        return None  # This analysis is not interprocedural

    def _handle_Load(self, expr):
        addr = self._expr(expr.addr)
        size = expr.result_size(self.tyenv) // 8
        return self._do_load(addr, size)

    def _handle_LoadG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard is True:
            return self._do_load(stmt.addr, stmt.addr.result_size(self.tyenv) // 8)
        if guard is False:
            return self._do_load(stmt.alt, stmt.alt.result_size(self.tyenv) // 8)
        return None

    def _handle_Const(self, expr):
        v = super()._handle_Const(expr)
        self._tsrc.add("const")
        return v

    def _handle_CmpLE(self, expr):
        self._handle_Comparison(*expr.args)

    def _handle_CmpGE(self, expr):
        self._handle_Comparison(*expr.args)

    def _handle_CmpLT(self, expr):
        self._handle_Comparison(*expr.args)

    def _handle_CmpGT(self, expr):
        self._handle_Comparison(*expr.args)

    def _handle_CCall(self, expr):
        if not isinstance(expr.args[0], pyvex.IRExpr.Const):
            return
        cond_type_enum = expr.args[0].con.value

        if self.arch.name in {"X86", "AMD64", "AARCH64"}:
            if cond_type_enum in EXPECTED_COND_TYPES[self.arch.name]:
                self._handle_Comparison(expr.args[2], expr.args[3])
        elif is_arm_arch(self.arch):
            if cond_type_enum in EXPECTED_COND_TYPES["ARM"]:
                self._handle_Comparison(expr.args[2], expr.args[3])
        else:
            # other architectures
            l.warning("Please fill in EXPECTED_COND_TYPES for %s.", self.arch.name)
            self._handle_Comparison(expr.args[2], expr.args[3])

    def _handle_Comparison(self, arg0, arg1):
        if self.block.addr not in self._indirect_jump_node_pred_addrs:
            return

        # found the comparison
        arg0_src, arg1_src = None, None

        if isinstance(arg0, pyvex.IRExpr.RdTmp):
            if arg0.tmp in self.state._tmpvar_source:
                arg0_src = self.state._tmpvar_source[arg0.tmp]
                arg0_src = None if not arg0_src or len(arg0_src) > 1 else next(iter(arg0_src))
        elif isinstance(arg0, pyvex.IRExpr.Const):
            arg0_src = "const"
        if isinstance(arg1, pyvex.IRExpr.RdTmp):
            if arg1.tmp in self.state._tmpvar_source:
                arg1_src = self.state._tmpvar_source[arg1.tmp]
                arg1_src = None if not arg1_src or len(arg1_src) > 1 else next(iter(arg1_src))
        elif isinstance(arg1, pyvex.IRExpr.Const):
            arg1_src = "const"

        if arg0_src == "const" and arg1_src == "const":
            # comparison of two consts... there is nothing we can do
            self.state.is_jumptable = True
            return
        if arg0_src not in {"const", None} and arg1_src not in {"const", None}:
            # this is probably not a jump table
            return
        if arg1_src == "const":
            # make sure arg0_src is const
            arg0_src, arg1_src = arg1_src, arg0_src

        self.state.is_jumptable = True

        if arg0_src != "const":
            # we failed during dependency tracking so arg0_src couldn't be determined
            # but we will still try to resolve it as a jump table as a fall back
            return

        if isinstance(arg1_src, tuple):
            arg1_src_stmt = self.project.factory.block(arg1_src[0], cross_insn_opt=True).vex.statements[arg1_src[1]]
            if isinstance(arg1_src_stmt, pyvex.IRStmt.Store):
                # Storing a constant/variable in memory
                # We will need to overwrite it when executing the slice to guarantee the full recovery of jump table
                # targets.
                #
                # Here is an example:
                #     mov  [rbp+var_54], 1
                # loc_4051a6:
                #     cmp  [rbp+var_54], 6
                #     ja   loc_405412 (default)
                #
                # Instead of writing 1 to [rbp+var_54], we want to write a symbolic variable there instead. Otherwise
                # we will only recover the second jump target instead of all 7 targets.
                self.state.stmts_to_instrument.append(("mem_write", *arg1_src))
            elif isinstance(arg1_src_stmt, pyvex.IRStmt.WrTmp) and isinstance(arg1_src_stmt.data, pyvex.IRExpr.Load):
                # Loading a constant/variable from memory (and later the value is stored in a register)
                # Same as above, we will need to overwrite it when executing the slice to guarantee the full recovery
                # of jump table targets.
                #
                # Here is an example:
                #     mov eax, [0x625a3c]
                #     cmp eax, 0x4
                #     ja  0x40899d  (default)
                # loc_408899:
                #     mov eax, eax
                #     mov rax, qword [rax*8+0x220741]
                #     jmp rax
                #
                self.state.stmts_to_instrument.append(("mem_read", *arg1_src))
            elif isinstance(arg1_src_stmt, pyvex.IRStmt.Put):
                # Storing a constant/variable in register
                # Same as above...
                #
                # Here is an example:
                #     movzx eax, byte ptr [rax+12h]
                #     movzx eax, al
                #     cmp   eax, 0xe
                #     ja    0x405b9f (default)
                # loc_405b34:
                #     mov   eax, eax
                #     mov   rax, qword [rax*8+0x2231ae]
                #
                self.state.stmts_to_instrument.append(("reg_write", *arg1_src))

    def _do_load(self, addr, size):
        src = (self.block.addr, self.stmt_idx)
        self._tsrc = {src}
        if addr is None:
            return None

        if self._is_spoffset(addr):
            spoffset = self._extract_spoffset_from_expr(addr)
            if spoffset is not None and spoffset.offset in self.state._stack:
                self._tsrc = {self.state._stack[spoffset.offset][0]}
                return self.state._stack[spoffset.offset][1]
        elif isinstance(addr, int):
            # Load data from memory if it is mapped
            try:
                return self.project.loader.memory.unpack_word(addr, size=size)
            except KeyError:
                return None
        elif self._is_registeroffset(addr):
            # Load data from a register, but this register hasn't been initialized at this point
            # We will need to initialize this register during slice execution later

            # Try to get where this register is first accessed
            reg_offset = self._extract_regoffset_from_expr(addr)
            if reg_offset is not None and reg_offset.reg in self.state._registers:
                try:
                    source = next(iter(src for src in self.state._registers[reg_offset.reg][0] if src != "const"))
                    assert isinstance(source, tuple)
                    self.state.regs_to_initialize.append((*source, reg_offset.reg, reg_offset.bits))
                except StopIteration:
                    # we don't need to initialize this register
                    # it might be caused by an incorrect analysis result
                    # e.g.  PN-337140.bin 11e918  r0 comes from r4, r4 comes from r0@11e8c0, and r0@11e8c0 comes from
                    # function call sub_375c04. Since we do not analyze sub_375c04, we treat r0@11e918 as a constant 0.
                    pass

            return None

        return None


#
# State hooks
#


class StoreHook:
    """
    Hook for memory stores.
    """

    @staticmethod
    def hook(state):
        write_length = state.inspect.mem_write_length
        if write_length is None:
            write_length = len(state.inspect.mem_write_expr)
        else:
            write_length = write_length * state.arch.byte_width
        state.inspect.mem_write_expr = claripy.BVS("instrumented_store", write_length)


class LoadHook:
    """
    Hook for memory loads.
    """

    def __init__(self):
        self._var = None

    def hook_before(self, state):
        addr = state.inspect.mem_read_address
        size = state.solver.eval(state.inspect.mem_read_length)
        self._var = claripy.BVS("instrumented_load", size * 8)
        state.memory.store(addr, self._var, endness=state.arch.memory_endness)

    def hook_after(self, state):
        state.inspect.mem_read_expr = self._var


class PutHook:
    """
    Hook for register writes.
    """

    @staticmethod
    def hook(state):
        state.inspect.reg_write_expr = claripy.BVS(
            "instrumented_put", state.solver.eval(state.inspect.reg_write_length) * 8
        )


class RegisterInitializerHook:
    """
    Hook for register init.
    """

    def __init__(self, reg_offset, reg_bits, value):
        self.reg_offset = reg_offset
        self.reg_bits = reg_bits
        self.value = value

    def hook(self, state):
        state.registers.store(self.reg_offset, claripy.BVV(self.value, self.reg_bits))


class BSSHook:
    """
    Hook for BSS read/write.
    """

    def __init__(self, project, bss_regions):
        self.project = project
        self._bss_regions = bss_regions
        self._written_addrs = set()

    def bss_memory_read_hook(self, state):
        if not self._bss_regions:
            return

        read_addr = state.inspect.mem_read_address
        read_length = state.inspect.mem_read_length

        if not isinstance(read_addr, int) and read_addr.symbolic:
            # don't touch it
            return

        concrete_read_addr = state.solver.eval(read_addr)
        concrete_read_length = state.solver.eval(read_length)

        for start, size in self._bss_regions:
            if start <= concrete_read_addr < start + size:
                # this is a read from the .bss section
                break
        else:
            return

        if concrete_read_addr not in self._written_addrs:
            # it was never written to before. we overwrite it with unconstrained bytes
            for i in range(0, concrete_read_length, self.project.arch.bytes):
                state.memory.store(
                    concrete_read_addr + i,
                    state.solver.Unconstrained("unconstrained", self.project.arch.bits),
                    endness=self.project.arch.memory_endness,
                )

                # job done :-)

    def bss_memory_write_hook(self, state):
        if not self._bss_regions:
            return

        write_addr = state.inspect.mem_write_address

        if not isinstance(write_addr, int) and write_addr.symbolic:
            return

        concrete_write_addr = state.solver.eval(write_addr)
        concrete_write_length = (
            state.solver.eval(state.inspect.mem_write_length)
            if state.inspect.mem_write_length is not None
            else len(state.inspect.mem_write_expr) // state.arch.byte_width
        )

        for start, size in self._bss_regions:
            if start <= concrete_write_addr < start + size:
                # hit a BSS section
                break
        else:
            return

        if concrete_write_length > 1024:
            l.warning("Writing more 1024 bytes to the BSS region, only considering the first 1024 bytes.")
            concrete_write_length = 1024

        for i in range(concrete_write_addr, concrete_write_length):
            self._written_addrs.add(i)


class MIPSGPHook:
    """
    Hooks all reads from and writes into the gp register for MIPS32 binaries.
    """

    def __init__(self, gp_offset: int, gp: int):
        self.gp_offset = gp_offset
        self.gp = gp

    def gp_register_read_hook(self, state):
        read_offset = state.inspect.reg_read_offset
        read_length = state.inspect.reg_read_length
        if state.solver.eval(read_offset) == self.gp_offset and read_length == 4:
            state.inspect.reg_read_expr = claripy.BVV(self.gp, size=32)

    def gp_register_write_hook(self, state):
        write_offset = state.inspect.reg_write_offset
        write_length = state.inspect.reg_write_length
        if state.solver.eval(write_offset) == self.gp_offset and write_length == 4:
            state.inspect.reg_write_expr = claripy.BVV(self.gp, size=32)


#
# Main class
#


class JumpTableResolver(IndirectJumpResolver):
    """
    A generic jump table resolver.

    This is a fast jump table resolution. For performance concerns, we made the following assumptions:
        - The final jump target comes from the memory.
        - The final jump target must be directly read out of the memory, without any further modification or altering.

    Progressively larger program slices will be analyzed to determine jump table location and size. If the size of the
    table cannot be determined, a *guess* will be made based on how many entries in the table *appear* valid.
    """

    def __init__(self, project, resolve_calls: bool = True):
        super().__init__(project, timeless=False)

        self.resolve_calls = resolve_calls

        self._bss_regions = None
        # the maximum number of resolved targets. Will be initialized from CFG.
        self._max_targets = None

        # cached memory read addresses that are used to initialize uninitialized registers
        # should be cleared before every symbolic execution run on the slice
        self._cached_memread_addrs = {}

        self._find_bss_region()

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        if pcode is not None and isinstance(block.vex, pcode.lifter.IRSB):
            if once("pcode__indirect_jump_resolver"):
                l.warning("JumpTableResolver does not support P-Code IR yet; CFG may be incomplete.")
            return False

        if jumpkind == "Ijk_Boring":
            return True
        return bool(self.resolve_calls and jumpkind == "Ijk_Call")

    def resolve(self, cfg, addr, func_addr, block, jumpkind, func_graph_complete: bool = True, **kwargs):
        """
        Resolves jump tables.

        :param cfg: A CFG instance.
        :param int addr: IRSB address.
        :param int func_addr: The function address.
        :param pyvex.IRSB block: The IRSB.
        :return: A bool indicating whether the indirect jump is resolved successfully, and a list of resolved targets
        :rtype: tuple
        """

        if not cfg.kb.functions.contains_addr(func_addr):
            # fix for angr issue #3768
            # the function must exist in the KB
            return False, None

        func: Function = cfg.kb.functions[func_addr]
        self._max_targets = cfg._indirect_jump_target_limit

        # this is an indirect call if (1) the instruction is a call, or (2) the instruction is a tail jump (we detect
        # sp moving up to approximate)
        potential_call_table = jumpkind == "Ijk_Call" or self._sp_moved_up(block) or len(func.block_addrs_set) <= 5
        # we only perform full-function propagation for jump tables or call tables in really small functions
        if not potential_call_table or len(func.block_addrs_set) <= 5:
            cv_manager = ConstantValueManager(self.project, cfg.kb, func)
        else:
            cv_manager = None

        for slice_steps in range(1, 5):
            # Perform a backward slicing from the jump target
            # Important: Do not go across function call boundaries
            b = Blade(
                cfg.graph,
                addr,
                -1,
                cfg=cfg,
                project=self.project,
                ignore_sp=False,
                ignore_bp=False,
                max_level=slice_steps,
                base_state=self.base_state,
                stop_at_calls=True,
                cross_insn_opt=True,
            )

            l.debug("Try resolving %#x with a %d-level backward slice...", addr, slice_steps)
            r, targets = self._resolve(
                cfg, addr, func, b, cv_manager, potential_call_table=False, func_graph_complete=func_graph_complete
            )
            if r:
                return r, targets

        if potential_call_table:
            b = Blade(
                cfg.graph,
                addr,
                -1,
                cfg=cfg,
                project=self.project,
                ignore_sp=False,
                ignore_bp=False,
                max_level=1,
                base_state=self.base_state,
                stop_at_calls=True,
                cross_insn_opt=True,
            )
            return self._resolve(
                cfg, addr, func, b, cv_manager, potential_call_table=True, func_graph_complete=func_graph_complete
            )

        return False, None

    #
    # Private methods
    #

    def _resolve(
        self,
        cfg,
        addr: int,
        func: Function,
        b: Blade,
        cv_manager: ConstantValueManager | None,
        potential_call_table: bool = False,
        func_graph_complete: bool = True,
    ) -> tuple[bool, Sequence[int] | None]:
        """
        Internal method for resolving jump tables.

        :param cfg:       A CFG instance.
        :param addr:      Address of the block where the indirect jump is.
        :param func:      The Function instance.
        :param b:         The generated backward slice.
        :return:          A bool indicating whether the indirect jump is resolved successfully, and a list of
                          resolved targets.
        """

        project = self.project  # short-hand
        func_addr = func.addr
        is_arm = is_arm_arch(self.project.arch)

        stmt_loc = (addr, DEFAULT_STATEMENT)
        if stmt_loc not in b.slice:
            return False, None

        (
            load_stmt_loc,
            load_stmt,
            load_size,
            stmts_to_remove,
            stmts_adding_base_addr,
            transformations,
        ) = self._find_load_statement(b, stmt_loc)
        ite_stmt, ite_stmt_loc = None, None

        if load_stmt_loc is None:
            # the load statement is not found
            # maybe it's a typical ARM-style jump table like the following:
            #   SUB    R3, R5, #34
            #   CMP    R3, #28
            #   ADDLS  PC, PC, R3,LSL#2
            if is_arm:
                ite_stmt, ite_stmt_loc, stmts_to_remove = self._find_load_pc_ite_statement(b, stmt_loc)
            if ite_stmt is None:
                l.debug("Could not find load statement in this slice")
                return False, None

        # more sanity checks

        # for a typical jump table, the current block has only one predecessor, and the predecessor to the current
        # block has two successors (not including itself)
        # for a typical vtable call (or jump if at the end of a function), the block as two predecessors that form a
        # diamond shape
        curr_node = func.get_node(addr)
        if curr_node is None or curr_node not in func.graph:
            l.debug("Could not find the node %#x in the function transition graph", addr)
            return False, None
        preds = list(func.graph.predecessors(curr_node))
        pred_endaddrs = {pred.addr + pred.size for pred in preds}  # handle non-normalized CFGs
        if func_graph_complete and not is_arm and not potential_call_table:
            # on ARM you can do a single-block jump table...
            if len(pred_endaddrs) == 1:
                pred_succs = [succ for succ in func.graph.successors(preds[0]) if succ.addr != preds[0].addr]
                if len(pred_succs) != 2:
                    l.debug("Expect two successors to the single predecessor, found %d.", len(pred_succs))
                    return False, None
            elif len(pred_endaddrs) == 2 and len(preds) == 2:
                pred_succs = set(
                    [succ for succ in func.graph.successors(preds[0]) if succ.addr != preds[0].addr]
                    + [succ for succ in func.graph.successors(preds[1]) if succ.addr != preds[1].addr]
                )
                is_diamond = False
                if len(pred_succs) == 2:
                    non_node_succ = next(iter(pred_succ for pred_succ in pred_succs if pred_succ is not curr_node))
                    while func.graph.out_degree[non_node_succ] == 1:
                        non_node_succ = next(iter(func.graph.successors(non_node_succ)))
                        if non_node_succ == curr_node:
                            is_diamond = True
                            break
                if not is_diamond:
                    l.debug("Expect a diamond shape.")
                    return False, None
            else:
                l.debug("The predecessor-successor shape does not look like a jump table or a vtable jump/call.")
                return False, None

        try:
            jump_target = self._try_resolve_single_constant_loads(load_stmt, cfg, addr)
        except NotAJumpTableNotification:
            return False, None
        if jump_target is not None:
            if self._is_target_valid(cfg, jump_target):
                ij = cfg.indirect_jumps.get(addr, None)
                if ij is not None:
                    ij.jumptable = False
                    ij.resolved_targets = {jump_target}
                return True, [jump_target]
            l.debug("Found single constant load, but it does not appear to be a valid target")
            return False, None

        # Well, we have a real jump table to resolve!

        # skip all statements after the load statement
        # We want to leave the final loaded value as symbolic, so we can
        # get the full range of possibilities
        b.slice.remove_nodes_from(stmts_to_remove)

        stmts_to_instrument, regs_to_initialize = [], []
        try:
            stmts_to_instrument, regs_to_initialize = self._jumptable_precheck(b, {pred.addr for pred in preds})
            l.debug(
                "jumptable_precheck provides stmts_to_instrument = %s, regs_to_initialize = %s",
                stmts_to_instrument,
                regs_to_initialize,
            )
        except NotAJumpTableNotification:
            if not potential_call_table and not is_arm:
                l.debug("Indirect jump at %#x does not look like a jump table. Skip.", addr)
                return False, None

        # Debugging output
        if l.level == logging.DEBUG:
            self._dbg_repr_slice(b)

        # Get all sources
        sources = [n_ for n_ in b.slice.nodes() if b.slice.in_degree(n_) == 0]

        # Create the annotated CFG
        annotatedcfg = AnnotatedCFG(project, None, detect_loops=False)
        annotatedcfg.from_digraph(b.slice)

        # pylint: disable=too-many-nested-blocks
        for block_addr, _ in sources:
            # Use slicecutor to execute each one, and get the address
            # We simply give up if any exception occurs on the way
            start_state = self._initial_state(block_addr, cfg, func_addr)

            # instrument specified store/put/load statements
            self._instrument_statements(start_state, stmts_to_instrument, regs_to_initialize)

            self._cached_memread_addrs.clear()
            init_registers_on_demand_bp = BP(when=BP_BEFORE, enabled=True, action=self._init_registers_on_demand)
            start_state.inspect.add_breakpoint("mem_read", init_registers_on_demand_bp)

            # constant value manager
            if cv_manager is not None:
                constant_value_reg_read_bp = BP(when=BP_AFTER, enabled=True, action=cv_manager.reg_read_callback)
                start_state.inspect.add_breakpoint("reg_read", constant_value_reg_read_bp)

            # use Any as the concretization strategy
            start_state.memory.read_strategies = [SimConcretizationStrategyAny()]
            start_state.memory.write_strategies = [SimConcretizationStrategyAny()]

            # Create the slicecutor
            simgr = self.project.factory.simulation_manager(start_state, resilience=True)
            slicecutor = Slicecutor(annotatedcfg, force_taking_exit=True)
            simgr.use_technique(slicecutor)
            simgr.use_technique(LocalLoopSeer(bound=1))
            if load_stmt is not None:
                explorer = Explorer(find=load_stmt_loc[0])
            elif ite_stmt is not None:
                explorer = Explorer(find=ite_stmt_loc[0])
            else:
                raise TypeError("Unsupported type of jump table.")
            simgr.use_technique(explorer)

            # Run it!
            try:
                simgr.run()
            except KeyError as ex:
                # This is because the program slice is incomplete.
                # Blade will support more IRExprs and IRStmts in the future
                l.debug("KeyError occurred due to incomplete program slice.", exc_info=ex)
                continue

            # Get the jumping targets
            for r in simgr.found:
                if load_stmt is not None:
                    ret = self._try_resolve_targets_load(
                        r,
                        addr,
                        cfg,
                        annotatedcfg,
                        load_stmt,
                        load_size,
                        stmts_adding_base_addr,
                        transformations,
                        potential_call_table,
                    )
                    if ret is None:
                        # Try the next state
                        continue
                    jump_table, jumptable_addr, entry_size, jumptable_size, all_targets, sort = ret
                    if sort == "jumptable":
                        ij_type = IndirectJumpType.Jumptable_AddressLoadedFromMemory
                    elif sort == "vtable":
                        ij_type = IndirectJumpType.Vtable
                    else:
                        ij_type = IndirectJumpType.Unknown
                elif ite_stmt is not None:
                    ret = self._try_resolve_targets_ite(r, addr, cfg, annotatedcfg, ite_stmt)
                    if ret is None:
                        # Try the next state
                        continue
                    jumptable_addr = None
                    jump_table, jumptable_size, entry_size = ret
                    all_targets = jump_table
                    ij_type = IndirectJumpType.Jumptable_AddressComputed
                else:
                    raise TypeError("Unsupported type of jump table.")

                assert ret is not None

                # finally, we filter jump targets according to the alignment of the architecture
                if is_arm_arch(self.project.arch):
                    alignment = 4 if addr % 2 == 0 else 2
                else:
                    alignment = self.project.arch.instruction_alignment
                if alignment != 1:
                    if is_arm_arch(self.project.arch) and addr % 2 == 1:
                        # Special logic for handling THUMB addresses
                        all_targets = [t_ for t_ in all_targets if (t_ - 1) % alignment == 0]
                    else:
                        all_targets = [t_ for t_ in all_targets if t_ % alignment == 0]

                l.info(
                    "Jump table at %#x has %d targets: %s",
                    addr,
                    len(all_targets),
                    ", ".join([hex(a) for a in all_targets]),
                )

                # write to the IndirectJump object in CFG
                ij: IndirectJump = cfg.indirect_jumps.get(addr, None)
                if ij is not None:
                    if len(all_targets) > 1:
                        # It can be considered a jump table only if there are more than one jump target
                        if ij_type in {
                            IndirectJumpType.Jumptable_AddressComputed,
                            IndirectJumpType.Jumptable_AddressLoadedFromMemory,
                        }:
                            ij.jumptable = True
                        else:
                            ij.jumptable = False
                        ij.jumptable_addr = jumptable_addr
                        ij.jumptable_size = jumptable_size
                        ij.jumptable_entry_size = entry_size
                        ij.resolved_targets = set(jump_table)
                        ij.jumptable_entries = jump_table
                        ij.type = ij_type
                    else:
                        ij.jumptable = False
                        ij.resolved_targets = set(jump_table)

                return True, all_targets

        l.info("Could not resolve indirect jump %#x in function %#x.", addr, func_addr)
        return False, None

    def _find_load_statement(self, b, stmt_loc):
        """
        Find the location of the final Load statement that loads indirect jump targets from the jump table.
        """

        # pylint:disable=no-else-continue

        # shorthand
        project = self.project

        # initialization
        load_stmt_loc, load_stmt, load_size = None, None, None
        stmts_to_remove = [stmt_loc]
        stmts_adding_base_addr: list[JumpTargetBaseAddr] = []
        # All temporary variables that hold indirect addresses loaded out of the memory
        # Obviously, load_stmt.tmp must be here
        # if there are additional data transferring statements between the Load statement and the base-address-adding
        # statement, all_addr_holders will have more than one temporary variables
        #
        # Here is an example:
        #
        # IRSB 0x4c64c4
        #  + 06 | t12 = LDle:I32(t7)
        #  + 07 | t11 = 32Sto64(t12)
        #  + 10 | t2 = Add64(0x0000000000571df0,t11)
        #
        # all_addr_holders will be {(0x4c64c4, 11): (AddressTransferringTypes.SignedExtension, 32, 64,),
        #           (0x4c64c4, 12); (AddressTransferringTypes.Assignment,),
        #           }
        transformations: dict[tuple[int, int], AddressTransformation] = OrderedDict()

        initial_block_addr = stmt_loc[0]
        all_load_stmts = sorted(self._all_qualified_load_stmts_in_slice(b, stmt_loc[0]))

        while True:
            preds = list(b.slice.predecessors(stmt_loc))
            if len(preds) != 1:
                break
            block_addr, stmt_idx = stmt_loc = preds[0]
            block = project.factory.block(block_addr, cross_insn_opt=True, backup_state=self.base_state).vex
            if stmt_idx == DEFAULT_STATEMENT:
                # it's the default exit. continue
                continue
            stmt = block.statements[stmt_idx]
            if isinstance(stmt, (pyvex.IRStmt.WrTmp, pyvex.IRStmt.Put)):
                if isinstance(stmt.data, (pyvex.IRExpr.Get, pyvex.IRExpr.RdTmp)):
                    # data transferring
                    stmts_to_remove.append(stmt_loc)
                    if isinstance(stmt, pyvex.IRStmt.WrTmp):
                        transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                            AddressTransformationTypes.Assignment, [stmt.tmp, AddressSingleton]
                        )
                    continue
                if isinstance(stmt.data, pyvex.IRExpr.ITE):
                    # data transferring
                    #   t16 = if (t43) ILGop_Ident32(LDle(t29)) else 0x0000c844
                    # > t44 = ITE(t43,t16,0x0000c844)
                    stmts_to_remove.append(stmt_loc)
                    if isinstance(stmt, pyvex.IRStmt.WrTmp):
                        transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                            AddressTransformationTypes.Assignment, [stmt.tmp, AddressSingleton]
                        )
                    continue
                if isinstance(stmt.data, pyvex.IRExpr.Unop):
                    if stmt.data.op == "Iop_32Sto64":
                        # data transferring with conversion
                        # t11 = 32Sto64(t12)
                        stmts_to_remove.append(stmt_loc)
                        if isinstance(stmt, pyvex.IRStmt.WrTmp):
                            transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                                AddressTransformationTypes.SignedExtension, [32, 64, AddressSingleton]
                            )
                        continue
                    if stmt.data.op == "Iop_64to32":
                        # data transferring with conversion
                        # t24 = 64to32(t21)
                        stmts_to_remove.append(stmt_loc)
                        if isinstance(stmt, pyvex.IRStmt.WrTmp):
                            transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                                AddressTransformationTypes.Truncation, [64, 32, AddressSingleton]
                            )
                        continue
                    if stmt.data.op == "Iop_32Uto64":
                        # data transferring with conversion
                        # t21 = 32Uto64(t22)
                        stmts_to_remove.append(stmt_loc)
                        if isinstance(stmt, pyvex.IRStmt.WrTmp):
                            transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                                AddressTransformationTypes.UnsignedExtension, [32, 64, AddressSingleton]
                            )
                        continue
                    if stmt.data.op == "Iop_16Uto32":
                        # data transferring with conversion
                        stmts_to_remove.append(stmt_loc)
                        if isinstance(stmt, pyvex.IRStmt.WrTmp):
                            transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                                AddressTransformationTypes.UnsignedExtension, [16, 32, AddressSingleton]
                            )
                        continue
                    if stmt.data.op == "Iop_8Uto32":
                        # data transferring with conversion
                        stmts_to_remove.append(stmt_loc)
                        if isinstance(stmt, pyvex.IRStmt.WrTmp):
                            transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                                AddressTransformationTypes.UnsignedExtension, [8, 32, AddressSingleton]
                            )
                        continue
                    if stmt.data.op == "Iop_8Uto64":
                        stmts_to_remove.append(stmt_loc)
                        if isinstance(stmt, pyvex.IRStmt.WrTmp):
                            transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                                AddressTransformationTypes.UnsignedExtension, [8, 64, AddressSingleton]
                            )
                        continue
                elif isinstance(stmt.data, pyvex.IRExpr.Binop):
                    if stmt.data.op.startswith("Iop_Add"):
                        # GitHub issue #1289, an S390X binary
                        # jump_label = &jump_table + *(jump_table[index])
                        #       IRSB 0x4007c0
                        #   00 | ------ IMark(0x4007c0, 4, 0) ------
                        # + 01 | t0 = GET:I32(212)
                        # + 02 | t1 = Add32(t0,0xffffffff)
                        #   03 | PUT(352) = 0x0000000000000003
                        #   04 | t13 = 32Sto64(t0)
                        #   05 | t6 = t13
                        #   06 | PUT(360) = t6
                        #   07 | PUT(368) = 0xffffffffffffffff
                        #   08 | PUT(376) = 0x0000000000000000
                        #   09 | PUT(212) = t1
                        #   10 | PUT(ia) = 0x00000000004007c4
                        #   11 | ------ IMark(0x4007c4, 6, 0) ------
                        # + 12 | t14 = 32Uto64(t1)
                        # + 13 | t8 = t14
                        # + 14 | t16 = CmpLE64U(t8,0x000000000000000b)
                        # + 15 | t15 = 1Uto32(t16)
                        # + 16 | t10 = t15
                        # + 17 | t11 = CmpNE32(t10,0x00000000)
                        # + 18 | if (t11) { PUT(offset=336) = 0x4007d4; Ijk_Boring }
                        #   Next: 0x4007ca
                        #
                        #       IRSB 0x4007d4
                        #   00 | ------ IMark(0x4007d4, 6, 0) ------
                        # + 01 | t8 = GET:I64(r2)
                        # + 02 | t7 = Shr64(t8,0x3d)
                        # + 03 | t9 = Shl64(t8,0x03)
                        # + 04 | t6 = Or64(t9,t7)
                        # + 05 | t11 = And64(t6,0x00000007fffffff8)
                        #   06 | ------ IMark(0x4007da, 6, 0) ------
                        #   07 | PUT(r1) = 0x0000000000400a50
                        #   08 | PUT(ia) = 0x00000000004007e0
                        #   09 | ------ IMark(0x4007e0, 6, 0) ------
                        # + 10 | t12 = Add64(0x0000000000400a50,t11)
                        # + 11 | t16 = LDbe:I64(t12)
                        #   12 | PUT(r2) = t16
                        #   13 | ------ IMark(0x4007e6, 4, 0) ------
                        # + 14 | t17 = Add64(0x0000000000400a50,t16)
                        # + Next: t17
                        #
                        # Special case: a base address is added to the loaded offset before jumping to it.
                        if isinstance(stmt.data.args[0], pyvex.IRExpr.Const) and isinstance(
                            stmt.data.args[1], pyvex.IRExpr.RdTmp
                        ):
                            transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                                AddressTransformationTypes.Add, [stmt.data.args[0].con.value, AddressSingleton]
                            )
                            # we no longer update stmts_adding_base_addr in this case because it's replaced by
                            # transformations
                            stmts_to_remove.append(stmt_loc)
                        elif isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp) and isinstance(
                            stmt.data.args[1], pyvex.IRExpr.Const
                        ):
                            transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                                AddressTransformationTypes.Add, [AddressSingleton, stmt.data.args[1].con.value]
                            )
                            # we no longer update stmts_adding_base_addr in this case because it's replaced by
                            # transformations
                            stmts_to_remove.append(stmt_loc)
                        elif isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp) and isinstance(
                            stmt.data.args[1], pyvex.IRExpr.RdTmp
                        ):
                            # one of the tmps must be holding a concrete value at this point. we will know this when
                            # we perform constant propagation before running JumpTableResolver. this can act as an
                            # indicator that we need to run constant propagation for this function.
                            # for now, we don't support it :)
                            # FIXME: Run constant propagation for the function when necessary. we can also remove
                            #  stmts_adding_base_addr and the surrounding logic then.
                            # transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                            #     AddressTransferringTypes.Add,
                            #     [Tmp(stmt.data.args[0].tmp), Tmp(stmt.data.args[1].tmp)],
                            # )
                            stmts_adding_base_addr.append(
                                JumpTargetBaseAddr(stmt_loc, stmt, stmt.data.args[0].tmp, tmp_1=stmt.data.args[1].tmp)
                            )
                            stmts_to_remove.append(stmt_loc)
                        else:
                            # not supported
                            pass
                        continue
                    if stmt.data.op.startswith("Iop_Or"):
                        # this is sometimes used in VEX statements in THUMB mode code to adjust the address to an odd
                        # number
                        # e.g.
                        #        IRSB 0x4b63
                        #    00 | ------ IMark(0x4b62, 4, 1) ------
                        #    01 | PUT(itstate) = 0x00000000
                        #  + 02 | t11 = GET:I32(r2)
                        #  + 03 | t10 = Shl32(t11,0x01)
                        #  + 04 | t9 = Add32(0x00004b66,t10)
                        #  + 05 | t8 = LDle:I16(t9)
                        #  + 06 | t7 = 16Uto32(t8)
                        #  + 07 | t14 = Shl32(t7,0x01)
                        #  + 08 | t13 = Add32(0x00004b66,t14)
                        #  + 09 | t12 = Or32(t13,0x00000001)
                        #  + Next: t12
                        if (
                            isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp)
                            and isinstance(stmt.data.args[1], pyvex.IRExpr.Const)
                            and stmt.data.args[1].con.value == 1
                        ):
                            # great. here it is
                            stmts_to_remove.append(stmt_loc)
                            transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                                AddressTransformationTypes.Or1, [AddressSingleton]
                            )
                            continue
                    elif stmt.data.op.startswith("Iop_Shl"):
                        # this is sometimes used when dealing with TBx instructions in ARM code.
                        # e.g.
                        #        IRSB 0x4b63
                        #    00 | ------ IMark(0x4b62, 4, 1) ------
                        #    01 | PUT(itstate) = 0x00000000
                        #  + 02 | t11 = GET:I32(r2)
                        #  + 03 | t10 = Shl32(t11,0x01)
                        #  + 04 | t9 = Add32(0x00004b66,t10)
                        #  + 05 | t8 = LDle:I16(t9)
                        #  + 06 | t7 = 16Uto32(t8)
                        #  + 07 | t14 = Shl32(t7,0x01)
                        #  + 08 | t13 = Add32(0x00004b66,t14)
                        #  + 09 | t12 = Or32(t13,0x00000001)
                        #  + Next: t12
                        if isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp) and isinstance(
                            stmt.data.args[1], pyvex.IRExpr.Const
                        ):
                            # found it
                            stmts_to_remove.append(stmt_loc)
                            transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                                AddressTransformationTypes.ShiftLeft, [AddressSingleton, stmt.data.args[1].con.value]
                            )
                            continue
                        # AArch64
                        #
                        # LDRB            W0, [X20,W26,UXTW]
                        # ADR             X1, loc_11F85C
                        # ADD             X0, X1, W0,SXTB#2
                        # BR              X0
                        #
                        #        IRSB 0x51f84c
                        #  + 00 | ------ IMark(0x51f84c, 4, 0) ------
                        #  + 01 | t8 = GET:I64(x26)
                        #  + 02 | t7 = 64to32(t8)
                        #  + 03 | t6 = 32Uto64(t7)
                        #  + 04 | t9 = GET:I64(x20)
                        #  + 05 | t5 = Add64(t9,t6)
                        #  + 06 | t11 = LDle:I8(t5)
                        #  + 07 | t10 = 8Uto64(t11)
                        #  + 08 | ------ IMark(0x51f850, 4, 0) ------
                        #    09 | PUT(x1) = 0x000000000051f85c
                        #  + 10 | ------ IMark(0x51f854, 4, 0) ------
                        #  + 11 | t14 = Shl64(t10,0x38)
                        #  + 12 | t13 = Sar64(t14,0x38)
                        #  + 13 | t12 = Shl64(t13,0x02)
                        #  + 14 | t4 = Add64(0x000000000051f85c,t12)
                        #    15 | PUT(x0) = t4
                        #  + 16 | ------ IMark(0x51f858, 4, 0) ------
                        #  + Next: t4
                    elif (
                        stmt.data.op.startswith("Iop_Sar")
                        and isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp)
                        and isinstance(stmt.data.args[1], pyvex.IRExpr.Const)
                    ):
                        # found it
                        stmts_to_remove.append(stmt_loc)
                        transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                            AddressTransformationTypes.ShiftRight, [AddressSingleton, stmt.data.args[1].con.value]
                        )
                        continue
                elif isinstance(stmt.data, pyvex.IRExpr.Load):
                    # Got it!
                    load_stmt, load_stmt_loc, load_size = (
                        stmt,
                        stmt_loc,
                        block.tyenv.sizeof(stmt.tmp) // self.project.arch.byte_width,
                    )
                    stmts_to_remove.append(stmt_loc)
                    is_first_load_stmt = (
                        True if not all_load_stmts else (stmt_loc == (initial_block_addr, all_load_stmts[0]))
                    )
                    transformations[(stmt_loc[0], stmt.tmp)] = AddressTransformation(
                        AddressTransformationTypes.Load, [AddressSingleton, load_size], first_load=is_first_load_stmt
                    )
                    if not is_first_load_stmt:
                        # This is not the first load statement in the block. more to go
                        continue
            elif isinstance(stmt, pyvex.IRStmt.LoadG):
                # Got it!
                #
                # this is how an ARM jump table is translated to VEX
                # > t16 = if (t43) ILGop_Ident32(LDle(t29)) else 0x0000c844
                load_stmt, load_stmt_loc, load_size = (
                    stmt,
                    stmt_loc,
                    block.tyenv.sizeof(stmt.dst) // self.project.arch.byte_width,
                )
                stmts_to_remove.append(stmt_loc)
            elif isinstance(stmt, pyvex.IRStmt.IMark):
                continue

            break

        return load_stmt_loc, load_stmt, load_size, stmts_to_remove, stmts_adding_base_addr, transformations

    def _find_load_pc_ite_statement(self, b: Blade, stmt_loc: tuple[int, int]):
        """
        Find the location of the final ITE statement that loads indirect jump targets into a tmp.

        The slice looks like the following:

               IRSB 0x41d0fc
          00 | ------ IMark(0x41d0fc, 4, 0) ------
        + 01 | t0 = GET:I32(r5)
        + 02 | t2 = Sub32(t0,0x00000022)
          03 | PUT(r3) = t2
          04 | ------ IMark(0x41d100, 4, 0) ------
          05 | PUT(cc_op) = 0x00000002
          06 | PUT(cc_dep1) = t2
          07 | PUT(cc_dep2) = 0x0000001c
          08 | PUT(cc_ndep) = 0x00000000
          09 | ------ IMark(0x41d104, 4, 0) ------
        + 10 | t25 = CmpLE32U(t2,0x0000001c)
          11 | t24 = 1Uto32(t25)
        + 12 | t8 = Shl32(t2,0x02)
        + 13 | t10 = Add32(0x0041d10c,t8)
        + 14 | t26 = ITE(t25,t10,0x0041d104)    <---- this is the statement that we are looking for. Note that
                                                      0x0041d104 *must* be ignored since it is a side effect generated
                                                      by the VEX ARM lifter
          15 | PUT(pc) = t26
          16 | t21 = Xor32(t24,0x00000001)
          17 | t27 = 32to1(t21)
          18 | if (t27) { PUT(offset=68) = 0x41d108; Ijk_Boring }
        + Next: t26

        :param b:           The Blade instance, which comes with the slice.
        :param stmt_loc:    The location of the final statement.
        :return:
        """

        project = self.project
        ite_stmt, ite_stmt_loc = None, None
        stmts_to_remove = [stmt_loc]

        while True:
            preds = list(b.slice.predecessors(stmt_loc))
            if len(preds) != 1:
                break
            block_addr, stmt_idx = stmt_loc = preds[0]
            stmts_to_remove.append(stmt_loc)
            block = project.factory.block(block_addr, cross_insn_opt=True).vex
            if stmt_idx == DEFAULT_STATEMENT:
                # we should not reach the default exit (which belongs to a predecessor block)
                break
            if not isinstance(block.next, pyvex.IRExpr.RdTmp):
                # next must be an RdTmp
                break
            stmt = block.statements[stmt_idx]
            if (
                isinstance(stmt, pyvex.IRStmt.WrTmp)
                and stmt.tmp == block.next.tmp
                and isinstance(stmt.data, pyvex.IRExpr.ITE)
            ):
                # yes!
                ite_stmt, ite_stmt_loc = stmt, stmt_loc
                break

        return ite_stmt, ite_stmt_loc, stmts_to_remove

    def _jumptable_precheck(self, b, indirect_jump_node_pred_addrs):
        """
        Perform a pre-check on the slice to determine whether it is a jump table or not. Please refer to the docstring
        of JumpTableProcessor for how precheck and statement instrumentation works. A NotAJumpTableNotification
        exception will be raised if the slice fails this precheck.

        :param b:   The statement slice generated by Blade.
        :return:    A list of statements to instrument, and a list of registers to initialize.
        :rtype:     tuple of lists
        """

        # pylint:disable=no-else-continue

        engine = JumpTableProcessor(self.project, indirect_jump_node_pred_addrs)

        sources = [n for n in b.slice.nodes() if b.slice.in_degree(n) == 0]

        annotatedcfg = AnnotatedCFG(self.project, None, detect_loops=False)
        annotatedcfg.from_digraph(b.slice)

        for src in sources:
            state = JumpTableProcessorState(self.project.arch)
            traced = {src[0]}
            while src is not None:
                state._tmpvar_source.clear()
                block_addr, _ = src

                block = self.project.factory.block(block_addr, cross_insn_opt=True, backup_state=self.base_state)
                stmt_whitelist = annotatedcfg.get_whitelisted_statements(block_addr)
                try:
                    engine.process(state, block=block, whitelist=stmt_whitelist)
                except (claripy.errors.ClaripyError, SimError, AngrError):
                    # anything can happen
                    break

                if state.is_jumptable:
                    return state.stmts_to_instrument, state.regs_to_initialize
                if state.is_jumptable is False:
                    raise NotAJumpTableNotification

                # find the next block
                src = None
                for idx in reversed(stmt_whitelist):
                    loc = (block_addr, idx)
                    successors = list(b.slice.successors(loc))
                    if len(successors) == 1:
                        block_addr_ = successors[0][0]
                        if block_addr_ not in traced:
                            src = successors[0]
                            traced.add(block_addr_)
                            break

        raise NotAJumpTableNotification

    @staticmethod
    def _try_resolve_single_constant_loads(load_stmt, cfg, addr):
        """
        Resolve cases where only a single constant load is required to resolve the indirect jump. Strictly speaking, it
        is not a jump table, but we resolve it here anyway.

        :param load_stmt:   The pyvex.IRStmt.Load statement that loads an address.
        :param cfg:         The CFG instance.
        :param int addr:    Address of the jump table block.
        :return:            A jump target, or None if it cannot be resolved.
        :rtype:             int or None
        """

        # If we're just reading a constant, don't bother with the rest of this mess!
        if isinstance(load_stmt, pyvex.IRStmt.WrTmp):
            if type(load_stmt.data.addr) is pyvex.IRExpr.Const:
                # It's directly loading from a constant address
                # e.g.,
                #  ldr r0, =main+1
                #  blx r0
                # It's not a jump table, but we resolve it anyway
                jump_target_addr = load_stmt.data.addr.con.value
                jump_target = cfg._fast_memory_load_pointer(jump_target_addr)
                if jump_target is None:
                    l.info(
                        "Constant indirect jump %#x points outside of loaded memory to %#08x", addr, jump_target_addr
                    )
                    raise NotAJumpTableNotification

                l.info("Resolved constant indirect jump from %#08x to %#08x", addr, jump_target_addr)
                return jump_target

        elif isinstance(load_stmt, pyvex.IRStmt.LoadG) and type(load_stmt.addr) is pyvex.IRExpr.Const:
            # It's directly loading from a constant address
            # e.g.,
            #  4352c     SUB     R1, R11, #0x1000
            #  43530     LDRHI   R3, =loc_45450
            #  ...
            #  43540     MOV     PC, R3
            #
            # It's not a jump table, but we resolve it anyway
            # Note that this block has two branches: One goes to 45450, the other one goes to whatever the original
            # value of R3 is. Some intensive data-flow analysis is required in this case.
            jump_target_addr = load_stmt.addr.con.value
            jump_target = cfg._fast_memory_load_pointer(jump_target_addr)
            l.info("Resolved constant indirect jump from %#08x to %#08x", addr, jump_target_addr)
            return jump_target

        return None

    def _try_resolve_targets_load(
        self,
        r,
        addr,
        cfg,
        annotatedcfg,
        load_stmt,
        load_size,
        stmts_adding_base_addr,
        transformations: dict[tuple[int, int], AddressTransformation],
        potential_call_table: bool = False,
    ):
        """
        Try loading all jump targets from a jump table or a vtable.
        """

        # shorthand
        project = self.project

        try:
            whitelist = annotatedcfg.get_whitelisted_statements(r.addr)
            last_stmt = annotatedcfg.get_last_statement_index(r.addr)
            succ = project.factory.successors(r, whitelist=whitelist, last_stmt=last_stmt)
        except (AngrError, SimError):
            # oops there are errors
            l.debug("Cannot get jump successor states from a path that has reached the target. Skip it.")
            return None

        all_states = succ.flat_successors + succ.unconstrained_successors
        if not all_states:
            l.debug("Slicecutor failed to execute the program slice. No output state is available.")
            return None

        state = all_states[0]  # Just take the first state
        self._cached_memread_addrs.clear()  # clear the cache to save some memory (and avoid confusion when debugging)

        # Parse the memory load statement and get the memory address of where the jump table is stored
        jumptable_addr = self._parse_load_statement(load_stmt, state)
        if jumptable_addr is None:
            return None

        # sanity check and necessary pre-processing
        jump_base_addr = None
        if stmts_adding_base_addr:
            if len(stmts_adding_base_addr) == 1:
                jump_base_addr = stmts_adding_base_addr[0]
                if jump_base_addr.base_addr_available:
                    addr_holders = {(jump_base_addr.stmt_loc[0], jump_base_addr.tmp)}
                else:
                    addr_holders = {
                        (jump_base_addr.stmt_loc[0], jump_base_addr.tmp),
                        (jump_base_addr.stmt_loc[0], jump_base_addr.tmp_1),
                    }
                if len(set(transformations.keys()).intersection(addr_holders)) != 1:
                    # for some reason it's trying to add a base address onto a different temporary variable that we
                    # are not aware of. skip.
                    return None

                if not jump_base_addr.base_addr_available:
                    # we need to decide which tmp is the address holder and which tmp holds the base address
                    addr_holder = next(iter(set(transformations.keys()).intersection(addr_holders)))
                    if jump_base_addr.tmp_1 == addr_holder[1]:
                        # swap the two tmps
                        jump_base_addr.tmp, jump_base_addr.tmp_1 = jump_base_addr.tmp_1, jump_base_addr.tmp
                    # Load the concrete base address
                    jump_base_addr.base_addr = state.solver.eval(state.scratch.temps[jump_base_addr.tmp_1])
            else:
                # We do not support the cases where the base address involves more than one addition.
                # One such case exists in libc-2.27.so shipped with Ubuntu x86 where esi is used as the address of the
                # data region.
                #
                # .text:00047316 mov     eax, esi
                # .text:00047318 mov     esi, [ebp+data_region_ptr]
                # .text:0004731E movsx   eax, al
                # .text:00047321 movzx   eax, byte ptr [esi+eax-603A0h]
                # .text:00047329 mov     eax, ds:(jpt_47337 - 1D8000h)[esi+eax*4] ; switch 32 cases
                # .text:00047330 lea     eax, (loc_47033 - 1D8000h)[esi+eax] ; jumptable 00047337 cases 0-13,27-31
                # .text:00047337 jmp     eax             ; switch
                #
                # the proper solution requires angr to correctly determine that esi is the beginning address of the data
                # region (in this case, 0x1d8000). we give up in such cases until we can reasonably perform a
                # full-function data propagation before performing jump table recovery.
                l.debug("Multiple statements adding bases, not supported yet")  # FIXME: Just check the addresses?

        if jumptable_addr.has_annotation_type(claripy.annotation.RegionAnnotation):
            return None

        all_targets = []
        jump_table = []

        jumptable_si = claripy.SI(bits=project.arch.bits, to_conv=jumptable_addr)

        # we may resolve a vtable (in C, e.g., the IO_JUMPS_FUNC in libc), but the stride of this load is usually 1
        # while the read statement reads a word size at a time.
        # we use this to differentiate between traditional jump tables (where each entry is some blocks that belong to
        # the current function) and vtables (where each entry is a function).
        if jumptable_si.args[3] < load_size:  # stride < load_size
            stride = load_size
            total_cases = jumptable_addr.cardinality // load_size
            sort = "vtable"  # it's probably a vtable!
        else:
            stride = jumptable_si.args[3]
            total_cases = jumptable_addr.cardinality
            sort = "jumptable"

        if total_cases > self._max_targets:
            if (
                potential_call_table
                and sort == "jumptable"
                and stride * 8 == state.arch.bits
                and jumptable_addr.op == "__add__"
            ):
                # Undetermined table size. Take a guess based on target plausibility.
                table_base_addr = None
                for arg in jumptable_addr.args:
                    if arg.concrete:
                        table_base_addr = state.solver.eval(arg)
                        break

                if table_base_addr is not None:
                    addr = table_base_addr
                    # FIXME: May want to support NULL targets for handlers that are not filled in / placeholders
                    # FIXME: Try negative offsets too? (this would be unusual)
                    l.debug("Inspecting table at %#x for plausible targets...", addr)
                    for i in range(self._max_targets):
                        target = cfg._fast_memory_load_pointer(addr, size=load_size)
                        if target is None or not self._is_jumptarget_legal(target):
                            break
                        l.debug("- %#x[%d] -> %#x", table_base_addr, i, target)
                        jump_table.append(target)
                        addr += stride
                    num_targets = len(jump_table)
                    if num_targets == 0:
                        l.debug("Didn't find any plausible targets in suspected jump table %#x", table_base_addr)
                    elif num_targets == self._max_targets:
                        l.debug(
                            "Reached maximum number of targets (%d) while scanning jump table %#x. It might not be "
                            "a jump table, or the limit might be too low.",
                            num_targets,
                            table_base_addr,
                        )
                    else:
                        l.debug("Table at %#x has %d plausible targets", table_base_addr, num_targets)
                        return jump_table, table_base_addr, load_size, num_targets * load_size, jump_table, sort

            # We resolved too many targets for this indirect jump. Something might have gone wrong.
            l.debug(
                "%d targets are resolved for the indirect jump at %#x. It may not be a jump table. Try the "
                "next source, if there is any.",
                total_cases,
                addr,
            )
            return None

            # Or alternatively, we can ask user, which is meh...
            #
            # jump_base_addr = int(raw_input("please give me the jump base addr: "), 16)
            # total_cases = int(raw_input("please give me the total cases: "))
            # jump_target = state.solver.SI(bits=64, lower_bound=jump_base_addr, upper_bound=jump_base_addr +
            # (total_cases - 1) * 8, stride=8)

        min_jumptable_addr = state.solver.min(jumptable_addr)
        max_jumptable_addr = state.solver.max(jumptable_addr)

        # Both the min jump target and the max jump target should be within a mapped memory region
        # i.e., we shouldn't be jumping to the stack or somewhere unmapped
        if not (
            (
                project.loader.find_segment_containing(min_jumptable_addr)
                and project.loader.find_segment_containing(max_jumptable_addr)
            )
            or (
                project.loader.find_section_containing(min_jumptable_addr)
                and project.loader.find_section_containing(max_jumptable_addr)
            )
        ):
            l.debug(
                "Jump table %#x might have jump targets outside mapped memory regions. "
                "Continue to resolve it from the next data source.",
                addr,
            )
            return None

        # Load the jump table from memory
        should_skip = False
        for idx, a in enumerate(range(min_jumptable_addr, max_jumptable_addr + 1, stride)):
            if idx % 100 == 0 and idx != 0:
                l.debug("%d targets have been resolved for the indirect jump at %#x...", idx, addr)
            if idx >= total_cases:
                break
            target = cfg._fast_memory_load_pointer(a, size=load_size)
            if target is None:
                l.debug("Cannot load pointer from address %#x. Skip.", a)
                should_skip = True
                break
            all_targets.append(target)
        if should_skip:
            return None

        # Adjust entries inside the jump table
        mask = (2**self.project.arch.bits) - 1
        transformation_list = list(reversed([v for v in transformations.values() if not v.first_load]))
        if transformation_list:

            def handle_signed_ext(a):
                return (a | 0xFFFFFFFF00000000) if a >= 0x80000000 else a

            def handle_unsigned_ext(a):
                return a

            def handle_trunc_64_32(a):
                return a & 0xFFFFFFFF

            def handle_or1(a):
                return a | 1

            def handle_lshift(num_bits, a):
                return a << num_bits

            def handle_rshift(num_bits, a):
                return a >> num_bits

            def handle_add(con, a):
                return (a + con) & mask

            def handle_load(size, a):
                return cfg._fast_memory_load_pointer(a, size=size)

            invert_conversion_ops = []
            for tran in transformation_list:
                tran_op, args = tran.op, tran.operands
                if tran_op is AddressTransformationTypes.SignedExtension:
                    if args == [32, 64, AddressSingleton]:
                        lam = handle_signed_ext
                    else:
                        raise NotImplementedError("Unsupported signed extension operation.")
                elif tran_op is AddressTransformationTypes.UnsignedExtension:
                    lam = handle_unsigned_ext
                elif tran_op is AddressTransformationTypes.Truncation:
                    if args == [64, 32, AddressSingleton]:
                        lam = handle_trunc_64_32
                    else:
                        raise NotImplementedError("Unsupported truncation operation.")
                elif tran_op is AddressTransformationTypes.Or1:
                    lam = handle_or1
                elif tran_op is AddressTransformationTypes.ShiftLeft:
                    lam = functools.partial(
                        handle_lshift, next(iter(arg for arg in args if arg is not AddressSingleton))
                    )
                elif tran_op is AddressTransformationTypes.ShiftRight:
                    lam = functools.partial(
                        handle_rshift, next(iter(arg for arg in args if arg is not AddressSingleton))
                    )
                elif tran_op is AddressTransformationTypes.Add:
                    add_arg = next(iter(arg for arg in args if arg is not AddressSingleton))
                    if not isinstance(add_arg, int):
                        # unsupported cases (Tmp, for example). abort
                        return None
                    lam = functools.partial(handle_add, add_arg)
                elif tran_op is AddressTransformationTypes.Load:
                    lam = functools.partial(handle_load, args[1])
                elif tran_op is AddressTransformationTypes.Assignment:
                    continue
                else:
                    raise NotImplementedError("Unsupported transformation operation.")
                invert_conversion_ops.append(lam)
            all_targets_copy = all_targets
            all_targets = []
            for target_ in all_targets_copy:
                for lam in invert_conversion_ops:
                    target_ = lam(target_)
                    if target_ is None:
                        # transformation failed. abort
                        return None
                all_targets.append(target_)
            if None in all_targets:
                return None
        if len(stmts_adding_base_addr) == 1:
            stmt_adding_base_addr = stmts_adding_base_addr[0]
            base_addr = stmt_adding_base_addr.base_addr
            all_targets = [(target + base_addr) & mask for target in all_targets]

        # special case for ARM: if the source block is in THUMB mode, all jump targets should be in THUMB mode, too
        if is_arm_arch(self.project.arch) and (addr & 1) == 1:
            all_targets = [target | 1 for target in all_targets]

        if len(all_targets) == 0:
            l.debug("Could not recover jump table")
            return None

        # Finally... all targets are ready
        illegal_target_found = False
        for target in all_targets:
            # if the total number of targets is suspicious (it usually implies a failure in applying the
            # constraints), check if all jump targets are legal
            if len(all_targets) in {1, 0x100, 0x10000} and not self._is_jumptarget_legal(target):
                l.info(
                    "Jump target %#x is probably illegal. Try to resolve indirect jump at %#x from the next source.",
                    target,
                    addr,
                )
                illegal_target_found = True
                break
            jump_table.append(target)
        if illegal_target_found:
            return None

        return jump_table, min_jumptable_addr, load_size, total_cases * load_size, all_targets, sort

    def _try_resolve_targets_ite(
        self, r, addr, cfg, annotatedcfg, ite_stmt: pyvex.IRStmt.WrTmp
    ):  # pylint:disable=unused-argument
        """
        Try loading all jump targets from parsing an ITE block.
        """
        project = self.project

        try:
            whitelist = annotatedcfg.get_whitelisted_statements(r.addr)
            last_stmt = annotatedcfg.get_last_statement_index(r.addr)
            succ = project.factory.successors(r, whitelist=whitelist, last_stmt=last_stmt)
        except (AngrError, SimError):
            # oops there are errors
            l.warning("Cannot get jump successor states from a path that has reached the target. Skip it.")
            return None

        all_states = succ.flat_successors + succ.unconstrained_successors
        if not all_states:
            l.warning("Slicecutor failed to execute the program slice. No output state is available.")
            return None

        state = all_states[0]  # Just take the first state
        temps = state.scratch.temps
        if not isinstance(ite_stmt.data, pyvex.IRExpr.ITE):
            return None
        # load the default
        if not isinstance(ite_stmt.data.iffalse, pyvex.IRExpr.Const):
            return None
        # ite_stmt.data.iffalse.con.value is garbage introduced by the VEX ARM lifter and should be ignored
        if not isinstance(ite_stmt.data.iftrue, pyvex.IRExpr.RdTmp):
            return None
        if not isinstance(ite_stmt.data.cond, pyvex.IRExpr.RdTmp):
            return None
        cond = temps[ite_stmt.data.cond.tmp]
        # apply the constraint
        state.add_constraints(cond == 1)
        # load the target
        target_expr = temps[ite_stmt.data.iftrue.tmp]
        try:
            jump_table = state.solver.eval_upto(target_expr, self._max_targets + 1)
        except SimError:
            return None
        entry_size = len(target_expr) // self.project.arch.byte_width

        if len(jump_table) == self._max_targets + 1:
            # so many targets! failed
            return None

        return jump_table, len(jump_table), entry_size

    @staticmethod
    def _instrument_statements(state, stmts_to_instrument, regs_to_initialize):
        """
        Hook statements as specified in stmts_to_instrument and overwrite values loaded in those statements.

        :param SimState state:              The program state to insert hooks to.
        :param list stmts_to_instrument:    A list of statements to instrument.
        :param list regs_to_initialize:     A list of registers to initialize.
        :return:                            None
        """

        for sort, block_addr, stmt_idx in stmts_to_instrument:
            l.debug("Add a %s hook to overwrite memory/register values at %#x:%d.", sort, block_addr, stmt_idx)
            if sort == "mem_write":
                bp = BP(
                    when=BP_BEFORE,
                    enabled=True,
                    action=StoreHook.hook,
                    condition=lambda _s, a=block_addr, idx=stmt_idx: _s.scratch.bbl_addr == a
                    and _s.scratch.stmt_idx == idx,
                )
                state.inspect.add_breakpoint("mem_write", bp)
            elif sort == "mem_read":
                hook = LoadHook()
                bp0 = BP(
                    when=BP_BEFORE,
                    enabled=True,
                    action=hook.hook_before,
                    condition=lambda _s, a=block_addr, idx=stmt_idx: _s.scratch.bbl_addr == a
                    and _s.scratch.stmt_idx == idx,
                )
                state.inspect.add_breakpoint("mem_read", bp0)
                bp1 = BP(
                    when=BP_AFTER,
                    enabled=True,
                    action=hook.hook_after,
                    condition=lambda _s, a=block_addr, idx=stmt_idx: _s.scratch.bbl_addr == a
                    and _s.scratch.stmt_idx == idx,
                )
                state.inspect.add_breakpoint("mem_read", bp1)
            elif sort == "reg_write":
                bp = BP(
                    when=BP_BEFORE,
                    enabled=True,
                    action=PutHook.hook,
                    condition=lambda _s, a=block_addr, idx=stmt_idx: _s.scratch.bbl_addr == a
                    and _s.scratch.stmt_idx == idx,
                )
                state.inspect.add_breakpoint("reg_write", bp)
            else:
                raise NotImplementedError(f"Unsupported sort {sort} in stmts_to_instrument.")

        reg_val = 0x13370000

        def bp_condition(block_addr, stmt_idx, _s):
            return _s.scratch.bbl_addr == block_addr and _s.inspect.statement == stmt_idx

        for block_addr, stmt_idx, reg_offset, reg_bits in regs_to_initialize:
            l.debug(
                "Add a hook to initialize register %s at %x:%d.",
                state.arch.translate_register_name(reg_offset, size=reg_bits),
                block_addr,
                stmt_idx,
            )
            bp = BP(
                when=BP_BEFORE,
                enabled=True,
                action=RegisterInitializerHook(reg_offset, reg_bits, reg_val).hook,
                condition=functools.partial(bp_condition, block_addr, stmt_idx),
            )
            state.inspect.add_breakpoint("statement", bp)
            reg_val += 16

    def _find_bss_region(self):
        self._bss_regions = []

        # TODO: support other sections other than '.bss'.
        # TODO: this is very hackish. fix it after the chaos.
        for section in self.project.loader.main_object.sections:
            if section.name == ".bss":
                self._bss_regions.append((section.vaddr, section.memsize))
                break

    def _init_registers_on_demand(self, state):
        # for uninitialized read using a register as the source address, we replace them in memory on demand
        read_addr = state.inspect.mem_read_address
        cond = state.inspect.mem_read_condition

        if not isinstance(read_addr, int) and read_addr.uninitialized and cond is None:
            # if this AST has been initialized before, just use the cached addr
            cached_addr = self._cached_memread_addrs.get(read_addr, None)
            if cached_addr is not None:
                state.inspect.mem_read_address = cached_addr
                return

            read_length = state.inspect.mem_read_length
            if not isinstance(read_length, int):
                read_length = read_length.args[3]  # max
            if read_length > 16:
                return
            new_read_addr = claripy.BVV(UninitReadMeta.uninit_read_base, state.arch.bits)
            UninitReadMeta.uninit_read_base += read_length

            # replace the expression in registers
            state.registers.replace_all(read_addr, new_read_addr)

            # extra caution: if this read_addr AST comes up again in the future, we want to replace it with the same
            # address again.
            self._cached_memread_addrs[read_addr] = new_read_addr

            state.inspect.mem_read_address = new_read_addr

            # job done :-)

    def _dbg_repr_slice(self, blade, in_slice_stmts_only=False):
        stmts = defaultdict(set)

        for addr, stmt_idx in sorted(blade.slice.nodes()):
            stmts[addr].add(stmt_idx)

        for addr in sorted(stmts.keys()):
            stmt_ids = stmts[addr]
            irsb = self.project.factory.block(addr, cross_insn_opt=True, backup_state=self.base_state).vex

            print("  ####")
            print(f"  #### Block {addr:#x}")
            print("  ####")

            for i, stmt in enumerate(irsb.statements):
                stmt_taken = i in stmt_ids
                display = stmt_taken if in_slice_stmts_only else True
                if display:
                    s = "%s %x:%02d | " % ("+" if stmt_taken else " ", addr, i)
                    s += f"{stmt.pp_str(arch=self.project.arch, tyenv=irsb.tyenv)} "
                    if stmt_taken:
                        s += "IN: %d" % blade.slice.in_degree((addr, i))
                    print(s)

            # the default exit
            default_exit_taken = DEFAULT_STATEMENT in stmt_ids
            s = "{} {:x}:default | PUT({}) = {}; {}".format(
                "+" if default_exit_taken else " ", addr, irsb.offsIP, irsb.next, irsb.jumpkind
            )
            print(s)

    def _initial_state(self, block_addr, cfg, func_addr: int):
        add_options = {
            o.DO_RET_EMULATION,
            o.TRUE_RET_EMULATION_GUARD,
            o.AVOID_MULTIVALUED_READS,
            # Keep IP symbolic to avoid unnecessary concretization
            o.KEEP_IP_SYMBOLIC,
            o.NO_IP_CONCRETIZATION,
            # be quiet!!!!!!
            o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            o.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        }
        state = self.project.factory.blank_state(
            addr=block_addr,
            mode="static",
            add_options=add_options,
            remove_options={
                o.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY,
                o.UNINITIALIZED_ACCESS_AWARENESS,
            }
            | o.refs,
        )
        state.regs._sp = 0x7FFF_FFF0

        # any read from an uninitialized segment should be unconstrained
        if self._bss_regions:
            bss_hook = BSSHook(self.project, self._bss_regions)
            bss_memory_write_bp = BP(when=BP_AFTER, enabled=True, action=bss_hook.bss_memory_write_hook)
            state.inspect.add_breakpoint("mem_write", bss_memory_write_bp)
            bss_memory_read_bp = BP(when=BP_BEFORE, enabled=True, action=bss_hook.bss_memory_read_hook)
            state.inspect.add_breakpoint("mem_read", bss_memory_read_bp)

        if self.project.arch.name == "MIPS32":
            try:
                func = cfg.kb.functions.get_by_addr(func_addr)
                if func.info and "gp" in func.info:
                    state.regs._gp = func.info["gp"]
            except KeyError:
                pass

            # instrument all reads from gp and all writes to gp
            gp = None
            try:
                func = cfg.kb.functions.get_by_addr(func_addr)
                if func.info and "gp" in func.info:
                    gp = func.info["gp"]
            except KeyError:
                pass
            if gp is not None:
                mips_gp_hook = MIPSGPHook(self.project.arch.registers["gp"][0], gp)
                mips_gp_read_bp = BP(when=BP_AFTER, enabled=True, action=mips_gp_hook.gp_register_read_hook)
                mips_gp_write_bp = BP(when=BP_AFTER, enabled=True, action=mips_gp_hook.gp_register_write_hook)
                state.inspect.add_breakpoint("reg_read", mips_gp_read_bp)
                state.inspect.add_breakpoint("reg_write", mips_gp_write_bp)

        # FIXME:
        # this is a hack: for certain architectures, we do not initialize the base pointer, since the jump table on
        # those architectures may use the bp register to store value
        if self.project.arch.name not in {"S390X"}:
            state.regs.bp = state.arch.initial_sp + 0x2000

        return state

    @staticmethod
    def _parse_load_statement(load_stmt, state):
        """
        Parse a memory load VEX statement and get the jump target addresses.

        :param load_stmt:   The VEX statement for loading the jump target addresses.
        :param state:       The SimState instance (in static mode).
        :return:            An abstract value (or a concrete value) representing the jump target addresses. Return None
                            if we fail to parse the statement.
        """

        # The jump table address is stored in a tmp. In this case, we find the jump-target loading tmp.
        load_addr_tmp = None

        if isinstance(load_stmt, pyvex.IRStmt.WrTmp):
            if type(load_stmt.data.addr) is pyvex.IRExpr.RdTmp:
                load_addr_tmp = load_stmt.data.addr.tmp
            elif type(load_stmt.data.addr) is pyvex.IRExpr.Const:
                # It's directly loading from a constant address
                # e.g.,
                #  ldr r0, =main+1
                #  blx r0
                # It's not a jump table, but we resolve it anyway
                jump_target_addr = load_stmt.data.addr.con.value
                return claripy.BVV(jump_target_addr, state.arch.bits)
        elif isinstance(load_stmt, pyvex.IRStmt.LoadG):
            if type(load_stmt.addr) is pyvex.IRExpr.RdTmp:
                load_addr_tmp = load_stmt.addr.tmp
            elif type(load_stmt.addr) is pyvex.IRExpr.Const:
                # It's directly loading from a constant address
                # e.g.,
                #  4352c     SUB     R1, R11, #0x1000
                #  43530     LDRHI   R3, =loc_45450
                #  ...
                #  43540     MOV     PC, R3
                #
                # It's not a jump table, but we resolve it anyway
                # Note that this block has two branches: One goes to 45450, the other one goes to whatever the original
                # value of R3 is. Some intensive data-flow analysis is required in this case.
                jump_target_addr = load_stmt.addr.con.value
                return claripy.BVV(jump_target_addr, state.arch.bits)
        else:
            raise TypeError(f"Unsupported address loading statement type {type(load_stmt)}.")

        if state.scratch.temps[load_addr_tmp] is None:
            # the tmp variable is not there... umm...
            return None

        jump_addr = state.scratch.temps[load_addr_tmp]

        if isinstance(load_stmt, pyvex.IRStmt.LoadG) and not isinstance(load_stmt.guard, pyvex.IRExpr.Const):
            # LoadG comes with a guard. We should apply this guard to the load expression
            guard_tmp = load_stmt.guard.tmp
            guard = state.scratch.temps[guard_tmp] != 0
            try:
                jump_addr = state.memory._apply_condition_to_symbolic_addr(jump_addr, guard)
            except Exception:  # pylint: disable=broad-except
                l.exception("Error computing jump table address!")
                return None
        return jump_addr

    def _sp_moved_up(self, block) -> bool:
        """
        Examine if the stack pointer moves up (if any values are popped out of the stack) within a single block.
        """

        spt = self.project.analyses.StackPointerTracker(
            None, {self.project.arch.sp_offset}, block=block, track_memory=False
        )
        offset_after = spt.offset_after(block.addr, self.project.arch.sp_offset)
        return offset_after is not None and offset_after > 0

    def _is_jumptarget_legal(self, target):
        try:
            vex_block = self.project.factory.block(target, cross_insn_opt=True).vex_nostmt
        except (AngrError, SimError):
            return False
        if vex_block.jumpkind == "Ijk_NoDecode":
            return False
        return vex_block.size != 0

    def _is_address_mapped(self, addr: int) -> bool:
        return (
            self.project.loader.find_segment_containing(addr) is not None
            or self.project.loader.find_section_containing(addr) is not None
        )

    def _all_qualified_load_stmts_in_slice(self, b: Blade, addr: int) -> list[int]:
        """
        Recognize all qualified load statements in a slice. A qualified load statements refers to those that are
        loading jump targets (or jump offsets) from a jump table, or loading jump table offsets from a jump-table
        offset table.

        :param b:       The Blade object.
        :param addr:    Address of the last block.
        :return:        A list of qualified load statement IDs.
        """

        stmt_ids = []
        for block_addr, stmt_id in b.slice.nodes:
            if block_addr == addr and stmt_id != DEFAULT_STATEMENT:
                stmt_ids.append(stmt_id)

        if not stmt_ids:
            return []
        stmt_ids = sorted(stmt_ids)
        qualified_load_stmt_ids = []
        load_stmt_ids = []
        block = self.project.factory.block(addr, cross_insn_opt=True, backup_state=self.base_state).vex
        tmp_values = {}
        mask = (2**self.project.arch.bits) - 1
        for stmt_id in stmt_ids:
            stmt = block.statements[stmt_id]
            if isinstance(stmt, pyvex.IRStmt.WrTmp):
                if isinstance(stmt.data, pyvex.IRExpr.Const):
                    tmp_values[stmt.tmp] = stmt.data.con.value
                elif isinstance(stmt.data, pyvex.IRExpr.Binop) and stmt.data.op.startswith("Iop_Add"):
                    op0 = None
                    if isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp):
                        op0 = tmp_values.get(stmt.data.args[0].tmp, None)
                    elif isinstance(stmt.data.args[0], pyvex.IRExpr.Const):
                        op0 = stmt.data.args[0].con.value
                    op1 = None
                    if isinstance(stmt.data.args[1], pyvex.IRExpr.RdTmp):
                        op1 = tmp_values.get(stmt.data.args[1].tmp, None)
                    elif isinstance(stmt.data.args[1], pyvex.IRExpr.Const):
                        op1 = stmt.data.args[1].con.value
                    if isinstance(op1, int) and not isinstance(op0, int):
                        op0, op1 = op1, op0
                    if isinstance(op0, int):
                        if op1 is None:
                            tmp_values[stmt.tmp] = ("+", op0, op1)
                        elif isinstance(op1, int):
                            tmp_values[stmt.tmp] = (op0 + op1) & mask
                        elif isinstance(op1, tuple) and op1[0] == "+":
                            tmp_values[stmt.tmp] = ("+", (op0 + op1[1]) & mask, op1[2])
                elif isinstance(stmt.data, pyvex.IRExpr.Load) and isinstance(stmt.data.addr, pyvex.IRExpr.RdTmp):
                    # is this load statement loading from a static address + an offset?
                    v = tmp_values.get(stmt.data.addr.tmp, None)
                    if isinstance(v, tuple) and v[0] == "+" and v[2] is None and self._is_address_mapped(v[1]):
                        qualified_load_stmt_ids.append(stmt_id)
                    load_stmt_ids.append(stmt_id)
        if qualified_load_stmt_ids and len(qualified_load_stmt_ids) <= 2:
            return qualified_load_stmt_ids
        if load_stmt_ids:
            return [load_stmt_ids[-1]]
        return []


from angr.analyses.propagator import PropagatorAnalysis
