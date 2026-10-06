from __future__ import annotations

from angr import sim_type
from angr.ailment.expression import Call, Const, Convert, DirtyExpression, Expression, Load, Reinterpret
from angr.ailment.statement import DirtyStatement, SideEffectStatement, Statement, Store
from angr.analyses.decompiler.variable_map import variable_map_of

from .rewriter_base import DirtyRewriterBase

# helper name (without the "<arch>g_dirtyhelper_" prefix) -> intrinsic name, parameter kinds, return kind.
# Parameter kinds: "ptr" is void *, "int" takes the operand's width. Return kinds: "void", "u64".
# Intrinsic names follow MSVC where an equivalent exists.
_INTRINSICS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "FSTENV": ("__fnstenv", ("ptr",), "void"),
    "FLDENV": ("__fldenv", ("ptr",), "void"),
    "FSAVE": ("__fnsave", ("ptr",), "void"),
    "FNSAVE": ("__fnsave", ("ptr",), "void"),
    "FNSAVES": ("__fnsave", ("ptr",), "void"),
    "FRSTOR": ("__frstor", ("ptr",), "void"),
    "FRSTORS": ("__frstor", ("ptr",), "void"),
    "FXSAVE": ("__fxsave", ("ptr",), "void"),
    "FXRSTOR": ("__fxrstor", ("ptr",), "void"),
    # amd64 fxsave/xsave are lifted as one helper per state component (xmm registers are explicit stores)
    "XSAVE_COMPONENT_0": ("__xsave_x87", ("ptr",), "void"),
    "XSAVE_COMPONENT_1_EXCLUDING_XMMREGS": ("__xsave_mxcsr", ("ptr",), "void"),
    "XRSTOR_COMPONENT_0": ("__xrstor_x87", ("ptr",), "void"),
    "XRSTOR_COMPONENT_1_EXCLUDING_XMMREGS": ("__xrstor_mxcsr", ("ptr",), "void"),
    "FINIT": ("__fninit", (), "void"),
    "RDTSC": ("__rdtsc", (), "u64"),
    "write_cr0": ("__writecr0", ("int",), "void"),
}

# IRStmt_MBE: the memory fence that mfence/lfence/sfence, cpuid and locked instructions lift to
_MEMORY_FENCE = "MBusEvent-Imbe_Fence"

# SxDT / LGDT_LIDT take (addr, op) where op is the ModRM reg field
_DESCRIPTOR_TABLE_INTRINSICS = {0: "__sgdt", 1: "__sidt", 2: "__lgdt", 3: "__lidt"}


class X86DirtyRewriter(DirtyRewriterBase):
    """
    Rewrites X86 DirtyStatement and DirtyExpression: x87 80-bit loads/stores become memory accesses, every other
    "<arch>g_dirtyhelper_*" call becomes an opaque intrinsic call with a prototype.
    """

    __slots__ = ()

    HELPER_PREFIX = "x86g_dirtyhelper_"

    def _rewrite_stmt(self, dirty: DirtyStatement) -> Statement | None:
        dirty_expr = dirty.dirty
        assert isinstance(dirty_expr, DirtyExpression)
        if self._helper_name(dirty_expr) == "storeF80le":
            return self._rewrite_storeF80le(dirty)

        if dirty_expr.callee == _MEMORY_FENCE:
            call_expr = self._make_call(dirty_expr, "_mm_mfence", (), (), "void")
        else:
            call_expr = self._rewrite_expr_to_call(dirty_expr)
            if isinstance(call_expr, Convert):
                call_expr = call_expr.operand
        if not isinstance(call_expr, Call):
            return None
        return SideEffectStatement(self.manager.next_atom(), call_expr, **dirty.tags)

    def _rewrite_expr(self, dirty: DirtyExpression) -> Expression | None:
        if self._helper_name(dirty) == "loadF80le":
            return self._rewrite_loadF80le(dirty)

        return self._rewrite_expr_to_call(dirty)

    def _helper_name(self, dirty: DirtyExpression) -> str | None:
        if dirty.callee.startswith(self.HELPER_PREFIX):
            return dirty.callee[len(self.HELPER_PREFIX) :]
        return None

    def _rewrite_expr_to_call(self, dirty: DirtyExpression) -> Call | Convert | None:
        name = self._helper_name(dirty)
        if name is None:
            return None
        operands = tuple(dirty.operands)

        match name:
            case "IN":
                if len(operands) != 2:
                    return None
                portno, size = operands
                if not isinstance(size, Const):
                    return None
                bits = size.value_int * self.arch.byte_width
                if not dirty.bits or bits > dirty.bits:
                    return None
                # the helper returns the port value zero-extended to its own width
                call = self._make_call(
                    dirty, f"__in{self._inout_intrinsic_suffix(bits)}", (portno,), ("u16",), "auto", bits=bits
                )
                if bits == dirty.bits:
                    return call
                return Convert(self.manager.next_atom(), bits, dirty.bits, False, call, **dirty.tags)
            case "OUT":
                if len(operands) != 3:
                    return None
                portno, data, size = operands
                if not isinstance(size, Const):
                    return None
                bits = size.value_int * self.arch.byte_width
                if data.bits > bits:
                    # the helper takes the value zero-extended to its own width
                    data = Convert(self.manager.next_atom(), data.bits, bits, False, data, **data.tags)
                return self._make_call(
                    dirty, f"__out{self._inout_intrinsic_suffix(bits)}", (portno, data), ("u16", "int"), "void"
                )
            case "SxDT" | "LGDT_LIDT":
                if len(operands) != 2:
                    return None
                addr, op = operands
                if not isinstance(op, Const) or op.value_int not in _DESCRIPTOR_TABLE_INTRINSICS:
                    return None
                return self._make_call(dirty, _DESCRIPTOR_TABLE_INTRINSICS[op.value_int], (addr,), ("ptr",), "void")
            case _ if name.startswith("CPUID_"):
                return self._make_call(dirty, "__cpuid", (), (), "void")

        spec = _INTRINSICS.get(name)
        if spec is not None:
            target, param_kinds, ret_kind = spec
            if len(param_kinds) != len(operands):
                return None
            return self._make_call(dirty, target, operands, param_kinds, ret_kind)

        # any other helper: an intrinsic named after it, with integer operands
        return self._make_call(dirty, f"__{name.lower()}", operands, tuple("int" for _ in operands), "auto")

    def _make_call(
        self,
        dirty: DirtyExpression,
        target: str,
        args: tuple[Expression, ...],
        param_kinds: tuple[str, ...],
        ret_kind: str,
        bits: int | None = None,
    ) -> Call:
        if bits is None:
            bits = dirty.bits
        # intrinsic prototypes are exact
        tags = dict(dirty.tags)
        tags["is_prototype_guessed"] = False
        call = Call(
            self.manager.next_atom(),
            target,
            args=args,
            bits=bits or None,
            **tags,
        )
        prototype = sim_type.SimTypeFunction(
            [self._param_type(kind, arg) for kind, arg in zip(param_kinds, args)],
            self._return_type(ret_kind, bits),
        ).with_arch(self.arch)
        assert isinstance(prototype, sim_type.SimTypeFunction)
        variable_map_of(self.manager).set_prototype(call, prototype)
        return call

    @staticmethod
    def _param_type(kind: str, arg: Expression) -> sim_type.SimType:
        match kind:
            case "ptr":
                return sim_type.SimTypePointer(sim_type.SimTypeBottom(label="void"))
            case "u16":
                return sim_type.SimTypeNum(16, signed=False)
            case _:
                return sim_type.SimTypeNum(arg.bits, signed=False)

    @staticmethod
    def _return_type(kind: str, bits: int) -> sim_type.SimType:
        match kind:
            case "void":
                return sim_type.SimTypeBottom(label="void")
            case "u64":
                return sim_type.SimTypeNum(64, signed=False)
            case _:
                return sim_type.SimTypeNum(bits, signed=False) if bits else sim_type.SimTypeBottom(label="void")

    #
    # x87 FP helpers
    #

    def _rewrite_storeF80le(self, dirty: DirtyStatement) -> Store | None:
        """
        storeF80le(addr, Reinterpret(F64->I64, fp_val)) -> Store(addr, fp_val, size=10)

        Rewrites the dirty helper into a regular 10-byte memory store.
        The size must match loadF80le (also 10 bytes) so that stack
        round-trips (fstpt/fldt) are recognized as the same variable.
        """
        expr = dirty.dirty
        assert isinstance(expr, DirtyExpression)
        if len(expr.operands) != 2:
            return None
        addr = expr.operands[0]
        value = expr.operands[1]
        # Unwrap Reinterpret(F64->I64, fp_val) to get the actual FP value
        if isinstance(value, Reinterpret) and value.from_type == "F" and value.to_type == "I":
            value = value.operand
        return Store(dirty.idx, addr, value, 10, "Iend_LE", **dirty.tags)

    @staticmethod
    def _rewrite_loadF80le(dirty: DirtyExpression) -> Load | None:
        """
        loadF80le(addr) -> Load(addr, size=10, long_double_load=True)

        Rewrites the dirty helper into a regular 10-byte memory load.
        The long_double_load tag marks the value as x87 extended precision
        so that downstream passes (codegen, type inference) can interpret
        the raw 80-bit encoding correctly.
        """
        if len(dirty.operands) != 1:
            return None
        addr = dirty.operands[0]
        tags = dict(dirty.tags)
        tags["long_double_load"] = True
        return Load(dirty.idx, addr, 10, "Iend_LE", **tags)

    #
    # in, out
    #

    @staticmethod
    def _inout_intrinsic_suffix(bits: int) -> str:
        match bits:
            case 8:
                return "byte"
            case 16:
                return "word"
            case 32:
                return "dword"
            case _:
                return f"_{bits}"
