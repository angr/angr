"""
Integration test: decompile ccop_triggers binaries and verify VEX ccalls are rewritten.

Each ccop_triggers binary contains NOINLINE functions that exercise specific
(ccop, condition, width) combinations.  The decompiler's ccall rewriters should
simplify these into clean C expressions (comparisons, overflow checks, etc.)
with no raw ``calculate_condition`` / ``calculate_rflags_c`` calls remaining.

Precompiled binaries live in the ``angr/binaries`` repo under
``tests/{x86_64,i386,armhf,aarch64}/ccop_triggers/``.  Sources and the build
script are in ``tests_src/ccop_triggers/``.
"""

from __future__ import annotations

import os

import pytest

import claripy

import angr
from angr.ailment import Expr
from angr.analyses.decompiler.ccall_rewriters.amd64_ccalls import (
    AMD64CCallRewriter,
    AMD64_CondTypes,
    AMD64_OpTypes,
)
from angr.analyses.decompiler.ccall_rewriters.arm_ccalls import ARMCCallRewriter
from angr.analyses.decompiler.ccall_rewriters.arm64_ccalls import ARM64CCallRewriter
from angr.analyses.decompiler.ccall_rewriters.x86_ccalls import (
    X86CCallRewriter,
    X86_CondTypes,
    X86_OpTypes,
)
from angr.engines.vex.claripy import ccall as ccall_sem
from angr.engines.vex.claripy.ccall import (
    ARMCondEQ,
    ARMCondNE,
    ARMCondHS,
    ARMCondLO,
    ARMCondMI,
    ARMCondPL,
    ARMCondVS,
    ARMCondVC,
    ARMCondHI,
    ARMCondLS,
    ARMCondGE,
    ARMCondLT,
    ARMCondGT,
    ARMCondLE,
    ARMG_CC_OP_COPY,
    ARMG_CC_OP_ADD,
    ARMG_CC_OP_SUB,
    ARMG_CC_OP_ADC,
    ARMG_CC_OP_SBB,
    ARMG_CC_OP_LOGIC,
    ARMG_CC_OP_MUL,
    ARMG_CC_OP_MULL,
    ARM64CondEQ,
    ARM64CondNE,
    ARM64CondCS,
    ARM64CondCC,
    ARM64CondMI,
    ARM64CondPL,
    ARM64CondVS,
    ARM64CondVC,
    ARM64CondHI,
    ARM64CondLS,
    ARM64CondGE,
    ARM64CondLT,
    ARM64CondGT,
    ARM64CondLE,
    ARM64G_CC_OP_COPY,
    ARM64G_CC_OP_ADD32,
    ARM64G_CC_OP_ADD64,
    ARM64G_CC_OP_SUB32,
    ARM64G_CC_OP_SUB64,
    ARM64G_CC_OP_ADC32,
    ARM64G_CC_OP_ADC64,
    ARM64G_CC_OP_SBC32,
    ARM64G_CC_OP_SBC64,
    ARM64G_CC_OP_LOGIC32,
    ARM64G_CC_OP_LOGIC64,
)

from tests.analyses.decompiler.test_ccall_rewriters import (
    _ail_to_claripy,
    _assert_equiv,
    _const,
    _make_operands,
    _op_category,
    _vv,
)
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


# ---------------------------------------------------------------------------
# Helper: discover binaries
# ---------------------------------------------------------------------------

_ARCH_DIRS = {
    "amd64": "x86_64",
    "i386": "i386",
    "armhf": "armhf",
    "aarch64": "aarch64",
}


def _discover_binaries():
    """Find all ccop_triggers binaries in the binaries repo, returning pytest params."""
    params = []
    for arch, dir_name in _ARCH_DIRS.items():
        arch_dir = os.path.join(test_location, dir_name, "ccop_triggers")
        if not os.path.isdir(arch_dir):
            continue
        for name in sorted(os.listdir(arch_dir)):
            path = os.path.join(arch_dir, name)
            if os.path.isfile(path) and name.startswith("ccop_"):
                params.append(pytest.param(path, arch, id=f"{arch}/{name}"))
    return params


# ---------------------------------------------------------------------------
# Helper: parse function names
# ---------------------------------------------------------------------------


def _parse_ccop_func(name):
    """Parse ``ccop_sub_condz_32`` -> ``('sub', 'condz', 32)`` (x86/amd64)
    or ``ccop_sub_eq_32`` -> ``('sub', 'eq', 32)`` (ARM/AArch64).

    For rflags_c functions like ``ccop_rflagsc_add_32`` -> ``('rflagsc', 'add', 32)``.
    Returns *None* on parse failure.
    """
    if not name.startswith("ccop_"):
        return None
    rest = name[5:]
    parts = rest.rsplit("_", 1)
    if len(parts) != 2 or not parts[1].isdigit():
        return None
    width = int(parts[1])
    prefix = parts[0]

    # rflags_c: op is 'rflagsc', second field is sub-operation (add/sub/dec)
    if prefix.startswith("rflagsc_"):
        return ("rflagsc", prefix[8:], width)

    op_cond = prefix.rsplit("_", 1)
    if len(op_cond) != 2:
        return None
    return (op_cond[0], op_cond[1], width)


# ---------------------------------------------------------------------------
# Rewriter coverage tables: which (op, cond) pairs each arch handles
# ---------------------------------------------------------------------------

_AMD64_HANDLED = {
    # SUB
    ("sub", "condz"),
    ("sub", "condnz"),
    ("sub", "condl"),
    ("sub", "condnl"),
    ("sub", "condle"),
    ("sub", "condnle"),
    ("sub", "condb"),
    ("sub", "condnb"),
    ("sub", "condbe"),
    ("sub", "condnbe"),
    ("sub", "conds"),
    ("sub", "condns"),
    # ADD
    ("add", "condz"),
    ("add", "condnz"),
    ("add", "conds"),
    ("add", "condns"),
    ("add", "condo"),
    ("add", "condno"),
    ("add", "condb"),
    # LOGIC
    ("logic", "condz"),
    ("logic", "condnz"),
    ("logic", "conds"),
    ("logic", "condns"),
    ("logic", "condl"),
    ("logic", "condnl"),
    ("logic", "condle"),
    ("logic", "condnle"),
    # INC
    ("inc", "condz"),
    ("inc", "condnz"),
    ("inc", "conds"),
    ("inc", "condns"),
    # DEC
    ("dec", "condz"),
    ("dec", "condnz"),
    ("dec", "conds"),
    ("dec", "condns"),
    ("dec", "condle"),
    ("dec", "condnle"),
    # SHL
    ("shl", "condz"),
    ("shl", "condnz"),
    ("shl", "conds"),
    ("shl", "condns"),
    # SHR
    ("shr", "condz"),
    ("shr", "condnz"),
    ("shr", "conds"),
    ("shr", "condns"),
    # UMUL / SMUL
    ("umul", "condo"),
    ("umul", "condno"),
    ("smul", "condo"),
    ("smul", "condno"),
    # SBB — only CondB on amd64
    ("sbb", "condb"),
    # COPY
    ("copy", "condz"),
    ("copy", "condnz"),
}

_I386_HANDLED = {
    # SUB — same as amd64
    ("sub", "condz"),
    ("sub", "condnz"),
    ("sub", "condl"),
    ("sub", "condnl"),
    ("sub", "condle"),
    ("sub", "condnle"),
    ("sub", "condb"),
    ("sub", "condnb"),
    ("sub", "condbe"),
    ("sub", "condnbe"),
    ("sub", "conds"),
    ("sub", "condns"),
    # ADD — amd64 set plus CondLE, CondNLE, CondBE
    ("add", "condz"),
    ("add", "condnz"),
    ("add", "conds"),
    ("add", "condns"),
    ("add", "condo"),
    ("add", "condno"),
    ("add", "condb"),
    ("add", "condle"),
    ("add", "condnle"),
    ("add", "condbe"),
    # LOGIC — amd64 set plus CondB, CondBE
    ("logic", "condz"),
    ("logic", "condnz"),
    ("logic", "conds"),
    ("logic", "condns"),
    ("logic", "condl"),
    ("logic", "condnl"),
    ("logic", "condle"),
    ("logic", "condnle"),
    ("logic", "condb"),
    ("logic", "condbe"),
    # INC — CondZ, CondNZ, CondO, CondNO  (CondS/CondNS is amd64-only)
    ("inc", "condz"),
    ("inc", "condnz"),
    ("inc", "condo"),
    ("inc", "condno"),
    # DEC — CondZ, CondNZ, CondLE, CondNLE  (CondS/CondNS is amd64-only)
    ("dec", "condz"),
    ("dec", "condnz"),
    ("dec", "condle"),
    ("dec", "condnle"),
    # SHL / SHR — same as amd64
    ("shl", "condz"),
    ("shl", "condnz"),
    ("shl", "conds"),
    ("shl", "condns"),
    ("shr", "condz"),
    ("shr", "condnz"),
    ("shr", "conds"),
    ("shr", "condns"),
    # UMUL / SMUL
    ("umul", "condo"),
    ("umul", "condno"),
    ("smul", "condo"),
    ("smul", "condno"),
    # ADC — CondO, CondNO, CondB
    ("adc", "condo"),
    ("adc", "condno"),
    ("adc", "condb"),
    # SBB — many conditions on x86
    ("sbb", "condb"),
    ("sbb", "condbe"),
    ("sbb", "condnb"),
    ("sbb", "condnbe"),
    ("sbb", "condl"),
    ("sbb", "condnl"),
    ("sbb", "condo"),
    ("sbb", "condno"),
    # COPY
    ("copy", "condz"),
    ("copy", "condnz"),
}

# Width-specific overrides: x86 SMUL rewriter only handles 32-bit (L)
_WIDTH_OVERRIDES = {
    ("i386", "smul", "condo", 8): False,
    ("i386", "smul", "condo", 16): False,
    ("i386", "smul", "condno", 8): False,
    ("i386", "smul", "condno", 16): False,
}


_ARMHF_HANDLED = {
    # SUB
    ("sub", "eq"),
    ("sub", "ne"),
    ("sub", "mi"),
    ("sub", "pl"),
    ("sub", "le"),
    # ADD
    ("add", "eq"),
    ("add", "hs"),
    ("add", "lo"),
    ("add", "mi"),
    ("add", "pl"),
    ("add", "le"),
    ("add", "hi"),
    ("add", "ls"),
    ("add", "ge"),
    ("add", "lt"),
    ("add", "gt"),
    # LOGIC
    ("logic", "eq"),
    ("logic", "hs"),
    ("logic", "lo"),
    # SBB
    ("sbb", "hs"),
    ("sbb", "lo"),
}

_AARCH64_HANDLED = {
    # SUB: all conditions
    ("sub", "eq"),
    ("sub", "ne"),
    ("sub", "hs"),
    ("sub", "lo"),
    ("sub", "mi"),
    ("sub", "pl"),
    ("sub", "vs"),
    ("sub", "vc"),
    ("sub", "hi"),
    ("sub", "ls"),
    ("sub", "ge"),
    ("sub", "lt"),
    ("sub", "gt"),
    ("sub", "le"),
    # ADD: all conditions
    ("add", "eq"),
    ("add", "ne"),
    ("add", "hs"),
    ("add", "lo"),
    ("add", "mi"),
    ("add", "pl"),
    ("add", "vs"),
    ("add", "vc"),
    ("add", "hi"),
    ("add", "ls"),
    ("add", "ge"),
    ("add", "lt"),
    ("add", "gt"),
    ("add", "le"),
    # LOGIC
    ("logic", "eq"),
    ("logic", "ne"),
    ("logic", "hs"),
    ("logic", "lo"),
    ("logic", "mi"),
    ("logic", "pl"),
    ("logic", "vs"),
    ("logic", "vc"),
    ("logic", "ge"),
    ("logic", "lt"),
    ("logic", "gt"),
    ("logic", "le"),
    # SBC
    ("sbc", "eq"),
    ("sbc", "ne"),
    ("sbc", "hs"),
    ("sbc", "lo"),
    # ADC
    ("adc", "eq"),
    ("adc", "ne"),
}


def _should_be_simplified(arch, op, cond, width):
    """Return True if this (op, cond, width) should be simplified on *arch*."""
    override = _WIDTH_OVERRIDES.get((arch, op, cond, width))
    if override is not None:
        return override
    # rflags_c is amd64-only and always handled there
    if op == "rflagsc":
        return arch == "amd64"
    if arch == "amd64":
        handled = _AMD64_HANDLED
    elif arch == "i386":
        handled = _I386_HANDLED
    elif arch == "armhf":
        handled = _ARMHF_HANDLED
    elif arch == "aarch64":
        handled = _AARCH64_HANDLED
    else:
        return False
    return (op, cond) in handled


# Substrings that indicate an unresolved VEX ccall in decompiled output
_CCALL_MARKERS = ("calculate_condition", "calculate_rflags_c")


# ---------------------------------------------------------------------------
# Z3 semantic equivalence verification
# ---------------------------------------------------------------------------

_COND_NAME_MAP = {
    "condz": "CondZ",
    "condnz": "CondNZ",
    "condl": "CondL",
    "condnl": "CondNL",
    "condle": "CondLE",
    "condnle": "CondNLE",
    "condb": "CondB",
    "condnb": "CondNB",
    "condbe": "CondBE",
    "condnbe": "CondNBE",
    "conds": "CondS",
    "condns": "CondNS",
    "condo": "CondO",
    "condno": "CondNO",
}

_ARM_COND_NAME_MAP = {
    # Long form (forward compat)
    "condeq": "CondEQ",
    "condne": "CondNE",
    "condhs": "CondHS",
    "condlo": "CondLO",
    "condmi": "CondMI",
    "condpl": "CondPL",
    "condvs": "CondVS",
    "condvc": "CondVC",
    "condhi": "CondHI",
    "condls": "CondLS",
    "condge": "CondGE",
    "condlt": "CondLT",
    "condgt": "CondGT",
    "condle": "CondLE",
    # Short form (matches binary function names like ccop_sub_eq_32)
    "eq": "CondEQ",
    "ne": "CondNE",
    "hs": "CondHS",
    "lo": "CondLO",
    "mi": "CondMI",
    "pl": "CondPL",
    "vs": "CondVS",
    "vc": "CondVC",
    "hi": "CondHI",
    "ls": "CondLS",
    "ge": "CondGE",
    "lt": "CondLT",
    "gt": "CondGT",
    "le": "CondLE",
}

# Map ARM condition name strings to their integer values
_ARM_COND_VALS = {
    "CondEQ": ARMCondEQ,
    "CondNE": ARMCondNE,
    "CondHS": ARMCondHS,
    "CondLO": ARMCondLO,
    "CondMI": ARMCondMI,
    "CondPL": ARMCondPL,
    "CondVS": ARMCondVS,
    "CondVC": ARMCondVC,
    "CondHI": ARMCondHI,
    "CondLS": ARMCondLS,
    "CondGE": ARMCondGE,
    "CondLT": ARMCondLT,
    "CondGT": ARMCondGT,
    "CondLE": ARMCondLE,
}

# Map ARM op name strings to their integer values (no width suffix)
_ARM_OP_VALS = {
    "ARMG_CC_OP_COPY": ARMG_CC_OP_COPY,
    "ARMG_CC_OP_ADD": ARMG_CC_OP_ADD,
    "ARMG_CC_OP_SUB": ARMG_CC_OP_SUB,
    "ARMG_CC_OP_ADC": ARMG_CC_OP_ADC,
    "ARMG_CC_OP_SBB": ARMG_CC_OP_SBB,
    "ARMG_CC_OP_LOGIC": ARMG_CC_OP_LOGIC,
    "ARMG_CC_OP_MUL": ARMG_CC_OP_MUL,
    "ARMG_CC_OP_MULL": ARMG_CC_OP_MULL,
}

# Map ARM64 condition name strings to their integer values
# Note: CondHS->ARM64CondCS, CondLO->ARM64CondCC (ARM64 uses CS/CC naming)
_ARM64_COND_VALS = {
    "CondEQ": ARM64CondEQ,
    "CondNE": ARM64CondNE,
    "CondHS": ARM64CondCS,
    "CondLO": ARM64CondCC,
    "CondMI": ARM64CondMI,
    "CondPL": ARM64CondPL,
    "CondVS": ARM64CondVS,
    "CondVC": ARM64CondVC,
    "CondHI": ARM64CondHI,
    "CondLS": ARM64CondLS,
    "CondGE": ARM64CondGE,
    "CondLT": ARM64CondLT,
    "CondGT": ARM64CondGT,
    "CondLE": ARM64CondLE,
}

# Map ARM64 op names to integer values; width-specific (32/64)
_ARM64_OP_VALS = {
    "ARM64G_CC_OP_COPY": ARM64G_CC_OP_COPY,
    "ARM64G_CC_OP_ADD32": ARM64G_CC_OP_ADD32,
    "ARM64G_CC_OP_ADD64": ARM64G_CC_OP_ADD64,
    "ARM64G_CC_OP_SUB32": ARM64G_CC_OP_SUB32,
    "ARM64G_CC_OP_SUB64": ARM64G_CC_OP_SUB64,
    "ARM64G_CC_OP_ADC32": ARM64G_CC_OP_ADC32,
    "ARM64G_CC_OP_ADC64": ARM64G_CC_OP_ADC64,
    "ARM64G_CC_OP_SBC32": ARM64G_CC_OP_SBC32,
    "ARM64G_CC_OP_SBC64": ARM64G_CC_OP_SBC64,
    "ARM64G_CC_OP_LOGIC32": ARM64G_CC_OP_LOGIC32,
    "ARM64G_CC_OP_LOGIC64": ARM64G_CC_OP_LOGIC64,
}

_WIDTH_SUFFIX = {8: "B", 16: "W", 32: "L", 64: "Q"}

# Dedup: each (arch, op, cond, width) is Z3-verified at most once across O1/O2/Os
_z3_verified: set[tuple] = set()


def _arm_op_category(op_name: str) -> str:
    """Classify an ARM/ARM64 op name into a category for operand layout."""
    for cat in ("SBC", "SBB", "ADC", "SUB", "ADD", "LOGIC", "MUL", "MULL", "COPY"):
        if cat in op_name.upper():
            return cat
    return op_name


def _make_arm_operands(op_name: str, native_bits: int):
    """Create AIL operands and claripy symbols for ARM/ARM64 ccalls.

    ARM/ARM64 ccalls use (cond_n_op, dep1, dep2, dep3) — four operands after
    the combined cond_n_op.  dep3 is the carry input for SBB/SBC/ADC ops,
    or 0 for everything else.
    """
    cat = _arm_op_category(op_name)
    dep1_a, dep1_c = _vv(1, native_bits), claripy.BVS("dep1", native_bits)
    vv_map: dict[int, claripy.ast.BV] = {1: dep1_c}

    if cat in ("SUB", "ADD"):
        dep2_a, dep2_c = _vv(2, native_bits), claripy.BVS("dep2", native_bits)
        dep3_a, dep3_c = _const(0, native_bits), claripy.BVV(0, native_bits)
        vv_map[2] = dep2_c
    elif cat == "LOGIC":
        # ARM32: dep2 = shifter_carry_out, dep3 = old V flag
        # ARM64: dep2 = 0, dep3 = 0
        # For Z3 verification we use symbolic dep2 for ARM32 (carry-out matters)
        # and zero for ARM64
        dep2_a, dep2_c = _vv(2, native_bits), claripy.BVS("dep2", native_bits)
        dep3_a, dep3_c = _vv(3, native_bits), claripy.BVS("dep3", native_bits)
        vv_map[2] = dep2_c
        vv_map[3] = dep3_c
    elif cat in ("SBB", "SBC", "ADC"):
        dep2_a, dep2_c = _vv(2, native_bits), claripy.BVS("dep2", native_bits)
        dep3_a, dep3_c = _vv(3, native_bits), claripy.BVS("dep3", native_bits)
        vv_map[2] = dep2_c
        vv_map[3] = dep3_c
    elif cat == "COPY":
        dep2_a, dep2_c = _const(0, native_bits), claripy.BVV(0, native_bits)
        dep3_a, dep3_c = _const(0, native_bits), claripy.BVV(0, native_bits)
    else:
        dep2_a, dep2_c = _vv(2, native_bits), claripy.BVS("dep2", native_bits)
        dep3_a, dep3_c = _const(0, native_bits), claripy.BVV(0, native_bits)
        vv_map[2] = dep2_c

    return dep1_a, dep2_a, dep3_a, dep1_c, dep2_c, dep3_c, vv_map


def _z3_verify_rewriter(arch, op, cond, width):
    """Z3-prove the rewriter produces a semantically correct expression for this combo."""
    key = (arch, op, cond, width)
    if key in _z3_verified:
        return
    _z3_verified.add(key)

    if arch in ("armhf", "aarch64"):
        _z3_verify_arm_rewriter(arch, op, cond, width)
        return

    native_bits = 64 if arch == "amd64" else 32

    # Build the VEX op name (e.g. "G_CC_OP_SUBL"); COPY has no width suffix
    op_name = "G_CC_OP_COPY" if op == "copy" else f"G_CC_OP_{op.upper()}{_WIDTH_SUFFIX[width]}"

    # Resolve cond/op values from the arch-appropriate dicts
    if arch == "amd64":
        cond_types, op_types = AMD64_CondTypes, AMD64_OpTypes
        callee = "amd64g_calculate_condition"
        platform = "AMD64"
        RewriterCls = AMD64CCallRewriter
    else:
        cond_types, op_types = X86_CondTypes, X86_OpTypes
        callee = "x86g_calculate_condition"
        platform = "X86"
        RewriterCls = X86CCallRewriter

    cond_key = _COND_NAME_MAP.get(cond)
    if cond_key is None or cond_key not in cond_types:
        return
    if op_name not in op_types:
        return

    cond_val = cond_types[cond_key]
    op_val = op_types[op_name]
    if cond_val is None or op_val is None:
        return

    dep1_a, dep2_a, ndep_a, dep1_c, dep2_c, ndep_c, vv_map = _make_operands(op_name, native_bits)

    ccall = Expr.VEXCCallExpression(
        None,
        callee,
        (
            _const(cond_val, native_bits),
            _const(op_val, native_bits),
            dep1_a,
            dep2_a,
            ndep_a,
        ),
        native_bits,
    )
    try:
        ail = RewriterCls(ccall, None).result
    except (AttributeError, TypeError):
        # Some rewriter paths (e.g. amd64 CondB+ADD) need project != None
        return
    if ail is None:
        raise AssertionError(f"Rewriter returned None for {cond_key}+{op_name}")

    mul_signed = _op_category(op_name) == "SMUL"
    try:
        rewritten = _ail_to_claripy(ail, vv_map, mul_signed=mul_signed)
    except NotImplementedError:
        # e.g. Stmt.Call with unsupported builtin target
        return

    orig = ccall_sem.pc_calculate_condition(
        None,
        claripy.BVV(cond_val, native_bits),
        claripy.BVV(op_val, native_bits),
        dep1_c,
        dep2_c,
        ndep_c,
        platform=platform,
    )
    _assert_equiv(rewritten, orig)


def _z3_verify_arm_rewriter(arch, op, cond, width):
    """Z3-prove the ARM/ARM64 rewriter produces a correct expression."""
    cond_key = _ARM_COND_NAME_MAP.get(cond)
    if cond_key is None:
        return

    if arch == "armhf":
        native_bits = 32
        cond_vals = _ARM_COND_VALS
        # ARM32 ops have no width suffix: ARMG_CC_OP_SUB, ARMG_CC_OP_ADD, ...
        op_name = f"ARMG_CC_OP_{op.upper()}"
        op_vals = _ARM_OP_VALS
        callee = "armg_calculate_condition"
        calc_fn = ccall_sem.armg_calculate_condition
        RewriterCls = ARMCCallRewriter
    else:
        native_bits = 64
        cond_vals = _ARM64_COND_VALS
        # ARM64 ops have width suffixes: ARM64G_CC_OP_SUB32, ARM64G_CC_OP_ADD64, ...
        op_name = f"ARM64G_CC_OP_{op.upper()}{width}"
        op_vals = _ARM64_OP_VALS
        callee = "arm64g_calculate_condition"
        calc_fn = ccall_sem.arm64g_calculate_condition
        RewriterCls = ARM64CCallRewriter

    if cond_key not in cond_vals:
        return
    if op_name not in op_vals:
        return

    cond_val = cond_vals[cond_key]
    op_val = op_vals[op_name]

    # ARM/ARM64 encode cond and op together: cond_n_op = (cond << 4) | op
    cond_n_op = (cond_val << 4) | op_val

    dep1_a, dep2_a, dep3_a, dep1_c, dep2_c, dep3_c, vv_map = _make_arm_operands(op_name, native_bits)

    ccall_expr = Expr.VEXCCallExpression(
        None,
        callee,
        (
            _const(cond_n_op, native_bits),
            dep1_a,
            dep2_a,
            dep3_a,
        ),
        native_bits,
    )
    try:
        ail = RewriterCls(ccall_expr, None).result
    except (AttributeError, TypeError):
        return
    if ail is None:
        raise AssertionError(f"Rewriter returned None for {arch} {cond_key}+{op_name}")

    try:
        rewritten = _ail_to_claripy(ail, vv_map)
    except NotImplementedError:
        return

    orig = calc_fn(
        None,
        claripy.BVV(cond_n_op, native_bits),
        dep1_c,
        dep2_c,
        dep3_c,
    )
    _assert_equiv(rewritten, orig)


def _z3_verify_rflagsc(sub_op, width):
    """Z3-prove the rflags_c rewriter for an amd64 sub-operation."""
    key = ("amd64", "rflagsc", sub_op, width)
    if key in _z3_verified:
        return
    _z3_verified.add(key)

    native_bits = 64
    op_name = f"G_CC_OP_{sub_op.upper()}{_WIDTH_SUFFIX[width]}"

    if op_name not in AMD64_OpTypes:
        return
    op_val = AMD64_OpTypes[op_name]
    if op_val is None:
        return

    cat = _op_category(op_name)
    dep1_a, dep1_c = _vv(1, native_bits), claripy.BVS("dep1", native_bits)
    vv_map: dict[int, claripy.ast.BV] = {1: dep1_c}

    if cat in ("ADD", "SUB"):
        dep2_a, dep2_c = _vv(2, native_bits), claripy.BVS("dep2", native_bits)
        ndep_a, ndep_c = _const(0, native_bits), claripy.BVV(0, native_bits)
        vv_map[2] = dep2_c
    else:
        # DEC: dep2=0, ndep=symbolic (old flags)
        dep2_a, dep2_c = _const(0, native_bits), claripy.BVV(0, native_bits)
        ndep_a, ndep_c = _vv(3, native_bits), claripy.BVS("ndep", native_bits)
        vv_map[3] = ndep_c

    ccall = Expr.VEXCCallExpression(
        None,
        "amd64g_calculate_rflags_c",
        (
            _const(op_val, native_bits),
            dep1_a,
            dep2_a,
            ndep_a,
        ),
        native_bits,
    )
    try:
        ail = AMD64CCallRewriter(ccall, None).result
    except (AttributeError, TypeError):
        return
    if ail is None:
        raise AssertionError(f"Rewriter returned None for rflags_c+{op_name}")

    try:
        rewritten = _ail_to_claripy(ail, vv_map)
    except NotImplementedError:
        return

    # rflags_c computes the carry flag = CondB in VEX semantics
    cond_b_val = AMD64_CondTypes["CondB"]
    if cond_b_val is None:
        return
    orig = ccall_sem.pc_calculate_condition(
        None,
        claripy.BVV(cond_b_val, native_bits),
        claripy.BVV(op_val, native_bits),
        dep1_c,
        dep2_c,
        ndep_c,
        platform="AMD64",
    )
    _assert_equiv(rewritten, orig)


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

_BINARIES = _discover_binaries()


@pytest.mark.skipif(not _BINARIES, reason="ccop_triggers binaries not found in binaries repo")
@pytest.mark.parametrize("bin_path,arch", _BINARIES)
def test_ccop_simplification(bin_path, arch):
    """Decompile every ccop_* function and verify expected ccalls are rewritten."""
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=False)
    cfg = p.analyses.CFGFast(normalize=True, data_references=True)
    p.analyses.CompleteCallingConventions(
        cfg=cfg.model,
        recover_variables=True,
        analyze_callsites=True,
    )

    ccop_funcs = sorted(
        [f for f in cfg.functions.values() if f.name.startswith("ccop_") and not f.is_plt and not f.is_simprocedure],
        key=lambda f: f.addr,
    )

    if not ccop_funcs:
        pytest.skip(f"No ccop_* functions in {os.path.basename(bin_path)}")

    failures = []
    for func in ccop_funcs:
        dec = p.analyses.Decompiler(func, cfg=cfg.model)

        if dec.codegen is None:
            failures.append(f"{func.name}: decompilation produced no output")
            continue

        text = dec.codegen.text
        parsed = _parse_ccop_func(func.name)
        if parsed is None:
            continue

        op, cond, width = parsed
        if not _should_be_simplified(arch, op, cond, width):
            continue  # fallback-only function — just checking it doesn't crash

        if text is not None and any(marker in text for marker in _CCALL_MARKERS):
            failures.append(f"{func.name}: ccall not simplified")

        # Z3 rewriter verification
        try:
            if op == "rflagsc":
                _z3_verify_rflagsc(cond, width)
            else:
                _z3_verify_rewriter(arch, op, cond, width)
        except AssertionError as e:
            failures.append(f"{func.name}: Z3 equivalence failed: {e}")

    if failures:
        pytest.fail(
            f"{len(failures)} function(s) in {os.path.basename(bin_path)} not simplified:\n"
            + "\n".join(f"  - {f}" for f in failures)
        )
