#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""
x87/SSE control-state instructions (fnstenv, fldenv, fnsave, frstor, fxsave, fxrstor, fninit) and rdtsc are lifted
to VEX dirty helpers that take the guest-state pointer. They must decompile to clean intrinsic calls: no raw helper
names, no GSPTR placeholder, no AIL operand reprs, no duplicated or dropped side effects.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os

import pytest

from angr.ailment import Manager
from angr.ailment.expression import Const, DirtyExpression, VirtualVariable, VirtualVariableCategory
from angr.analyses import Decompiler
from tests.common import bin_location, load_project_with_scoped_cfg

_FP_DIR = os.path.join(bin_location, "tests", "decompiler_fp")

# function -> (intrinsic, number of expected calls)
_EXPECTED = {
    "save_env": ("__fnstenv(", 1),
    "load_env": ("__fldenv(", 1),
    "save_state": ("__fnsave(", 1),
    "restore_state": ("__frstor(", 1),
    "init_fpu": ("__fninit(", 1),
    "read_tsc": ("__rdtsc(", 1),
    # OUT's data operand is the IN result: nested dirty expressions are rewritten too
    "io_roundtrip": ("__outbyte(112, ", 1),
}
_EXPECTED_FX = {
    "x87_env_x86.exe": {"save_fx": ("__fxsave(", 1), "restore_fx": ("__fxrstor(", 1)},
    # amd64 fxsave/fxrstor are lifted per state component
    "x87_env_amd64": {"save_fx": ("__xsave_x87(", 1), "restore_fx": ("__xrstor_x87(", 1)},
}

_LEAKS = ("dirtyhelper", "GSPTR", "unsupported", "vvar_", "[D]")


def _decompile(bin_name: str, func_name: str) -> str:
    proj, cfg = load_project_with_scoped_cfg(
        os.path.join(_FP_DIR, bin_name),
        _symbol_addr(bin_name, func_name),
        window=0x100,
        expand_call_tree=False,
        project_kwargs={"auto_load_libs": False},
    )
    func = cfg.kb.functions[_symbol_addr(bin_name, func_name)]
    dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
    assert dec.codegen is not None and dec.codegen.text is not None
    return dec.codegen.text


_ADDRS: dict[tuple[str, str], int] = {}


def _symbol_addr(bin_name: str, func_name: str) -> int:
    key = (bin_name, func_name)
    if key not in _ADDRS:
        import angr  # pylint:disable=import-outside-toplevel

        proj = angr.Project(os.path.join(_FP_DIR, bin_name), auto_load_libs=False)
        sym = proj.loader.find_symbol(func_name) or proj.loader.find_symbol("_" + func_name)
        assert sym is not None
        _ADDRS[key] = sym.rebased_addr
    return _ADDRS[key]


@pytest.mark.parametrize("bin_name", ["x87_env_amd64", "x87_env_x86.exe"])
@pytest.mark.parametrize("func_name", [*_EXPECTED, "save_fx", "restore_fx"])
def test_x87_state_intrinsics(bin_name, func_name):
    intrinsic, count = (_EXPECTED | _EXPECTED_FX[bin_name])[func_name]
    text = _decompile(bin_name, func_name)
    assert text.count(intrinsic) == count, text
    if func_name == "io_roundtrip":
        assert "__inbyte(39)" in text, text
    for leak in _LEAKS:
        assert leak not in text, text


@pytest.mark.parametrize("bin_name", ["x87_env_amd64", "x87_env_x86.exe"])
@pytest.mark.parametrize("func_name", ["save_fx", "save_state", "save_env"])
def test_state_save_prototype(bin_name, func_name):
    # the vector-register stores of FXSAVE are not argument uses; the saved image's first dword is returned
    text = _decompile(bin_name, func_name)
    assert f"int {'_' if bin_name.endswith('.exe') else ''}{func_name}(double a0)\n" in text, text
    assert "return v0;" in text, text


def test_rdtsc_result_recombined():
    # edx:eax is put back together into the single 64-bit __rdtsc() result, which is read once
    text = _decompile("x87_env_amd64", "read_tsc")
    assert text.count("__rdtsc(") == 1
    assert ">> 32" not in text and "0xffffffff" not in text, text
    assert "unsigned long long v1;" in text and "return v1;" in text, text


def test_inbyte_result_is_a_byte():
    # __inbyte returns an 8-bit value: no 64-bit local and no leftover mask when it is passed to __outbyte
    text = _decompile("x87_env_amd64", "io_roundtrip")
    assert "char v1;" in text, text
    assert "__outbyte(112, v1);" in text, text


def test_dirty_expression_codegen_renders_c_operands():
    # a dirty expression no rewriter handles is rendered as __dirty_<callee>(<C operands>)
    from angr.analyses.decompiler.structured_codegen.c import (  # pylint:disable=import-outside-toplevel
        CDirtyExpression,
        CStructuredCodeGenerator,
    )

    proj, cfg = load_project_with_scoped_cfg(
        os.path.join(_FP_DIR, "x87_env_amd64"),
        _symbol_addr("x87_env_amd64", "init_fpu"),
        window=0x100,
        expand_call_tree=False,
        project_kwargs={"auto_load_libs": False},
    )
    dec = proj.analyses[Decompiler].prep(fail_fast=True)(
        cfg.kb.functions[_symbol_addr("x87_env_amd64", "init_fpu")], cfg=cfg.model
    )
    codegen = dec.codegen
    assert isinstance(codegen, CStructuredCodeGenerator)
    m = Manager()
    vvar = VirtualVariable(m.next_atom(), 7, 64, VirtualVariableCategory.REGISTER, oident=16)
    dirty = DirtyExpression(m.next_atom(), "ppc32g_dirtyhelper_foo", [vvar, Const(m.next_atom(), 3, 32)], bits=32)
    node = codegen._handle(dirty)
    assert isinstance(node, CDirtyExpression)
    text = "".join(chunk for chunk, _ in node.c_repr_chunks())
    assert text.startswith("__dirty_ppc32g_dirtyhelper_foo(")
    assert text.endswith(", 3)")
    assert "vvar_" not in text and "[D]" not in text
    # an unhandled dirty expression is an unsigned value of its own width
    assert node.type.c_repr() == "unsigned int"


@pytest.mark.parametrize("bin_name", ["x87_env_amd64", "x87_env_x86.exe"])
def test_gsptr_dropped_on_both_converter_paths(bin_name):
    # the guest-state pointer argument of FSTENV is dropped by the Python-IRSB path and the libVEX FFI path alike
    import angr  # pylint:disable=import-outside-toplevel
    from angr.ailment import IRSBConverter, VEXIRSBConverter  # pylint:disable=import-outside-toplevel
    from angr.ailment.statement import DirtyStatement  # pylint:disable=import-outside-toplevel

    proj = angr.Project(os.path.join(_FP_DIR, bin_name), auto_load_libs=False)
    addr = _symbol_addr(bin_name, "save_env")
    block = proj.factory.block(addr)
    start, backer = next(proj.loader.memory.backers(addr))
    assert isinstance(backer, bytearray)
    ffi_block = VEXIRSBConverter.convert_from_lift(
        proj.arch, addr, backer, Manager(), max_bytes=block.size, bytes_offset=addr - start
    )
    for ail_block in (IRSBConverter.convert(block.vex, Manager()), ffi_block):
        dirty_stmts = [stmt for stmt in ail_block.statements if isinstance(stmt, DirtyStatement)]
        assert len(dirty_stmts) == 1
        dirty = dirty_stmts[0].dirty
        assert isinstance(dirty, DirtyExpression)
        assert dirty.callee.endswith("g_dirtyhelper_FSTENV")
        assert len(dirty.operands) == 1
        assert not isinstance(dirty.operands[0], DirtyExpression)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
