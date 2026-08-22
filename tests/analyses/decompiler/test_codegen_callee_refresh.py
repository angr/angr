from __future__ import annotations

import shutil
import subprocess

import archinfo
import pytest

import angr
from angr import ailment
from angr.analyses.decompiler.structurer_nodes import SequenceNode
from angr.analyses.decompiler.variable_map import VariableMap
from angr.engines.pcode.cc import register_pcode_arch_default_cc
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable


def _caller_codegen():
    arch = archinfo.ArchPcode("x86:LE:16:Real Mode")
    project = angr.load_shellcode(
        b"\xc3",
        arch,
        0,
        0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    caller = project.kb.functions.function(addr=0, name="caller", create=True)
    callee = project.kb.functions.function(addr=0x100, name="sub_3b90", create=True)
    assert caller is not None
    assert callee is not None

    word_type = SimTypeShort(signed=False).with_arch(arch)
    argument_types = [
        SimTypeChar(signed=True).with_arch(arch),
        SimTypeChar(signed=False).with_arch(arch),
        word_type,
    ]
    caller.prototype = SimTypeFunction([], word_type).with_arch(arch)
    scalar_edge_prototype = SimTypeFunction(argument_types, word_type).with_arch(arch)
    callee.prototype = scalar_edge_prototype.copy().with_arch(arch)

    call = ailment.Expr.Call(
        1,
        ailment.Expr.Const(2, callee.addr, 16),
        args=[
            ailment.Expr.Const(3, 1, 16),
            ailment.Expr.Const(4, 2, 16),
            ailment.Expr.Const(5, 3, 16),
        ],
        bits=16,
    )
    variable_map = VariableMap()
    variable_map.set_prototype(call, scalar_edge_prototype)
    call_statement = ailment.Stmt.SideEffectStatement(
        6,
        call,
        ret_expr=ailment.Expr.Register(7, 0, 16),
        ins_addr=0,
    )
    codegen = project.analyses.CStructuredCodeGenerator(
        caller,
        SequenceNode(0, nodes=[ailment.Block(0, 1, statements=[call_statement])]),
        variable_map=variable_map,
    )

    assert "= sub_3b90(1, 2, 3);" in codegen.text
    assert codegen.unsupported_constructs == ()
    return project, callee, codegen, argument_types


def _assert_final_void_conflict(codegen):
    codegen.regenerate_text()

    assert "((unsigned short (*)(char, unsigned char, unsigned short))sub_3b90)(1, 2, 3)" in codegen.text
    assert [(item.kind, item.operation, item.count) for item in codegen.unsupported_constructs] == [
        ("void_call_value", "call-result-consumed", 1)
    ]


def test_regeneration_observes_a_later_callee_prototype_change():
    _project, callee, codegen, argument_types = _caller_codegen()
    callee.prototype = SimTypeFunction(argument_types, None).with_arch(codegen.project.arch)

    _assert_final_void_conflict(codegen)


def test_regeneration_observes_a_replaced_callee_function():
    project, original_callee, codegen, argument_types = _caller_codegen()
    del project.kb.functions[original_callee.addr]
    replacement_callee = project.kb.functions.function(
        addr=original_callee.addr,
        create=True,
    )
    assert replacement_callee is not None
    assert replacement_callee is not original_callee
    replacement_callee.name = original_callee.name
    replacement_callee.prototype = SimTypeFunction(argument_types, None).with_arch(project.arch)

    _assert_final_void_conflict(codegen)


def test_reload_function_metadata_observes_a_replaced_caller_function():
    project, _callee, codegen, _argument_types = _caller_codegen()
    original_caller = codegen._func
    del project.kb.functions[original_caller.addr]
    replacement_caller = project.kb.functions.function(
        addr=original_caller.addr,
        create=True,
    )
    assert replacement_caller is not None
    assert replacement_caller is not original_caller
    replacement_caller.name = "replacement_caller"
    replacement_caller.prototype = SimTypeFunction([], SimTypeChar(signed=False)).with_arch(project.arch)

    codegen.reload_function_metadata()
    codegen.regenerate_text()

    assert codegen._func is replacement_caller
    assert "unsigned char replacement_caller(void)" in codegen.text


def test_reload_function_metadata_rejects_a_different_function():
    _project, callee, codegen, _argument_types = _caller_codegen()

    try:
        codegen.reload_function_metadata(callee)
    except ValueError as error:
        assert f"{callee.addr:#x}" in str(error)
        assert f"{codegen._func.addr:#x}" in str(error)
    else:
        raise AssertionError("reload_function_metadata() accepted a function at a different address")


def _retyped_call_argument_codegen() -> str:
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    project = angr.load_shellcode(
        b"\xc3",
        arch,
        0,
        0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    caller = project.kb.functions.function(addr=0, name="caller", create=True)
    direct_callee = project.kb.functions.function(addr=0x100, name="takes_word", create=True)
    casted_callee = project.kb.functions.function(addr=0x120, name="takes_pointer", create=True)
    assert caller is not None
    assert direct_callee is not None
    assert casted_callee is not None

    word_type = SimTypeShort(signed=False).with_arch(arch)
    pointer_type = SimTypePointer(SimTypeChar(signed=False)).with_arch(arch)
    caller.prototype = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(arch)
    direct_callee.prototype = SimTypeFunction([word_type], word_type).with_arch(arch)
    casted_callee.prototype = SimTypeFunction([pointer_type], word_type).with_arch(arch)

    storage = SimStackVariable(-2, 2, ident="is_value", name="value", region=caller.addr)
    variable_manager = project.kb.dec_variables[caller.addr]
    variable_manager.set_variable_type(storage, word_type)
    direct_argument = ailment.Expr.VirtualVariable(
        1,
        1,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-2,
    )
    casted_argument = ailment.Expr.VirtualVariable(
        2,
        2,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-2,
    )
    direct_call = ailment.Expr.Call(
        3,
        ailment.Expr.Const(4, direct_callee.addr, 16),
        args=[direct_argument],
        bits=16,
    )
    casted_call = ailment.Expr.Call(
        5,
        ailment.Expr.Const(6, casted_callee.addr, 16),
        args=[casted_argument],
        bits=16,
    )
    scalar_edge_prototype = SimTypeFunction([word_type], word_type).with_arch(arch)
    variable_map = VariableMap()
    variable_map.set_variable(direct_argument, storage)
    variable_map.set_variable(casted_argument, storage)
    variable_map.set_prototype(casted_call, scalar_edge_prototype)
    block = ailment.Block(
        0,
        1,
        statements=[
            ailment.Stmt.SideEffectStatement(7, direct_call, ins_addr=0),
            ailment.Stmt.SideEffectStatement(8, casted_call, ins_addr=1),
        ],
    )
    codegen = project.analyses.CStructuredCodeGenerator(
        caller,
        SequenceNode(0, nodes=[block]),
        variable_map=variable_map,
    )

    assert "unsigned short value;" in codegen.text
    assert "takes_word(value);" in codegen.text
    assert "((unsigned short (*)(unsigned short))takes_pointer)(value);" in codegen.text

    # Whole-program finalization may refine the declaration after this retained
    # C AST was built. Both exact scalar call boundaries must then reacquire an
    # explicit guest-word conversion without changing either prototype.
    variable_manager.set_variable_type(storage, pointer_type)
    codegen.reload_variable_types()
    codegen.regenerate_text()

    assert "unsigned char *value;" in codegen.text
    assert "takes_word((unsigned short)value);" in codegen.text
    assert "((unsigned short (*)(unsigned short))takes_pointer)((unsigned short)value);" in codegen.text
    assert direct_callee.prototype.args == (word_type,)
    assert casted_callee.prototype.args == (pointer_type,)
    assert codegen.unsupported_constructs == ()
    return codegen.text


def test_reload_variable_types_recoerces_exact_scalar_call_arguments():
    _retyped_call_argument_codegen()


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang is required to syntax-check emitted C")
def test_retyped_scalar_call_arguments_compile_without_conversion_errors():
    clang = shutil.which("clang")
    assert clang is not None
    source = """
unsigned short takes_word(unsigned short);
unsigned char *takes_pointer(unsigned char *);
""" + _retyped_call_argument_codegen()
    result = subprocess.run(
        [
            clang,
            "--target=i386-unknown-none-elf",
            "-std=gnu11",
            "-ffreestanding",
            "-fno-builtin",
            "-fsyntax-only",
            "-Werror=implicit-function-declaration",
            "-Werror=incompatible-pointer-types",
            "-Werror=int-conversion",
            "-ferror-limit=0",
            "-fno-color-diagnostics",
            "-x",
            "c",
            "-",
        ],
        input=source,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def _source_blind_pcode_return_refresh():
    """Recover and decompile one consumed-AX call and one proven-unused-AX call from bytes only."""

    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    register_pcode_arch_default_cc(arch)

    code = bytearray(b"\x90" * 0x31)
    # call sub_10; mov bx, ax; ret
    code[0:6] = bytes.fromhex("e80d0089c3c3")
    code[0x10] = 0xC3  # sub_10: ret
    # call sub_30; sub ax, ax; ret
    code[0x20:0x26] = bytes.fromhex("e80d0029c0c3")
    code[0x30] = 0xC3  # sub_30: ret

    project = angr.load_shellcode(
        bytes(code),
        arch=arch,
        load_address=0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    project.simos.name = "Win16"
    cfg = project.analyses.CFGFast(
        function_starts=[0, 0x10, 0x20, 0x30],
        regions=[(0, len(code))],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        resolve_indirect_jumps=False,
    )
    project.analyses.CompleteCallingConventions(
        recover_variables=False,
        cfg=cfg.model,
        analyze_callsites=True,
        workers=0,
        target_functions={0, 0x10, 0x20, 0x30},
    )

    consumed_callee = cfg.functions[0x10]
    void_callee = cfg.functions[0x30]
    assert isinstance(consumed_callee.prototype.returnty, SimTypeShort)
    assert isinstance(void_callee.prototype.returnty, SimTypeBottom)

    # Mirror a whole-program producer that retains caller codegens while later callees are decompiled and their
    # CCA_LOW prototypes are refined to CCA_DECOMPILER. The retained callers must observe the refreshed program-wide
    # declaration without losing the proven cross-call return fact.
    consumed_caller_decompilation = project.analyses.Decompiler(cfg.functions[0], cfg=cfg.model, fail_fast=True)
    void_caller_decompilation = project.analyses.Decompiler(cfg.functions[0x20], cfg=cfg.model, fail_fast=True)
    consumed_callee_decompilation = project.analyses.Decompiler(consumed_callee, cfg=cfg.model, fail_fast=True)
    void_callee_decompilation = project.analyses.Decompiler(void_callee, cfg=cfg.model, fail_fast=True)

    codegens = (
        consumed_caller_decompilation.codegen,
        void_caller_decompilation.codegen,
        consumed_callee_decompilation.codegen,
        void_callee_decompilation.codegen,
    )
    assert all(codegen is not None for codegen in codegens)
    consumed_caller_codegen, void_caller_codegen, consumed_callee_codegen, void_callee_codegen = codegens

    assert consumed_callee.prototype_source is PrototypeSource.CCA_DECOMPILER
    assert isinstance(consumed_callee.prototype.returnty, SimTypeShort)
    assert void_callee.prototype_source is PrototypeSource.CCA_DECOMPILER
    assert isinstance(void_callee.prototype.returnty, SimTypeBottom)

    consumed_caller_codegen.regenerate_text()
    void_caller_codegen.regenerate_text()
    assert consumed_caller_codegen.unsupported_constructs == ()
    assert void_caller_codegen.unsupported_constructs == ()
    assert "return sub_10();" in consumed_caller_codegen.text
    assert "sub_30();" in void_caller_codegen.text
    assert "return sub_30();" not in void_caller_codegen.text

    return (
        "short sub_10(void);\n" + consumed_caller_codegen.text,
        consumed_callee_codegen.text,
        "void sub_30(void);\n" + void_caller_codegen.text,
        void_callee_codegen.text,
    )


def test_pcode_decompiler_refresh_preserves_proven_cross_call_return_type():
    _source_blind_pcode_return_refresh()


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang is required to syntax-check emitted C")
def test_pcode_decompiler_refresh_emits_compilable_c():
    clang = shutil.which("clang")
    assert clang is not None
    for source in _source_blind_pcode_return_refresh():
        result = subprocess.run(
            [
                clang,
                "--target=i386-unknown-none-elf",
                "-std=gnu11",
                "-ffreestanding",
                "-fno-builtin",
                "-fno-stack-protector",
                "-fno-pic",
                "-fno-pie",
                "-O0",
                "-fsyntax-only",
                "-ferror-limit=0",
                "-fno-color-diagnostics",
                "-x",
                "c",
                "-",
            ],
            input=source,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
