from __future__ import annotations

import shutil
import subprocess

import archinfo
import pytest

import angr
from angr.engines.pcode.cc import SimCCPCodeX86Win16NearCdecl
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeShort


def _decompile_pointer_typed_swi_constant(language_id: str) -> str:
    # mov ax, 0x4201; int 21h; ret. Padding makes 0x4201 part of the readable image so ordinary type inference
    # classifies the constant as a pointer; the SWI boundary must still consume the exact 16-bit AX value.
    code = bytes.fromhex("b80142 f8 fc cd21 c3") + b"\x00" * 0x300
    arch = archinfo.ArchPcode(language_id)
    project = angr.load_shellcode(
        code,
        arch,
        0x4000,
        0x4000,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    project.simos.name = "Win16"
    cfg = project.analyses.CFGFast(
        function_starts=[0x4000],
        regions=[(0x4000, 0x4008)],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        resolve_indirect_jumps=False,
    )
    function = cfg.functions[0x4000]
    function.calling_convention = SimCCPCodeX86Win16NearCdecl(arch)
    function.prototype = SimTypeFunction([], SimTypeShort(signed=False)).with_arch(arch)
    function.prototype_source = PrototypeSource.SIGNATURES

    decompilation = project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=False,
        use_cache=False,
        update_cache=False,
    )

    assert not decompilation.errors
    assert decompilation.codegen is not None
    assert decompilation.codegen.text is not None
    return decompilation.codegen.text


def _decompile_deterministic_swi_state(language_id: str) -> str:
    # 0x7fff + 1 sets OF, SAHF sets CF/PF/AF/ZF/SF from AH=0xd5, and STD sets DF. The remaining MOVs establish the
    # exact guest words without changing flags before INT 21h.
    code = bytes.fromhex(
        "b8ff7f 050100 b4d5 9e b81111 8ed8 b82222 8ec0 b83412 b42a bb7856 b9bc9a baf0de be5713 bf6824 fd cd21 c3"
    )
    arch = archinfo.ArchPcode(language_id)
    project = angr.load_shellcode(
        code,
        arch,
        0x4000,
        0x4000,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    project.simos.name = "Win16"
    cfg = project.analyses.CFGFast(
        function_starts=[0x4000],
        regions=[(0x4000, 0x4000 + len(code))],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        resolve_indirect_jumps=False,
    )
    function = cfg.functions[0x4000]
    function.calling_convention = SimCCPCodeX86Win16NearCdecl(arch)
    function.prototype = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(arch)
    function.prototype_source = PrototypeSource.SIGNATURES

    decompilation = project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=False,
        use_cache=False,
        update_cache=False,
    )

    assert not decompilation.errors
    assert decompilation.codegen is not None
    assert decompilation.codegen.text is not None
    return decompilation.codegen.text


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang is required to validate generated C")
@pytest.mark.parametrize("language_id", ("x86:LE:16:Protected Mode", "x86:LE:16:Real Mode"))
def test_x86_pcode_swi_arguments_are_exact_guest_words_and_compile(language_id: str):
    text = _decompile_pointer_typed_swi_constant(language_id)

    assert "__pcode_swi(33, 16897," in text
    assert "(void*)0x4201" not in text
    assert "(void *)0x4201" not in text

    compiler = shutil.which("clang")
    assert compiler is not None
    declaration = (
        "unsigned short __pcode_swi("
        "unsigned short, unsigned short, unsigned short, unsigned short, unsigned short, "
        "unsigned short, unsigned short, unsigned short, unsigned short, "
        "unsigned char, unsigned char, unsigned char, unsigned char, unsigned char, unsigned char, unsigned char);\n"
    )
    result = subprocess.run(
        [
            compiler,
            "--target=i386-unknown-none-elf",
            "-std=gnu11",
            "-ffreestanding",
            "-fsyntax-only",
            "-Wconversion",
            "-Werror=conversion",
            "-Werror=implicit-function-declaration",
            "-Werror=incompatible-pointer-types",
            "-Werror=int-conversion",
            "-Werror=pointer-to-int-cast",
            "-x",
            "c",
            "-",
        ],
        input=declaration + text,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("language_id", ("x86:LE:16:Protected Mode", "x86:LE:16:Real Mode"))
def test_x86_pcode_swi_passes_all_guest_registers_and_flags_at_runtime(language_id: str, tmp_path):
    compiler = shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("A C compiler is required for generated-C execution validation")

    text = _decompile_deterministic_swi_state(language_id)
    assert text.count("__pcode_swi(") == 1
    source = tmp_path / "pcode_swi.c"
    executable = tmp_path / "pcode_swi"
    source.write_text(
        """
static unsigned int swi_calls, swi_mismatch;
unsigned short __pcode_swi(
    unsigned short vector, unsigned short ax, unsigned short bx, unsigned short cx,
    unsigned short dx, unsigned short si, unsigned short di, unsigned short ds,
    unsigned short es, unsigned char cf, unsigned char pf, unsigned char af,
    unsigned char zf, unsigned char sf, unsigned char of, unsigned char df)
{
    ++swi_calls;
    swi_mismatch |= vector != 33 || ax != 0x2a34 || bx != 0x5678 || cx != 0x9abc;
    swi_mismatch |= dx != 0xdef0 || si != 0x1357 || di != 0x2468;
    swi_mismatch |= ds != 0x1111 || es != 0x2222;
    swi_mismatch |= cf != 1 || pf != 1 || af != 1 || zf != 1 || sf != 1 || of != 1 || df != 1;
    return 0xbeef;
}
"""
        + text
        + "\nint main(void) { _start(); return swi_calls != 1 || swi_mismatch != 0; }\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            compiler,
            "-std=c11",
            "-Wall",
            "-Werror",
            "-Wno-unused-variable",
            "-Wno-unused-but-set-variable",
            "-Wno-unused-function",
            "-Wno-parentheses",
            "-D_start=recovered_entry",
            str(source),
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run([str(executable)], check=True, capture_output=True, text=True)
