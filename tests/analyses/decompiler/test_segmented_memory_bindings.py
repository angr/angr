from __future__ import annotations

import re
import shutil
import subprocess

import archinfo
import pytest

import angr
from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from angr.analyses.decompiler.segmented_memory import normalize_segmented_memory_bindings
from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeWalker
from angr.calling_conventions import SimCCUsercall, SimRegArg
from angr.engines.pcode.cc import SimCCPCodeX86Win16FarPascal, SimCCPCodeX86Win16NearCdecl
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort

_ADDRESS_KIND = "x86-protected-16:16"
_WIDTH_2_BINDINGS = {
    _ADDRESS_KIND: {
        "endness": archinfo.Endness.LE,
        "loads": {2: "pbr_win16_active_load_u16"},
        "stores": {2: "pbr_win16_active_store_u16"},
    }
}
_WIDTH_10_BINDINGS = {
    _ADDRESS_KIND: {
        "endness": archinfo.Endness.LE,
        "loads": {10: "pbr_win16_active_load_u80"},
        "stores": {10: "pbr_win16_active_store_u80"},
    }
}
_WIDTH_8_BINDINGS = {
    _ADDRESS_KIND: {
        "endness": archinfo.Endness.LE,
        "loads": {8: "pbr_win16_active_load_u64"},
        "stores": {8: "pbr_win16_active_store_u64"},
    }
}
_BYTE_AND_WORD_BINDINGS = {
    _ADDRESS_KIND: {
        "endness": archinfo.Endness.LE,
        "loads": {
            1: "pbr_win16_active_load_u8",
            2: "pbr_win16_active_load_u16",
        },
        "stores": {
            1: "pbr_win16_active_store_u8",
            2: "pbr_win16_active_store_u16",
        },
    }
}


class _DereferenceCollector(CStructuredCodeWalker):
    def __init__(self):
        self.dereferences = []

    def handle_CUnaryOp(self, obj):
        if obj.op == "Dereference":
            self.dereferences.append(obj)
        return super().handle_CUnaryOp(obj)


def _project(code: bytes, function_starts: list[int]):
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    project = angr.load_shellcode(
        code,
        arch=arch,
        load_address=0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    project.simos.name = "Win16"
    cfg = project.analyses.CFGFast(
        function_starts=function_starts,
        regions=[(0, len(code))],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        resolve_indirect_jumps=False,
    )
    return project, cfg


def _set_prototype(project, function, *, returns_value: bool) -> None:
    function.calling_convention = SimCCPCodeX86Win16NearCdecl(project.arch)
    return_type = SimTypeShort(signed=False) if returns_value else SimTypeBottom(label="void")
    function.prototype = SimTypeFunction([], return_type).with_arch(project.arch)
    function.prototype_source = PrototypeSource.SIGNATURES


def _decompile(
    project,
    cfg,
    function,
    segmented_memory_bindings,
    *,
    register_state_bindings=None,
    use_cache: bool = False,
):
    return project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=True,
        use_cache=use_cache,
        update_cache=use_cache,
        register_state_bindings=register_state_bindings,
        segmented_memory_bindings=segmented_memory_bindings,
    )


def _assert_no_c_dereferences(codegen) -> None:
    assert codegen.cfunc is not None
    collector = _DereferenceCollector()
    collector.handle(codegen.cfunc)
    assert collector.dereferences == []


def _compile_and_run_generated_c(tmp_path, text: str, prelude: str, main: str) -> None:
    compiler = shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("A C compiler is required for generated-C execution validation")

    source = tmp_path / "segmented_memory.c"
    executable = tmp_path / "segmented_memory"
    source.write_text(f"{prelude}\n{text}\n{main}\n", encoding="utf-8")
    subprocess.run(
        [
            compiler,
            "-std=c11",
            "-Wall",
            "-Werror",
            "-Wno-unused-variable",
            "-Wno-unused-function",
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


def test_segmented_memory_bindings_are_validated_and_normalized_deterministically():
    bindings = {
        "z-kind": {
            "endness": archinfo.Endness.LE,
            "loads": {2: "z_load_u16", 1: "z_load_u8"},
        },
        "a-kind": {
            "endness": archinfo.Endness.BE,
            "stores": {4: "a_store_u32", 2: "a_store_u16"},
        },
    }

    assert normalize_segmented_memory_bindings(bindings) == (
        ("a-kind", archinfo.Endness.BE, 2, None, "a_store_u16"),
        ("a-kind", archinfo.Endness.BE, 4, None, "a_store_u32"),
        ("z-kind", archinfo.Endness.LE, 1, "z_load_u8", None),
        ("z-kind", archinfo.Endness.LE, 2, "z_load_u16", None),
    )


@pytest.mark.parametrize(
    ("bindings", "exception", "match"),
    (
        ({_ADDRESS_KIND: {"endness": "middle", "loads": {2: "load"}}}, ValueError, "endness"),
        ({_ADDRESS_KIND: {"endness": archinfo.Endness.LE, "loads": {0: "load"}}}, ValueError, "positive"),
        ({_ADDRESS_KIND: {"endness": archinfo.Endness.LE, "loads": {True: "load"}}}, TypeError, "integer"),
        (
            {_ADDRESS_KIND: {"endness": archinfo.Endness.LE, "loads": {2: "load(); exploit"}}},
            ValueError,
            "identifier",
        ),
        (
            {_ADDRESS_KIND: {"endness": archinfo.Endness.LE, "loads": {2: "return"}}},
            ValueError,
            "identifier",
        ),
        (
            {_ADDRESS_KIND: {"endness": archinfo.Endness.LE, "loads": {2: "load_λ"}}},
            ValueError,
            "identifier",
        ),
        (
            {_ADDRESS_KIND: {"endness": archinfo.Endness.LE, "loads": {2: "load"}, "fallback": "native"}},
            ValueError,
            "Unknown",
        ),
    ),
)
def test_segmented_memory_bindings_reject_invalid_abi(bindings, exception, match):
    with pytest.raises(exception, match=match):
        normalize_segmented_memory_bindings(bindings)


def test_bound_protected_mode_load_lowers_to_runtime_helper_without_host_dereference(tmp_path):
    project, cfg = _project(bytes.fromhex("a10010c3"), [0])  # mov ax, word ptr ds:0x1000; ret
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)

    decompilation = _decompile(
        project,
        cfg,
        function,
        _WIDTH_2_BINDINGS,
        register_state_bindings={"ds": "PBR_DS"},
    )

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    snapshot = re.search(r"\b([A-Za-z_]\w*) = PBR_DS;  // ds", text)
    assert snapshot is not None
    assert f"pbr_win16_active_load_u16({snapshot.group(1)}, (unsigned long)0x1000)" in text
    assert "(unsigned short)ds" not in text
    assert decompilation.codegen.unsupported_constructs == ()
    _assert_no_c_dereferences(decompilation.codegen)
    _compile_and_run_generated_c(
        tmp_path,
        text,
        "static unsigned short PBR_DS; "
        "static unsigned short pbr_win16_active_load_u16(unsigned short segment, unsigned long offset) "
        "{ return segment == 0x1234 && offset == 0x1000 ? 0xbeef : 0; }",
        "int main(void) { PBR_DS = 0x1234; return _start() != 0xbeef; }",
    )


def test_bound_protected_mode_store_lowers_to_runtime_helper_without_host_dereference():
    project, cfg = _project(bytes.fromhex("b83412a30010c3"), [0])  # mov ax,0x1234; mov ds:0x1000,ax; ret
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        function,
        _WIDTH_2_BINDINGS,
        register_state_bindings={"ds": "PBR_DS"},
    )

    assert decompilation.codegen is not None
    snapshot = re.search(r"\b([A-Za-z_]\w*) = PBR_DS;  // ds", decompilation.codegen.text)
    assert snapshot is not None
    assert (
        f"pbr_win16_active_store_u16({snapshot.group(1)}, (unsigned long)0x1000, 4660);" in decompilation.codegen.text
    )
    assert "(unsigned short)ds" not in decompilation.codegen.text
    assert decompilation.codegen.unsupported_constructs == ()
    _assert_no_c_dereferences(decompilation.codegen)


def test_bound_protected_mode_tbyte_load_and_store_use_exact_u80_runtime_carrier():
    # fld tbyte ptr ds:0x1000; fstp tbyte ptr ds:0x1010; ret. This byte-only fixture forces both helper calls to
    # survive simplification and proves that the 80-bit payload is not narrowed to a host int.
    project, cfg = _project(bytes.fromhex("db2e0010db3e1010c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        function,
        _WIDTH_10_BINDINGS,
        register_state_bindings={"ds": "PBR_DS"},
    )

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    snapshot = re.search(r"\b([A-Za-z_]\w*) = PBR_DS;  // ds", text)
    assert snapshot is not None
    assert "uint80_t " in text
    assert f"pbr_win16_active_load_u80({snapshot.group(1)}, (unsigned long)0x1000)" in text
    assert f"pbr_win16_active_store_u80({snapshot.group(1)}, (unsigned long)0x1010" in text
    assert "(int)pbr_win16_active_load_u80" not in text
    assert "(uint80_t)" not in text
    assert decompilation.codegen.unsupported_constructs == ()
    _assert_no_c_dereferences(decompilation.codegen)


def test_bound_protected_mode_qword_load_and_store_use_exact_u64_runtime_carrier():
    # fld qword ptr ds:0x1000; fstp qword ptr ds:0x1008; ret.
    project, cfg = _project(bytes.fromhex("dd060010dd1e0810c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        function,
        _WIDTH_8_BINDINGS,
        register_state_bindings={"ds": "PBR_DS"},
    )

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    snapshot = re.search(r"\b([A-Za-z_]\w*) = PBR_DS;  // ds", text)
    assert snapshot is not None
    assert "uint64_t " in text
    assert f"pbr_win16_active_load_u64({snapshot.group(1)}, (unsigned long)0x1000)" in text
    assert f"pbr_win16_active_store_u64({snapshot.group(1)}, (unsigned long)4104" in text
    assert "(uint64_t)v" not in text
    assert decompilation.codegen.unsupported_constructs == ()
    _assert_no_c_dereferences(decompilation.codegen)


def test_proven_ss_parameter_addresses_lower_as_native_c_accesses():
    # A source-free slice from a real Win16 string-comparison routine. REP lowering clones the two BP-relative loads
    # into Reference(stack-vvar) offsets, so the Load nodes themselves no longer retain their variable-map entries.
    code = bytes.fromhex(
        "558bec57561e078b4e08e3268bd98b7e048bf733c0f2aef7d903cb8bfe8b7606"
        "f3a68a44ff33c93a45ff770474044949f7d18bc15e5f8be55dc3"
    )
    project, cfg = _project(code, [0])
    function = cfg.functions[0]
    function.calling_convention = SimCCPCodeX86Win16NearCdecl(project.arch)
    function.prototype = SimTypeFunction(
        [
            SimTypeShort(signed=False),
            SimTypeChar(signed=False),
            SimTypeChar(signed=False),
        ],
        SimTypeShort(signed=False),
    ).with_arch(project.arch)
    function.prototype_source = PrototypeSource.SIGNATURES

    decompilation = _decompile(
        project,
        cfg,
        function,
        _BYTE_AND_WORD_BINDINGS,
        register_state_bindings={"ds": "PBR_DS", "ss": "PBR_SS", "es": "PBR_ES"},
    )

    assert decompilation.codegen is not None
    assert "pbr_win16_active_load_u16(PBR_SS" not in decompilation.codegen.text
    assert "(unsigned long)&a" not in decompilation.codegen.text
    assert "&a1" in decompilation.codegen.text
    assert "&a2" in decompilation.codegen.text
    ds_snapshot = re.search(r"\b([A-Za-z_]\w*) = PBR_DS;  // ds", decompilation.codegen.text)
    assert ds_snapshot is not None
    assert f"pbr_win16_active_load_u8({ds_snapshot.group(1)}" in decompilation.codegen.text
    assert decompilation.codegen.unsupported_constructs == ()


def test_proven_ss_local_load_and_store_remain_native_c_accesses():
    # push bp; mov bp,sp; sub sp,2; mov ax,0x1234; mov [bp-2],ax; mov ax,[bp-2]; leave; ret
    project, cfg = _project(bytes.fromhex("558bec83ec02b834128946fe8b46fe8be55dc3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)

    decompilation = _decompile(
        project,
        cfg,
        function,
        _WIDTH_2_BINDINGS,
        register_state_bindings={"ss": "PBR_SS"},
    )

    assert decompilation.codegen is not None
    assert "pbr_win16_active_" not in decompilation.codegen.text
    assert decompilation.codegen.unsupported_constructs == ()


def test_proven_ss_alias_preserves_overlapping_fpu_stack_storage_widths():
    # Source-free x86-16 fixture: copy SS to ES, store an 80-bit x87 value at
    # ES:[BP-0xe], then store the 14-byte x87 environment at ES:[BP-0x1a].
    # The final environment word overlaps the low two bytes of the uint80_t
    # object and must remain a narrow lvalue view, not overwrite all 80 bits.
    code = bytes.fromhex("558bec83ec1a8cd08ec0d9e826db7ef226d976e68be55dc3")
    project, cfg = _project(code, [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        function,
        _WIDTH_10_BINDINGS,
        register_state_bindings={"ss": "PBR_SS", "es": "PBR_ES"},
    )

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    wide_variable = re.search(r"uint80_t (v\d+);", text)
    assert wide_variable is not None
    assert f"*((unsigned short *)&{wide_variable.group(1)}) =" in text
    assert "pbr_win16_active_store_" not in text
    assert decompilation.codegen.unsupported_constructs == ()


def test_proven_ss_parameter_slice_retains_exact_stack_storage(tmp_path):
    # push bp; mov bp,sp; mov ax,[bp+8]; pop bp; retf 10. Under the far-Pascal ABI, [bp+8] is the high word of the
    # 32-bit fourth argument. SSA rewrites it to Reference(a3)+2, which must remain tied to a3's stack storage.
    project, cfg = _project(bytes.fromhex("558bec8b46085dca0a00"), [0])
    function = cfg.functions[0]
    function.calling_convention = SimCCPCodeX86Win16FarPascal(project.arch)
    function.prototype = SimTypeFunction(
        [
            SimTypeShort(signed=False),
            SimTypeShort(signed=False),
            SimTypeShort(signed=False),
            SimTypeLong(signed=False),
        ],
        SimTypeShort(signed=False),
    ).with_arch(project.arch)
    function.prototype_source = PrototypeSource.SIGNATURES

    decompilation = _decompile(
        project,
        cfg,
        function,
        _WIDTH_2_BINDINGS,
        register_state_bindings={"ss": "PBR_SS"},
    )

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    assert "pbr_win16_active_load_u16" not in text
    assert "(char *)&a3 + 2" in text
    assert decompilation.codegen.unsupported_constructs == ()
    _compile_and_run_generated_c(
        tmp_path,
        text,
        "",
        "int main(void) { return _start(0, 0, 0, 0xbeef1234UL) != 0xbeef; }",
    )


def test_genuine_guest_ss_offset_remains_runtime_checked():
    # mov ax, word ptr ss:[bx]; ret
    project, cfg = _project(bytes.fromhex("368b07c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)

    decompilation = _decompile(
        project,
        cfg,
        function,
        _WIDTH_2_BINDINGS,
        register_state_bindings={"ss": "PBR_SS"},
    )

    assert decompilation.codegen is not None
    snapshot = re.search(r"\b([A-Za-z_]\w*) = PBR_SS;  // ss", decompilation.codegen.text)
    assert snapshot is not None
    assert (
        f"pbr_win16_active_load_u16({snapshot.group(1)}, (unsigned long)(unsigned short)(unsigned long)"
        in decompilation.codegen.text
    )
    assert decompilation.codegen.unsupported_constructs == ()
    _assert_no_c_dereferences(decompilation.codegen)


@pytest.mark.parametrize(
    ("code", "register", "selector"),
    (
        ("8b04c3", "si", "PBR_DS"),  # mov ax, word ptr ds:[si]; ret
        ("268b05c3", "di", "PBR_ES"),  # mov ax, word ptr es:[di]; ret
    ),
)
def test_non_ss_register_offset_uses_machine_width_when_type_recovery_infers_pointer(code, register, selector):
    project, cfg = _project(bytes.fromhex(code), [0])
    function = cfg.functions[0]
    function.calling_convention = SimCCUsercall(
        project.arch,
        [SimRegArg(register, 2)],
        SimRegArg("ax", 2),
    )
    function.prototype = SimTypeFunction(
        [SimTypePointer(SimTypeChar(signed=False))],
        SimTypeShort(signed=False),
    ).with_arch(project.arch)
    function.prototype_source = PrototypeSource.SIGNATURES

    decompilation = _decompile(
        project,
        cfg,
        function,
        _WIDTH_2_BINDINGS,
        register_state_bindings={"ds": "PBR_DS", "es": "PBR_ES"},
    )

    assert decompilation.codegen is not None
    segment_name = selector.removeprefix("PBR_").lower()
    snapshot = re.search(rf"\b([A-Za-z_]\w*) = {selector};  // {segment_name}", decompilation.codegen.text)
    assert snapshot is not None
    assert (
        f"pbr_win16_active_load_u16({snapshot.group(1)}, (unsigned long)(unsigned short)(unsigned long)a0)"
    ) in decompilation.codegen.text
    assert decompilation.codegen.unsupported_constructs == ()
    _assert_no_c_dereferences(decompilation.codegen)


def test_ss_register_offset_with_pointer_type_remains_unsupported():
    project, cfg = _project(bytes.fromhex("368b04c3"), [0])  # mov ax, word ptr ss:[si]; ret
    function = cfg.functions[0]
    function.calling_convention = SimCCUsercall(
        project.arch,
        [SimRegArg("si", 2)],
        SimRegArg("ax", 2),
    )
    function.prototype = SimTypeFunction(
        [SimTypePointer(SimTypeChar(signed=False))],
        SimTypeShort(signed=False),
    ).with_arch(project.arch)
    function.prototype_source = PrototypeSource.SIGNATURES

    decompilation = _decompile(
        project,
        cfg,
        function,
        _WIDTH_2_BINDINGS,
        register_state_bindings={"ss": "PBR_SS"},
    )

    assert decompilation.codegen is not None
    assert "pbr_win16_active_load_u16(PBR_SS" not in decompilation.codegen.text
    assert "/* unsupported AIL statement; see structured diagnostics */" in decompilation.codegen.text
    assert {item.kind for item in decompilation.codegen.unsupported_constructs} >= {
        "segmented_address",
        "unsupported_statement",
    }


def test_ambiguous_host_pointer_as_segment_offset_fails_closed():
    # Build a local's host address in DI, copy SS into ES, then use ES:DI. Without exact selector/provenance tracking,
    # passing the C pointer to the guest runtime as an integer offset is unsound and must make the function ineligible.
    code = bytes.fromhex("558bec83ec0416078d7efcb834122689058be55dc3")
    project, cfg = _project(code, [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        function,
        _WIDTH_2_BINDINGS,
        register_state_bindings={"ss": "PBR_SS", "es": "PBR_ES"},
    )

    assert decompilation.codegen is not None
    assert "pbr_win16_active_store_u16(PBR_ES" not in decompilation.codegen.text
    assert "(unsigned long)&" not in decompilation.codegen.text
    assert "/* unsupported AIL statement; see structured diagnostics */" in decompilation.codegen.text
    assert {item.kind for item in decompilation.codegen.unsupported_constructs} >= {
        "segmented_address",
        "unsupported_statement",
    }


@pytest.mark.parametrize(
    "code",
    (
        "ff160010c3",  # call word ptr ds:0x1000; ret
        "ff55fec3",  # call word ptr ds:[di-2]; ret
    ),
)
def test_segmented_indirect_call_is_structured_ineligible_without_raw_ail_in_c(code):
    project, cfg = _project(bytes.fromhex(code), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        function,
        _WIDTH_2_BINDINGS,
        register_state_bindings={"cs": "PBR_CS", "ds": "PBR_DS", "ss": "PBR_SS"},
    )

    assert decompilation.codegen is not None
    assert "pbr_win16_active_load_u16(" in decompilation.codegen.text
    assert "/* unsupported AIL statement; see structured diagnostics */" in decompilation.codegen.text
    assert "SegmentedAddress" not in decompilation.codegen.text
    assert "x86-protected-16:16" not in decompilation.codegen.text
    assert "vvar_" not in decompilation.codegen.text
    assert {item.kind for item in decompilation.codegen.unsupported_constructs} >= {
        "segmented_address",
        "unsupported_statement",
    }

    restored = type(decompilation.codegen).parse(
        decompilation.codegen.serialize(),
        project=project,
        kb=project.kb,
        func=function,
    )
    assert restored.unsupported_constructs == decompilation.codegen.unsupported_constructs
    assert "SegmentedAddress" not in restored.text
    assert "vvar_" not in restored.text


@pytest.mark.parametrize(
    "bindings",
    (
        None,
        {_ADDRESS_KIND: {"endness": archinfo.Endness.LE, "loads": {1: "pbr_win16_active_load_u8"}}},
        {_ADDRESS_KIND: {"endness": archinfo.Endness.BE, "loads": {2: "pbr_win16_active_load_u16"}}},
    ),
)
def test_unbound_load_binding_width_or_endness_is_structured_unsupported_without_host_dereference(bindings):
    project, cfg = _project(bytes.fromhex("a10010c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)

    decompilation = _decompile(
        project,
        cfg,
        function,
        bindings,
        register_state_bindings={"ds": "PBR_DS"},
    )

    assert decompilation.codegen is not None
    assert any(item.kind == "segmented_address" for item in decompilation.codegen.unsupported_constructs)
    assert "0x10000" not in decompilation.codegen.text
    _assert_no_c_dereferences(decompilation.codegen)

    restored = type(decompilation.codegen).parse(
        decompilation.codegen.serialize(),
        project=project,
        kb=project.kb,
        func=function,
    )
    assert restored.unsupported_constructs == decompilation.codegen.unsupported_constructs
    _assert_no_c_dereferences(restored)


def test_unbound_store_operation_is_structured_unsupported_without_host_dereference():
    project, cfg = _project(bytes.fromhex("b83412a30010c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)
    load_only = {
        _ADDRESS_KIND: {
            "endness": archinfo.Endness.LE,
            "loads": {2: "pbr_win16_active_load_u16"},
        }
    }

    decompilation = _decompile(
        project,
        cfg,
        function,
        load_only,
        register_state_bindings={"ds": "PBR_DS"},
    )

    assert decompilation.codegen is not None
    assert any(item.kind == "segmented_address" for item in decompilation.codegen.unsupported_constructs)
    assert "0x10000" not in decompilation.codegen.text
    _assert_no_c_dereferences(decompilation.codegen)


def test_unbound_tbyte_width_is_structured_unsupported_without_host_dereference():
    project, cfg = _project(bytes.fromhex("db2e0010db3e1010c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        function,
        _WIDTH_2_BINDINGS,
        register_state_bindings={"ds": "PBR_DS"},
    )

    assert decompilation.codegen is not None
    assert any(item.kind == "segmented_address" for item in decompilation.codegen.unsupported_constructs)
    assert "0x10000" not in decompilation.codegen.text
    _assert_no_c_dereferences(decompilation.codegen)


def test_segmented_memory_bindings_roundtrip_through_cache_and_control_cache_identity():
    project, cfg = _project(bytes.fromhex("a10010c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)

    first = _decompile(
        project,
        cfg,
        function,
        _WIDTH_2_BINDINGS,
        register_state_bindings={"ds": "PBR_DS"},
        use_cache=True,
    )
    parsed_cache = DecompilationCache.parse(
        first.cache.serialize(),
        project=project,
        kb=project.kb,
        function=function,
        cfg=cfg.model,
    )

    assert parsed_cache.parameters["segmented_memory_bindings"] == (
        (
            _ADDRESS_KIND,
            archinfo.Endness.LE,
            2,
            "pbr_win16_active_load_u16",
            "pbr_win16_active_store_u16",
        ),
    )
    assert "pbr_win16_active_load_u16" in parsed_cache.codegen.text

    project.kb.decompilations[(function.addr, "pseudocode")] = parsed_cache
    same_binding = _decompile(
        project,
        cfg,
        function,
        _WIDTH_2_BINDINGS,
        register_state_bindings={"ds": "PBR_DS"},
        use_cache=True,
    )
    assert same_binding.clinic is parsed_cache.clinic
    assert "pbr_win16_active_load_u16" in same_binding.codegen.text

    changed_bindings = {
        _ADDRESS_KIND: {
            "endness": archinfo.Endness.LE,
            "loads": {2: "pbr_win16_active_load_u16_alternate"},
            "stores": {2: "pbr_win16_active_store_u16"},
        }
    }
    changed_binding = _decompile(
        project,
        cfg,
        function,
        changed_bindings,
        register_state_bindings={"ds": "PBR_DS"},
        use_cache=True,
    )
    assert changed_binding.clinic is not parsed_cache.clinic
    assert "pbr_win16_active_load_u16_alternate" in changed_binding.codegen.text


@pytest.mark.parametrize(
    ("code", "returns_value"),
    (
        ("5589e583ec02b8341289ec5dc3", False),
        ("5589e58b46045dc3", True),
    ),
)
def test_ss_stack_addresses_remain_semantic_without_breaking_stack_recovery(code, returns_value):
    project, cfg = _project(bytes.fromhex(code), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=returns_value)

    decompilation = _decompile(project, cfg, function, None)

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs == ()
    assert "SegmentedAddress" not in decompilation.codegen.text


@pytest.mark.parametrize(
    "code",
    (
        "9a08000000c39090b80100c3",  # callf 0000:0008; ret; ...; mov ax,1; ret
        "ea08000000909090b80100c3",  # jmpf 0000:0008; ...; mov ax,1; ret
    ),
)
def test_direct_far_transfer_fails_closed_without_runtime_selector_or_host_cast(code):
    project, cfg = _project(bytes.fromhex(code), [0, 8])
    for address in (0, 8):
        _set_prototype(project, cfg.functions[address], returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        cfg.functions[0],
        None,
        register_state_bindings={"cs": "PBR_CS", "sp": "PBR_SP", "ss": "PBR_SS"},
    )

    assert decompilation.codegen is not None
    assert "/* unsupported AIL statement; see structured diagnostics */" in decompilation.codegen.text
    assert "PBR_CS =" not in decompilation.codegen.text
    assert "((void (*)" not in decompilation.codegen.text
    assert any(item.kind == "unsupported_statement" for item in decompilation.codegen.unsupported_constructs)


def test_direct_near_call_remains_an_ordinary_recovered_call():
    # call +2; ret; nop; mov ax,1; ret
    project, cfg = _project(bytes.fromhex("e80200c390b80100c3"), [0, 5])
    for address in (0, 5):
        _set_prototype(project, cfg.functions[address], returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        cfg.functions[0],
        None,
        register_state_bindings={"cs": "PBR_CS", "sp": "PBR_SP", "ss": "PBR_SS"},
    )

    assert decompilation.codegen is not None
    assert "sub_5();" in decompilation.codegen.text
    assert decompilation.codegen.unsupported_constructs == ()
