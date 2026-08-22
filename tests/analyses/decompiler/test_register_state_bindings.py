from __future__ import annotations

import re
import shutil
import subprocess

import archinfo
import pytest

import angr
from angr import ailment
from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from angr.analyses.decompiler.register_state import (
    normalize_initial_register_state_bindings,
    normalize_post_call_register_state_bindings,
    normalize_register_state_bindings,
)
from angr.engines.pcode.cc import SimCCPCodeX86Win16NearCdecl
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeShort


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
    register_state_bindings,
    *,
    initial_register_state_bindings=None,
    post_call_register_state_bindings=None,
    segmented_memory_bindings=None,
    indirect_far_call_bindings=None,
    use_cache: bool = False,
):
    return project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=True,
        use_cache=use_cache,
        update_cache=use_cache,
        register_state_bindings=register_state_bindings,
        initial_register_state_bindings=initial_register_state_bindings,
        post_call_register_state_bindings=post_call_register_state_bindings,
        segmented_memory_bindings=segmented_memory_bindings,
        indirect_far_call_bindings=indirect_far_call_bindings,
    )


def _compile_and_run_generated_c(tmp_path, text: str, prelude: str, main: str) -> None:
    compiler = shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("A C compiler is required for generated-C execution validation")

    source = tmp_path / "register_state.c"
    executable = tmp_path / "register_state"
    source.write_text(f"{prelude}\n{text}\n{main}\n", encoding="utf-8")
    subprocess.run(
        [
            compiler,
            "-std=c11",
            "-Wall",
            "-Werror",
            "-Wno-unused-variable",
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


def _call_then(readback: bytes):
    body = bytes.fromhex("e80d00") + readback + bytes.fromhex("c3")
    code = body + b"\x90" * (0x10 - len(body)) + bytes.fromhex("c3")
    project, cfg = _project(code, [0, 0x10])
    caller = cfg.functions[0]
    callee = cfg.functions[0x10]
    callee.name = "selected_api"
    _set_prototype(project, caller, returns_value=True)
    _set_prototype(project, callee, returns_value=False)
    return project, cfg, caller


@pytest.mark.parametrize(
    ("register", "readback"),
    (
        ("ax", b""),
        ("bx", bytes.fromhex("89d8")),
        ("cx", bytes.fromhex("89c8")),
        ("dx", bytes.fromhex("89d0")),
        ("si", bytes.fromhex("89f0")),
        ("di", bytes.fromhex("89f8")),
    ),
)
def test_post_call_register_state_binding_supplies_selected_16bit_register_outputs(register, readback):
    project, cfg, caller = _call_then(readback)
    identifier = f"POST_{register.upper()}"

    decompilation = _decompile(
        project,
        cfg,
        caller,
        None,
        post_call_register_state_bindings={("callee_name", "selected_api"): {register: identifier}},
    )

    assert decompilation.codegen is not None
    assert "selected_api();" in decompilation.codegen.text
    assert f"return {identifier};" in decompilation.codegen.text
    assert decompilation.codegen.text.index("selected_api();") < decompilation.codegen.text.index(identifier)


@pytest.mark.parametrize(
    ("readback", "fragments"),
    (
        (bytes.fromhex("88e0"), ("POST_AX & 0xff00", "POST_AX >> 8 & 0xff")),  # mov al, ah
        (bytes.fromhex("88c4"), ("POST_AX & 0xff", "POST_AX & 0xff")),  # mov ah, al
    ),
)
def test_post_call_register_state_binding_preserves_aliases_during_partial_writes(readback, fragments):
    project, cfg, caller = _call_then(readback)

    decompilation = _decompile(
        project,
        cfg,
        caller,
        None,
        post_call_register_state_bindings={("callee_name", "selected_api"): {"ax": "POST_AX"}},
    )

    assert decompilation.codegen is not None
    assert all(fragment in decompilation.codegen.text for fragment in fragments), decompilation.codegen.text
    assert "// al" not in decompilation.codegen.text
    assert "// ah" not in decompilation.codegen.text


def test_post_call_register_state_binding_is_ignored_after_a_later_machine_definition():
    project, cfg, caller = _call_then(bytes.fromhex("bb341289d8"))  # mov bx, 0x1234; mov ax, bx

    decompilation = _decompile(
        project,
        cfg,
        caller,
        None,
        post_call_register_state_bindings={("callee_name", "selected_api"): {"bx": "POST_BX"}},
    )

    assert decompilation.codegen is not None
    assert "return 4660;" in decompilation.codegen.text
    assert "POST_BX" not in decompilation.codegen.text


def test_post_call_register_state_binding_overrides_a_pre_call_machine_definition():
    body = bytes.fromhex("bb3412e80a0089d8c3")  # mov bx, 0x1234; call 0x10; mov ax, bx; ret
    project, cfg = _project(body + b"\x90" * (0x10 - len(body)) + bytes.fromhex("c3"), [0, 0x10])
    caller = cfg.functions[0]
    callee = cfg.functions[0x10]
    callee.name = "selected_api"
    _set_prototype(project, caller, returns_value=True)
    _set_prototype(project, callee, returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        caller,
        None,
        post_call_register_state_bindings={("callee_name", "selected_api"): {"bx": "POST_BX"}},
    )

    assert decompilation.codegen is not None
    assert "return POST_BX;" in decompilation.codegen.text
    assert "4660" not in decompilation.codegen.text


@pytest.mark.parametrize("selector", (("callee_addr", 0x10), ("callsite_addr", 0)))
def test_post_call_register_state_binding_supports_exact_address_selectors(selector):
    project, cfg, caller = _call_then(bytes.fromhex("89d8"))

    decompilation = _decompile(
        project,
        cfg,
        caller,
        None,
        post_call_register_state_bindings={selector: {"bx": "POST_BX"}},
    )

    assert decompilation.codegen is not None
    assert "return POST_BX;" in decompilation.codegen.text


def test_post_call_register_state_effects_preserve_callsite_argument_recovery():
    # push 0x1234; call 0x10; add sp, 2; mov ax, bx; ret
    body = bytes.fromhex("683412e80a0083c40289d8c3")
    project, cfg = _project(body + b"\x90" * (0x10 - len(body)) + bytes.fromhex("c3"), [0, 0x10])
    caller = cfg.functions[0]
    callee = cfg.functions[0x10]
    callee.name = "selected_api"
    _set_prototype(project, caller, returns_value=True)
    callee.calling_convention = SimCCPCodeX86Win16NearCdecl(project.arch)
    callee.prototype = SimTypeFunction([SimTypeShort(signed=False)], SimTypeBottom(label="void")).with_arch(
        project.arch
    )
    callee.prototype_source = PrototypeSource.SIGNATURES

    decompilation = _decompile(
        project,
        cfg,
        caller,
        None,
        post_call_register_state_bindings={("callee_name", "selected_api"): {"bx": "POST_BX"}},
    )

    assert decompilation.codegen is not None
    assert "= 4660;" in decompilation.codegen.text
    assert "selected_api(" in decompilation.codegen.text
    assert "return POST_BX;" in decompilation.codegen.text


def test_one_call_can_define_all_win16_general_purpose_register_outputs():
    # call selected_api; push di/si/dx/cx/bx/ax; call sink; add sp, 12; ret
    body = bytes.fromhex("e82d00575652515350e8340083c40cc3")
    code = body + b"\x90" * (0x30 - len(body)) + b"\xc3" + b"\x90" * 0x0F + b"\xc3"
    project, cfg = _project(code, [0, 0x30, 0x40])
    caller = cfg.functions[0]
    selected = cfg.functions[0x30]
    sink = cfg.functions[0x40]
    selected.name = "selected_api"
    sink.name = "sink"
    _set_prototype(project, caller, returns_value=False)
    _set_prototype(project, selected, returns_value=False)
    sink.calling_convention = SimCCPCodeX86Win16NearCdecl(project.arch)
    sink.prototype = SimTypeFunction(
        [SimTypeShort(signed=False) for _ in range(6)], SimTypeBottom(label="void")
    ).with_arch(project.arch)
    sink.prototype_source = PrototypeSource.SIGNATURES
    identifiers = {register: f"POST_{register.upper()}" for register in ("ax", "bx", "cx", "dx", "si", "di")}

    decompilation = _decompile(
        project,
        cfg,
        caller,
        None,
        post_call_register_state_bindings={("callee_name", "selected_api"): identifiers},
    )

    assert decompilation.codegen is not None
    assert "selected_api();" in decompilation.codegen.text
    assert "sink(" in decompilation.codegen.text
    for identifier in identifiers.values():
        assert identifier in decompilation.codegen.text
        assert decompilation.codegen.text.index("selected_api();") < decompilation.codegen.text.index(identifier)


def test_post_call_register_state_binding_does_not_guess_an_indirect_callee_identity():
    # mov bx, 0x10; call bx; mov ax, cx; ret
    body = bytes.fromhex("bb1000ffd389c8c3")
    project, cfg = _project(body + b"\x90" * (0x10 - len(body)) + bytes.fromhex("c3"), [0, 0x10])
    caller = cfg.functions[0]
    callee = cfg.functions[0x10]
    callee.name = "selected_api"
    _set_prototype(project, caller, returns_value=True)
    _set_prototype(project, callee, returns_value=False)

    by_name = _decompile(
        project,
        cfg,
        caller,
        None,
        post_call_register_state_bindings={("callee_name", "selected_api"): {"cx": "POST_CX"}},
    )
    assert by_name.codegen is not None
    assert "POST_CX" not in by_name.codegen.text
    assert "unsupported AIL statement" in by_name.codegen.text


def test_post_call_register_state_bindings_validate_selectors_identifiers_and_overlaps():
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")

    with pytest.raises(ValueError, match="Unknown post-call"):
        normalize_post_call_register_state_bindings(arch, {("callee", "api"): {"ax": "POST_AX"}})
    with pytest.raises(TypeError, match="callee_addr selector values must be integers"):
        normalize_post_call_register_state_bindings(arch, {("callee_addr", "0x10"): {"ax": "POST_AX"}})
    with pytest.raises(ValueError, match="must be C identifiers"):
        normalize_post_call_register_state_bindings(arch, {("callee_name", "api"): {"ax": "task->ax"}})
    with pytest.raises(ValueError, match="must not overlap"):
        normalize_post_call_register_state_bindings(
            arch,
            {("callee_name", "api"): {"ax": "POST_AX", "al": "POST_AL"}},
        )

    project, cfg, caller = _call_then(b"")
    with pytest.raises(ValueError, match="Matching post_call_register_state_bindings ranges must not overlap"):
        _decompile(
            project,
            cfg,
            caller,
            None,
            post_call_register_state_bindings={
                ("callee_name", "selected_api"): {"ax": "POST_AX"},
                ("callsite_addr", 0): {"ax": "POST_AX_AT_SITE"},
            },
        )


def test_post_call_register_state_bindings_compose_with_initial_and_exact_ambient_state():
    project, cfg, caller = _call_then(bytes.fromhex("89d8"))

    decompilation = _decompile(
        project,
        cfg,
        caller,
        None,
        initial_register_state_bindings={"bx": "INITIAL_BX"},
        post_call_register_state_bindings={("callee_name", "selected_api"): {"bx": "POST_BX"}},
    )
    assert decompilation.codegen is not None
    assert "return POST_BX;" in decompilation.codegen.text
    assert "INITIAL_BX" not in decompilation.codegen.text

    ambient = _decompile(
        project,
        cfg,
        caller,
        {"bx": "MACHINE_BX"},
        post_call_register_state_bindings={("callee_name", "selected_api"): {"bx": "POST_BX"}},
    )
    assert ambient.codegen is not None
    snapshot = re.search(r"\b([A-Za-z_]\w*) = POST_BX;", ambient.codegen.text)
    assert snapshot is not None
    assert f"MACHINE_BX = {snapshot.group(1)};" in ambient.codegen.text
    assert f"return {snapshot.group(1)};" in ambient.codegen.text

    with pytest.raises(ValueError, match="must be disjoint or exactly equal"):
        _decompile(
            project,
            cfg,
            caller,
            {"bx": "MACHINE_BX"},
            post_call_register_state_bindings={("callee_name", "selected_api"): {"bl": "POST_BL"}},
        )


def test_post_call_register_state_bindings_roundtrip_through_cache_and_control_cache_identity():
    project, cfg, caller = _call_then(bytes.fromhex("89d8"))
    bindings = {("callee_name", "selected_api"): {"bx": "POST_BX"}}

    first = _decompile(
        project,
        cfg,
        caller,
        None,
        post_call_register_state_bindings=bindings,
        use_cache=True,
    )
    parsed_cache = DecompilationCache.parse(
        first.cache.serialize(),
        project=project,
        kb=project.kb,
        function=caller,
        cfg=cfg.model,
    )
    expected = normalize_post_call_register_state_bindings(project.arch, bindings)

    assert parsed_cache.parameters["post_call_register_state_bindings"] == expected
    assert parsed_cache.clinic.post_call_register_state_bindings == expected
    assert "return POST_BX;" in parsed_cache.codegen.text

    project.kb.decompilations[(caller.addr, "pseudocode")] = parsed_cache
    same_binding = _decompile(
        project,
        cfg,
        caller,
        None,
        post_call_register_state_bindings=bindings,
        use_cache=True,
    )
    assert same_binding.clinic is parsed_cache.clinic
    assert "return POST_BX;" in same_binding.codegen.text

    no_binding = _decompile(project, cfg, caller, None, use_cache=True)
    assert no_binding.clinic is not parsed_cache.clinic
    assert "POST_BX" not in no_binding.codegen.text


@pytest.mark.parametrize(
    ("register_name", "code", "c_lvalue"),
    (
        ("es", "8cc0c3", "PBR_ES"),
        ("cs", "8cc8c3", "PBR_CS"),
        ("ss", "8cd0c3", "PBR_SS"),
        ("ds", "8cd8c3", "PBR_DS"),
    ),
)
def test_bound_segment_register_read_snapshots_external_lvalue(register_name, code, c_lvalue):
    project, cfg = _project(bytes.fromhex(code), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)

    decompilation = _decompile(project, cfg, function, {register_name: c_lvalue})

    assert decompilation.codegen is not None
    snapshot = re.search(rf"\b([A-Za-z_]\w*) = {re.escape(c_lvalue)};  // {register_name}", decompilation.codegen.text)
    assert snapshot is not None
    assert f"return {snapshot.group(1)};" in decompilation.codegen.text


def test_register_state_binding_is_opt_in_and_accepts_exact_storage_key():
    project, cfg = _project(bytes.fromhex("8cd8c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)

    unbound = _decompile(project, cfg, function, None)
    bound = _decompile(project, cfg, function, {(262, 2): "machine->ds"})

    assert unbound.codegen is not None and bound.codegen is not None
    assert "// ds" in unbound.codegen.text
    assert "machine->ds" not in unbound.codegen.text
    snapshot = re.search(r"\b([A-Za-z_]\w*) = machine->ds;  // ds", bound.codegen.text)
    assert snapshot is not None
    assert f"return {snapshot.group(1)};" in bound.codegen.text


def test_register_state_binding_rejects_ambiguous_overlapping_storage():
    arch = archinfo.ArchPcode("x86:LE:32:default")

    with pytest.raises(ValueError, match="must not overlap"):
        normalize_register_state_bindings(arch, {"eax": "machine->eax", "ax": "machine->ax"})


def test_write_only_bound_register_state_survives_simplification():
    project, cfg = _project(bytes.fromhex("b834128ed8c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)

    decompilation = _decompile(project, cfg, function, {"ds": "PBR_DS"})

    assert decompilation.codegen is not None
    snapshot = re.search(r"\b([A-Za-z_]\w*) = 4660;", decompilation.codegen.text)
    assert snapshot is not None
    assert f"PBR_DS = {snapshot.group(1)};" in decompilation.codegen.text


def test_pcode_segment_register_stack_swap_preserves_both_values(tmp_path):
    # Source-free x86-16 fixture: push es; push ds; pop es; pop ds; ret.
    project, cfg = _project(bytes.fromhex("061e071fc3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        function,
        {"ds": "PBR_DS", "es": "PBR_ES", "ss": "PBR_SS"},
    )

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    saved_es = re.search(r"\b([A-Za-z_]\w*) = PBR_ES;", text)
    saved_ds = re.search(r"\b([A-Za-z_]\w*) = PBR_DS;", text)
    assert saved_es is not None and saved_ds is not None
    assert saved_es.group(1) != saved_ds.group(1)
    assert "PBR_ES = " in text
    assert "PBR_DS = " in text
    _compile_and_run_generated_c(
        tmp_path,
        text,
        "static unsigned short PBR_DS, PBR_ES, PBR_SS;",
        "int main(void) { PBR_DS = 0x1234; PBR_ES = 0xabcd; PBR_SS = 0x7777; _start(); "
        "return PBR_DS != 0xabcd || PBR_ES != 0x1234; }",
    )


@pytest.mark.parametrize(
    ("code", "preserved_mask", "source_expression", "expected"),
    (
        ("88d8c3", "{ax} & 0xff00", "{bx} & 0xff", 0xAB34),  # mov al, bl; ret
        ("88fcc3", "{ax} & 0xff", "{bx} >> 8 & 0xff", 0x12CD),  # mov ah, bh; ret
    ),
)
def test_containing_register_state_bindings_cover_subregister_reads_and_partial_writes(
    code, preserved_mask, source_expression, expected, tmp_path
):
    project, cfg = _project(bytes.fromhex(code), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)

    decompilation = _decompile(project, cfg, function, {"ax": "PBR_AX", "bx": "PBR_BX"})

    assert decompilation.codegen is not None
    ax_snapshot = re.search(r"\b([A-Za-z_]\w*) = PBR_AX;", decompilation.codegen.text)
    bx_snapshot = re.search(r"\b([A-Za-z_]\w*) = PBR_BX;", decompilation.codegen.text)
    assert ax_snapshot is not None and bx_snapshot is not None
    assert preserved_mask.format(ax=ax_snapshot.group(1), bx=bx_snapshot.group(1)) in decompilation.codegen.text
    assert source_expression.format(ax=ax_snapshot.group(1), bx=bx_snapshot.group(1)) in decompilation.codegen.text
    assert "PBR_AX = " in decompilation.codegen.text
    assert "// al" not in decompilation.codegen.text
    assert "// ah" not in decompilation.codegen.text
    assert "// bl" not in decompilation.codegen.text
    assert "// bh" not in decompilation.codegen.text
    _compile_and_run_generated_c(
        tmp_path,
        decompilation.codegen.text,
        "static unsigned short PBR_AX, PBR_BX;",
        f"int main(void) {{ PBR_AX = 0xabcd; PBR_BX = 0x1234; "
        f"return _start() != {expected} || PBR_AX != {expected}; }}",
    )


@pytest.mark.parametrize(
    ("register", "opcode"),
    (
        ("cx", "91"),
        ("dx", "92"),
        ("bx", "93"),
        ("si", "96"),
        ("di", "97"),
    ),
)
def test_bound_general_purpose_register_versions_execute_xchg_atomically(register, opcode, tmp_path):
    # Source-free x86-16 fixture: xchg ax, <register>; ret.
    project, cfg = _project(bytes.fromhex(opcode + "c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)
    other_lvalue = f"M_{register.upper()}"

    decompilation = _decompile(project, cfg, function, {"ax": "M_AX", register: other_lvalue})

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    ax_snapshot = re.search(r"\b([A-Za-z_]\w*) = M_AX;", text)
    other_snapshot = re.search(rf"\b([A-Za-z_]\w*) = {other_lvalue};", text)
    assert ax_snapshot is not None and other_snapshot is not None
    assert ax_snapshot.group(1) != other_snapshot.group(1)
    assert f"M_AX = {other_lvalue};" not in text
    assert f"{other_lvalue} = M_AX;" not in text
    _compile_and_run_generated_c(
        tmp_path,
        text,
        f"static unsigned short M_AX, {other_lvalue};",
        f"int main(void) {{ M_AX = 0x1234; {other_lvalue} = 0xabcd; _start(); "
        f"return M_AX != 0xabcd || {other_lvalue} != 0x1234; }}",
    )


def test_bound_carry_state_keeps_prior_ssa_version_through_adc(tmp_path):
    # Source-free x86-16 fixture: cmp si, di; adc ax, bx; ret.
    project, cfg = _project(bytes.fromhex("3bf711d8c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)
    bindings = {register: f"M_{register.upper()}" for register in ("ax", "bx", "si", "di", "cf")}

    decompilation = _decompile(project, cfg, function, bindings)

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    carry_snapshot = re.search(r"\b([A-Za-z_]\w*) = [^;]*<[^;]*;\n    M_CF = \1;", text)
    assert carry_snapshot is not None
    assert text.count("M_CF = ") == 3
    # The ADC result and its flags consume the local carry from CMP, never an ambient lvalue already overwritten by
    # another statement from the ADC instruction.
    assert text.count(carry_snapshot.group(1)) >= 4
    _compile_and_run_generated_c(
        tmp_path,
        text,
        "static unsigned short M_AX, M_BX, M_SI, M_DI; static unsigned char M_CF;",
        "int main(void) { M_AX = 0xffff; M_BX = 0; M_SI = 1; M_DI = 2; M_CF = 0; _start(); "
        "return M_AX != 0 || M_CF != 1; }",
    )


def test_bound_carry_state_keeps_segmented_load_definition_for_scasb(tmp_path):
    # Source-free x86-16 fixture: scasb; ret. Preserving the otherwise-dead CF definition must also preserve the
    # temporary segmented load that it consumes; retaining only the CF assignment leaves a dangling dirty vvar.
    project, cfg = _project(b"\x90" * 0x10 + bytes.fromhex("aec3"), [0x10])
    function = cfg.functions[0x10]
    _set_prototype(project, function, returns_value=False)
    bindings = {register: f"M_{register.upper()}" for register in ("ax", "di", "cf", "df", "es")}

    decompilation = _decompile(
        project,
        cfg,
        function,
        bindings,
        segmented_memory_bindings={
            "x86-protected-16:16": {
                "endness": "Iend_LE",
                "loads": {1: "load8"},
                "stores": {1: "store8"},
            }
        },
    )

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    loaded_value = re.search(r"\b([A-Za-z_]\w*) = load8\([^;]+\);", text)
    assert loaded_value is not None
    assert re.search(rf"< {re.escape(loaded_value.group(1))};\n    M_CF = ", text)
    assert "unsupported instruction" not in text
    _compile_and_run_generated_c(
        tmp_path,
        text,
        "static unsigned short M_AX, M_DI, M_ES; static unsigned char M_CF, M_DF; "
        "static unsigned char load8(unsigned short segment, unsigned long offset) "
        "{ (void)segment; (void)offset; return 7; }",
        "int main(void) { M_AX = 5; M_DI = 10; M_ES = 0; M_CF = 0; M_DF = 0; sub_10(); "
        "return M_DI != 11 || M_CF != 1; }",
    )


def test_repne_scasb_carries_bound_counter_and_index_across_iterations(tmp_path):
    # Source-free x86-16 fixture: repne scasb; ret. The p-code lifter represents the repeated instruction as a
    # single-block loop with an in-block side exit. CX and DI must therefore receive entry/backedge phis instead of
    # reading their entry snapshots on every iteration.
    project, cfg = _project(b"\x90" * 0x10 + bytes.fromhex("f2aec3"), [0x10])
    function = cfg.functions[0x10]
    _set_prototype(project, function, returns_value=False)
    bindings = {register: f"M_{register.upper()}" for register in ("ax", "cx", "di", "cf", "df", "es")}

    decompilation = _decompile(
        project,
        cfg,
        function,
        bindings,
        segmented_memory_bindings={
            "x86-protected-16:16": {
                "endness": "Iend_LE",
                "loads": {1: "load8"},
                "stores": {1: "store8"},
            }
        },
    )

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    assert re.search(r"\b([A-Za-z_]\w*) -= 1;\n\s*M_CX = \1;", text)
    assert re.search(r"\b([A-Za-z_]\w*) = \1 \+ 1 - 2 \* \w+;\n\s*M_DI = \1;", text)
    _compile_and_run_generated_c(
        tmp_path,
        text,
        "static unsigned short M_AX, M_CX, M_DI, M_ES; static unsigned char M_CF, M_DF; "
        "static unsigned int load_count; "
        "static unsigned char load8(unsigned short segment, unsigned long offset) "
        "{ (void)segment; (void)offset; ++load_count; return load_count <= 6 ? 7 : 5; }",
        "int main(void) { M_AX = 5; M_CX = 2; M_DI = 10; M_DF = 0; sub_10(); "
        "return M_CX != 0 || M_DI != 12 || load_count != 4; }",
    )


def test_ambient_write_through_sequence_keeps_conditional_braces(tmp_path):
    # Source-free x86-16 loop: compare SI/DI, decrement DI twice, load CX, conditionally increment AX, and repeat.
    # Lowering the one conditional AX definition into local+ambient assignments must keep both inside the branch.
    body = bytes.fromhex("3bf773094f4f8b0de3f640ebf3c3")
    project, cfg = _project(b"\x90" * 0x10 + body, [0x10])
    function = cfg.functions[0x10]
    _set_prototype(project, function, returns_value=True)
    bindings = {register: f"M_{register.upper()}" for register in ("ax", "cx", "si", "di", "cf", "df", "ds")}

    decompilation = _decompile(
        project,
        cfg,
        function,
        bindings,
        segmented_memory_bindings={
            "x86-protected-16:16": {
                "endness": "Iend_LE",
                "loads": {2: "load16"},
                "stores": {2: "store16"},
            }
        },
    )

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    assert ", ," not in text
    assert re.search(r"if \([^\n]+\)\n\s*\{\n\s*\w+ \+= 1;\n\s*M_AX = \w+;\n\s*\}", text)
    _compile_and_run_generated_c(
        tmp_path,
        text,
        "static unsigned short M_AX, M_CX, M_SI, M_DI, M_DS; static unsigned char M_CF, M_DF; "
        "static unsigned short load16(unsigned short segment, unsigned long offset) "
        "{ (void)segment; (void)offset; return 1; }",
        "int main(void) { M_AX = 2; M_SI = 0; M_DI = 2; M_DF = 0; sub_10(); "
        "return M_AX != 3 || M_DI != 0 || M_CX != 1; }",
    )


def test_multistatement_expression_flattens_ambient_write_throughs(tmp_path):
    # Source-free x86-16 fixture: inc bx; inc cx; ret. Reuse its recovered assignments in the same
    # MultiStatementExpression shape emitted by structuring; each assignment lowers to local+ambient writes.
    project, cfg = _project(bytes.fromhex("4341c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)

    decompilation = _decompile(project, cfg, function, {"bx": "M_BX", "cx": "M_CX"})

    assert decompilation.codegen is not None
    assignments = [
        stmt
        for block in decompilation.clinic.graph
        for stmt in block.statements
        if isinstance(stmt, ailment.Stmt.Assignment)
        and isinstance(stmt.dst, ailment.Expr.VirtualVariable)
        and stmt.dst.was_reg
    ]
    assert len(assignments) == 2
    expression = ailment.Expr.MultiStatementExpression(
        decompilation.clinic._ail_manager.next_atom(),
        assignments,
        ailment.Expr.Const(decompilation.clinic._ail_manager.next_atom(), 1, 1),
    )
    expression_text = decompilation.codegen._handle(expression).c_repr()

    assert ", ," not in expression_text
    assert expression_text.count(",") == 4
    assert expression_text.index("M_BX = ") < expression_text.index("M_CX = ")
    local_names = sorted(set(re.findall(r"\bv\d+\b", expression_text)))
    assert local_names
    _compile_and_run_generated_c(
        tmp_path,
        f"static int run_expression(void) {{ unsigned short {', '.join(local_names)}; "
        f"{'; '.join(f'{name} = 0' for name in local_names)}; return {expression_text}; }}",
        "static unsigned short M_BX, M_CX;",
        "int main(void) { return run_expression() != 1 || M_BX != 1 || M_CX != 1; }",
    )


def test_bound_direction_flag_write_is_mirrored_from_local_snapshot(tmp_path):
    # Source-free x86-16 fixture: std; ret.
    project, cfg = _project(bytes.fromhex("fdc3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)

    decompilation = _decompile(project, cfg, function, {"df": "M_DF"})

    assert decompilation.codegen is not None
    value = re.search(r"\b([A-Za-z_]\w*) = 1;", decompilation.codegen.text)
    assert value is not None
    assert f"M_DF = {value.group(1)};" in decompilation.codegen.text
    _compile_and_run_generated_c(
        tmp_path,
        decompilation.codegen.text,
        "static unsigned char M_DF;",
        "int main(void) { M_DF = 0; _start(); return M_DF != 1; }",
    )


def test_bound_call_result_is_evaluated_once_and_written_through(tmp_path):
    # Source-free x86-16 fixtures: caller is `call 0x20; ret`; callee returns 0x1234 in AX.
    code = bytes.fromhex("e81d00c3") + b"\x90" * 0x1C + bytes.fromhex("b83412c3")
    project, cfg = _project(code, [0, 0x20])
    caller = cfg.functions[0]
    callee = cfg.functions[0x20]
    _set_prototype(project, caller, returns_value=True)
    _set_prototype(project, callee, returns_value=True)
    bindings = {register: f"M_{register.upper()}" for register in ("ax", "bx", "cx", "dx", "si", "di")}

    decompilation = _decompile(project, cfg, caller, bindings)

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    assert text.count("sub_20()") == 1
    result = re.search(r"\b([A-Za-z_]\w*) = sub_20\(\);", text)
    assert result is not None
    assert f"M_AX = {result.group(1)};" in text
    assert f"return {result.group(1)};" in text
    _compile_and_run_generated_c(
        tmp_path,
        text,
        "static unsigned short M_AX, M_BX, M_CX, M_DX, M_SI, M_DI; "
        "static unsigned int call_count; "
        "unsigned short sub_20(void) { ++call_count; return 0xbeef; }",
        "int main(void) { return _start() != 0xbeef || M_AX != 0xbeef || call_count != 1; }",
    )


def test_post_call_ambient_reloads_snapshot_before_simultaneous_writes(tmp_path):
    # Source-free x86-16 fixtures: call 0x20; xchg ax, bx; ret. The runtime stub models the callee's ambient writes.
    code = bytes.fromhex("e81d0093c3") + b"\x90" * 0x1B + bytes.fromhex("c3")
    project, cfg = _project(code, [0, 0x20])
    caller = cfg.functions[0]
    callee = cfg.functions[0x20]
    _set_prototype(project, caller, returns_value=False)
    _set_prototype(project, callee, returns_value=False)

    decompilation = _decompile(project, cfg, caller, {"ax": "M_AX", "bx": "M_BX"})

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    ax_reload = re.search(r"\b([A-Za-z_]\w*) = M_AX;", text)
    bx_reload = re.search(r"\b([A-Za-z_]\w*) = M_BX;", text)
    assert ax_reload is not None and bx_reload is not None
    call_position = text.index("sub_20();")
    assert call_position < text.index(ax_reload.group(0))
    assert call_position < text.index(bx_reload.group(0))
    _compile_and_run_generated_c(
        tmp_path,
        text,
        "static unsigned short M_AX, M_BX; void sub_20(void) { M_AX = 0x1234; M_BX = 0xabcd; }",
        "int main(void) { _start(); return M_AX != 0xabcd || M_BX != 0x1234; }",
    )


def test_bound_si_di_state_crosses_a_direct_recovered_call(tmp_path):
    # Source-free x86-16 fixtures: set SI=DI=0x0886, call 0x20, return; callee returns SI in AX.
    caller_body = bytes.fromhex("be8608bf8608e81700c3")
    code = caller_body + b"\x90" * (0x20 - len(caller_body)) + bytes.fromhex("89f0c3")
    project, cfg = _project(code, [0, 0x20])
    caller = cfg.functions[0]
    callee = cfg.functions[0x20]
    _set_prototype(project, caller, returns_value=True)
    _set_prototype(project, callee, returns_value=True)
    bindings = {register: f"M_{register.upper()}" for register in ("ax", "bx", "cx", "dx", "si", "di")}

    caller_decompilation = _decompile(project, cfg, caller, bindings)
    callee_decompilation = _decompile(project, cfg, callee, bindings)

    assert caller_decompilation.codegen is not None and callee_decompilation.codegen is not None
    caller_text = caller_decompilation.codegen.text
    callee_text = callee_decompilation.codegen.text
    assert caller_text.index("M_SI = ") < caller_text.index("sub_20()")
    assert caller_text.index("M_DI = ") < caller_text.index("sub_20()")
    assert "= M_SI;  // si" in callee_text
    _compile_and_run_generated_c(
        tmp_path,
        callee_text + "\n" + caller_text,
        "static unsigned short M_AX, M_BX, M_CX, M_DX, M_SI, M_DI;",
        "int main(void) { return _start() != 0x0886 || M_SI != 0x0886 || M_DI != 0x0886 || M_AX != 0x0886; }",
    )


def test_ambient_entry_loop_phis_are_initialized_once_from_external_state(tmp_path):
    # Entry is also a loop header: cmp si,di; jae exit; sub di,4; inspect/call previous far-pointer entry; loop; ret.
    # This is the exact source-free instruction sequence that exposed the stale DI split in the Bang fixture.
    code = b"\x90" * 0x10 + bytes.fromhex("3bf7730e83ef048b050b450274f2ff1debeec3")
    project, cfg = _project(code, [0x10])
    function = cfg.functions[0x10]
    _set_prototype(project, function, returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        function,
        {"si": "M_SI", "di": "M_DI", "ds": "M_DS"},
        segmented_memory_bindings={
            "x86-protected-16:16": {
                "endness": "Iend_LE",
                "loads": {2: "load16"},
                "stores": {2: "store16"},
            }
        },
        indirect_far_call_bindings={
            0x1E: {
                "dispatcher": "dispatch_far_slot",
                "address_kind": "x86-protected-16:16",
                "slot_selector_register": "ds",
                "slot_offset_register": "di",
                "register_inputs": (),
            }
        },
    )

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    assert text.count("= M_SI;  // si") == 1
    assert text.count("= M_DI;  // di") == 1
    assert re.search(r"\b([A-Za-z_]\w*) -= 4;\n\s*M_DI = \1;", text)
    assert re.search(r"load16\([^,]+, \(unsigned long\)\(\w+ \+ 2\)\)", text)
    assert decompilation.codegen.unsupported_constructs == ()
    _compile_and_run_generated_c(
        tmp_path,
        text,
        "static unsigned short M_SI, M_DI, M_DS; "
        "static unsigned int load_count, address_mismatch, far_call_count; "
        "static unsigned short load16(unsigned short segment, unsigned long offset) "
        "{ static const unsigned short expected[] = {4, 6, 0, 2}; "
        "if (segment != 0x1234 || load_count >= 4 || offset != expected[load_count]) address_mismatch = 1; "
        "++load_count; return 0; } "
        "static void dispatch_far_slot(unsigned short segment, unsigned short offset) "
        "{ (void)segment; (void)offset; ++far_call_count; }",
        "int main(void) { M_SI = 0; M_DI = 8; M_DS = 0x1234; sub_10(); "
        "return M_DI != 0 || load_count != 4 || address_mismatch || far_call_count; }",
    )


def test_bound_register_state_flows_from_caller_to_callee():
    code = bytes.fromhex("b834128ed8e80800c3") + b"\x90" * 7 + bytes.fromhex("8cd8c3")
    project, cfg = _project(code, [0, 0x10])
    caller = cfg.functions[0]
    callee = cfg.functions[0x10]
    _set_prototype(project, caller, returns_value=True)
    _set_prototype(project, callee, returns_value=True)

    caller_decompilation = _decompile(project, cfg, caller, {"ds": "PBR_DS"})
    callee_decompilation = _decompile(project, cfg, callee, {"ds": "PBR_DS"})

    assert caller_decompilation.codegen is not None and callee_decompilation.codegen is not None
    written_value = re.search(r"\b([A-Za-z_]\w*) = 4660;", caller_decompilation.codegen.text)
    assert written_value is not None
    assert f"PBR_DS = {written_value.group(1)};" in caller_decompilation.codegen.text
    assert "return sub_10();" in caller_decompilation.codegen.text
    assert caller_decompilation.codegen.text.index(
        f"PBR_DS = {written_value.group(1)};"
    ) < caller_decompilation.codegen.text.index("return sub_10();")
    callee_snapshot = re.search(r"\b([A-Za-z_]\w*) = PBR_DS;", callee_decompilation.codegen.text)
    assert callee_snapshot is not None
    assert f"return {callee_snapshot.group(1)};" in callee_decompilation.codegen.text


def test_bound_register_state_is_conservatively_invalidated_from_callee_to_caller():
    code = bytes.fromhex("e80d008cd8c3") + b"\x90" * 10 + bytes.fromhex("b834128ed8c3")
    project, cfg = _project(code, [0, 0x10])
    caller = cfg.functions[0]
    callee = cfg.functions[0x10]
    _set_prototype(project, caller, returns_value=True)
    _set_prototype(project, callee, returns_value=True)

    caller_decompilation = _decompile(project, cfg, caller, {"ds": "PBR_DS"})
    callee_decompilation = _decompile(project, cfg, callee, {"ds": "PBR_DS"})

    assert caller_decompilation.codegen is not None and callee_decompilation.codegen is not None
    assert "sub_10();" in caller_decompilation.codegen.text
    reload = re.search(r"\b([A-Za-z_]\w*) = PBR_DS;", caller_decompilation.codegen.text)
    assert reload is not None
    assert f"return {reload.group(1)};" in caller_decompilation.codegen.text
    assert caller_decompilation.codegen.text.index("sub_10();") < caller_decompilation.codegen.text.index(
        reload.group(0)
    )
    callee_value = re.search(r"\b([A-Za-z_]\w*) = 4660;", callee_decompilation.codegen.text)
    assert callee_value is not None
    assert f"PBR_DS = {callee_value.group(1)};" in callee_decompilation.codegen.text


def test_register_state_bindings_roundtrip_through_cache_and_control_cache_identity():
    project, cfg = _project(bytes.fromhex("8cd8c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)

    first = _decompile(project, cfg, function, {"ds": "PBR_DS"}, use_cache=True)
    parsed_cache = DecompilationCache.parse(
        first.cache.serialize(),
        project=project,
        kb=project.kb,
        function=function,
        cfg=cfg.model,
    )

    assert parsed_cache.parameters["register_state_bindings"] == ((262, 2, "PBR_DS"),)
    assert parsed_cache.clinic.register_state_bindings == ((262, 2, "PBR_DS"),)
    assert "= PBR_DS;  // ds" in parsed_cache.codegen.text

    project.kb.decompilations[(function.addr, "pseudocode")] = parsed_cache
    same_binding = _decompile(project, cfg, function, {"ds": "PBR_DS"}, use_cache=True)
    assert same_binding.clinic is parsed_cache.clinic
    assert "= PBR_DS;  // ds" in same_binding.codegen.text

    no_binding = _decompile(project, cfg, function, None, use_cache=True)
    assert no_binding.clinic is not parsed_cache.clinic
    assert "PBR_DS" not in no_binding.codegen.text
    assert "// ds" in no_binding.codegen.text


def test_initial_register_state_binding_substitutes_only_the_entry_value():
    project, cfg = _project(bytes.fromhex("89d8c3"), [0])  # mov ax, bx; ret
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)

    decompilation = _decompile(
        project,
        cfg,
        function,
        None,
        initial_register_state_bindings={"bx": "PBR_INITIAL_BX"},
    )

    assert decompilation.codegen is not None
    assert "return PBR_INITIAL_BX;" in decompilation.codegen.text
    assert "// bx" not in decompilation.codegen.text


def test_initial_register_state_bindings_initialize_mutable_entry_loop_phis_source_free():
    # cmp si,di; jae exit; sub di,4; inspect/call the preceding far-pointer table entry; loop; ret. The function
    # entry is also the loop header, so SI and DI each need an external-entry input in addition to the backedge.
    code = bytes.fromhex("3bf7730e83ef048b050b450274f2ff1debeec3")
    project, cfg = _project(code, [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        function,
        None,
        initial_register_state_bindings={"si": "PBR_INITIAL_SI", "di": "PBR_INITIAL_DI"},
        use_cache=True,
    )

    assert decompilation.codegen is not None
    assert re.search(r"unsigned short \w+ = PBR_INITIAL_SI;  // si", decompilation.codegen.text)
    assert re.search(r"unsigned short \w+ = PBR_INITIAL_DI;  // di", decompilation.codegen.text)
    assert decompilation.codegen.text.count("PBR_INITIAL_SI") == 1
    assert decompilation.codegen.text.count("PBR_INITIAL_DI") == 1

    parsed_cache = DecompilationCache.parse(
        decompilation.cache.serialize(),
        project=project,
        kb=project.kb,
        function=function,
        cfg=cfg.model,
    )
    assert " = PBR_INITIAL_SI;  // si" in parsed_cache.codegen.text
    assert " = PBR_INITIAL_DI;  // di" in parsed_cache.codegen.text

    unbound = _decompile(project, cfg, function, None)
    assert unbound.codegen is not None
    assert "PBR_INITIAL_" not in unbound.codegen.text


@pytest.mark.parametrize(
    ("code", "preserved_mask", "source_expression"),
    (
        ("88d8c3", "PBR_INITIAL_AX & 0xff00", "PBR_INITIAL_BX & 0xff"),  # mov al, bl; ret
        ("88fcc3", "PBR_INITIAL_AX & 0xff", "PBR_INITIAL_BX >> 8 & 0xff"),  # mov ah, bh; ret
    ),
)
def test_initial_register_state_binding_handles_subregister_reads_and_partial_writes(
    code, preserved_mask, source_expression
):
    project, cfg = _project(bytes.fromhex(code), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)

    decompilation = _decompile(
        project,
        cfg,
        function,
        None,
        initial_register_state_bindings={"ax": "PBR_INITIAL_AX", "bx": "PBR_INITIAL_BX"},
    )

    assert decompilation.codegen is not None
    assert preserved_mask in decompilation.codegen.text
    assert source_expression in decompilation.codegen.text
    assert "// al" not in decompilation.codegen.text
    assert "// ah" not in decompilation.codegen.text
    assert "// bl" not in decompilation.codegen.text
    assert "// bh" not in decompilation.codegen.text


def test_initial_register_state_binding_is_ignored_after_definition():
    project, cfg = _project(bytes.fromhex("bb341289d8c3"), [0])  # mov bx, 0x1234; mov ax, bx; ret
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)

    decompilation = _decompile(
        project,
        cfg,
        function,
        None,
        initial_register_state_bindings={"bx": "PBR_INITIAL_BX"},
    )

    assert decompilation.codegen is not None
    assert "return 4660;" in decompilation.codegen.text
    assert "PBR_INITIAL_BX" not in decompilation.codegen.text


def test_initial_register_state_binding_obeys_call_preservation_rules():
    # Near cdecl clobbers CX but preserves BX. The callee body defines neither register.
    caller_saved_code = bytes.fromhex("e80d0089c8c3") + b"\x90" * 10 + bytes.fromhex("b83412c3")
    callee_saved_code = bytes.fromhex("e80d0089d8c3") + b"\x90" * 10 + bytes.fromhex("b83412c3")

    for code, register, identifier, should_survive in (
        (caller_saved_code, "cx", "PBR_INITIAL_CX", False),
        (callee_saved_code, "bx", "PBR_INITIAL_BX", True),
    ):
        project, cfg = _project(code, [0, 0x10])
        caller = cfg.functions[0]
        callee = cfg.functions[0x10]
        _set_prototype(project, caller, returns_value=True)
        _set_prototype(project, callee, returns_value=True)

        decompilation = _decompile(
            project,
            cfg,
            caller,
            None,
            initial_register_state_bindings={register: identifier},
        )

        assert decompilation.codegen is not None
        assert (identifier in decompilation.codegen.text) is should_survive
        if should_survive:
            assert f"return {identifier};" in decompilation.codegen.text
        else:
            assert f"// {register}" in decompilation.codegen.text


def test_initial_register_state_bindings_do_not_change_stack_frame_recovery():
    code = bytes.fromhex("5589e583ec02b8341289ec5dc3")
    unbound_project, unbound_cfg = _project(code, [0])
    unbound_function = unbound_cfg.functions[0]
    _set_prototype(unbound_project, unbound_function, returns_value=True)
    bound_project, bound_cfg = _project(code, [0])
    bound_function = bound_cfg.functions[0]
    _set_prototype(bound_project, bound_function, returns_value=True)

    unbound = _decompile(unbound_project, unbound_cfg, unbound_function, None)
    bound = _decompile(
        bound_project,
        bound_cfg,
        bound_function,
        None,
        initial_register_state_bindings={"ax": "PBR_INITIAL_AX", "bx": "PBR_INITIAL_BX"},
    )

    assert unbound.codegen is not None and bound.codegen is not None
    assert bound.codegen.text == unbound.codegen.text
    assert "return 4660;" in bound.codegen.text


def test_initial_register_state_bindings_require_identifiers_and_must_not_overlap_ambient_bindings():
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    with pytest.raises(ValueError, match="must be C identifiers"):
        normalize_initial_register_state_bindings(arch, {"ax": "machine->ax"})

    project, cfg = _project(bytes.fromhex("89d8c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)
    with pytest.raises(ValueError, match="must not overlap"):
        _decompile(
            project,
            cfg,
            function,
            {"ax": "PBR_TASK->ax"},
            initial_register_state_bindings={"al": "PBR_INITIAL_AL"},
        )


def test_initial_register_state_bindings_roundtrip_through_cache_and_control_cache_identity():
    project, cfg = _project(bytes.fromhex("89d8c3"), [0])
    function = cfg.functions[0]
    _set_prototype(project, function, returns_value=True)

    first = _decompile(
        project,
        cfg,
        function,
        None,
        initial_register_state_bindings={"bx": "PBR_INITIAL_BX"},
        use_cache=True,
    )
    parsed_cache = DecompilationCache.parse(
        first.cache.serialize(),
        project=project,
        kb=project.kb,
        function=function,
        cfg=cfg.model,
    )

    assert parsed_cache.parameters["initial_register_state_bindings"] == ((12, 2, "PBR_INITIAL_BX"),)
    assert parsed_cache.clinic.initial_register_state_bindings == ((12, 2, "PBR_INITIAL_BX"),)
    assert "return PBR_INITIAL_BX;" in parsed_cache.codegen.text

    project.kb.decompilations[(function.addr, "pseudocode")] = parsed_cache
    same_binding = _decompile(
        project,
        cfg,
        function,
        None,
        initial_register_state_bindings={"bx": "PBR_INITIAL_BX"},
        use_cache=True,
    )
    assert same_binding.clinic is parsed_cache.clinic
    assert "return PBR_INITIAL_BX;" in same_binding.codegen.text

    no_binding = _decompile(project, cfg, function, None, use_cache=True)
    assert no_binding.clinic is not parsed_cache.clinic
    assert "PBR_INITIAL_BX" not in no_binding.codegen.text
    assert "// bx" in no_binding.codegen.text
