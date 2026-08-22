from __future__ import annotations

import shutil
import subprocess

import archinfo
import pytest

import angr
from angr.ailment import AILBlockViewer, Expr
from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from angr.analyses.decompiler.far_calls import normalize_far_call_bindings
from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeWalker
from angr.engines.pcode.cc import (
    SimCCPCodeX86Win16FarCdecl,
    SimCCPCodeX86Win16FarPascal,
    SimCCPCodeX86Win16NearCdecl,
)
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.rustylib.ailment import Expression  # pylint:disable=import-error,no-name-in-module
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort

_INTERNAL_BINDINGS = {
    "begin": "guest_far_begin",
    "end": "guest_far_end",
    "internal_targets": {0x10: "SEGMENT_GAME"},
}


class _AILCallCollector(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.calls = []

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        self.calls.append(expr)
        return super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)


class _CCallCollector(CStructuredCodeWalker):
    def __init__(self):
        self.calls = []

    def handle_CFunctionCall(self, obj):
        self.calls.append(obj)
        return super().handle_CFunctionCall(obj)


def _project(
    code: bytes,
    function_starts: list[int],
    *,
    hook_addresses: tuple[int, ...] = (),
    resolve_indirect_jumps: bool = False,
):
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    project = angr.load_shellcode(
        code,
        arch=arch,
        load_address=0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    project.simos.name = "Win16"
    for address in hook_addresses:
        project.hook(address, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())

    regions = [(0, len(code)), *((address, address + 1) for address in hook_addresses)]
    cfg = project.analyses.CFGFast(
        function_starts=[*function_starts, *hook_addresses],
        regions=regions,
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        resolve_indirect_jumps=resolve_indirect_jumps,
    )
    return project, cfg


def _set_prototype(project, function, *, far: bool, args=(), returns_value: bool) -> None:
    function.calling_convention = (
        SimCCPCodeX86Win16FarCdecl(project.arch) if far else SimCCPCodeX86Win16NearCdecl(project.arch)
    )
    return_type = SimTypeShort(signed=False) if returns_value else SimTypeBottom(label="void")
    function.prototype = SimTypeFunction(list(args), return_type).with_arch(project.arch)
    function.prototype_source = PrototypeSource.SIGNATURES


def _decompile(
    project,
    cfg,
    function,
    far_call_bindings,
    *,
    post_call_register_state_bindings=None,
    use_cache: bool = False,
    save_unoptimized_graph: bool = False,
):
    return project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=True,
        use_cache=use_cache,
        update_cache=use_cache,
        far_call_bindings=far_call_bindings,
        post_call_register_state_bindings=post_call_register_state_bindings,
        save_unoptimized_graph=save_unoptimized_graph,
    )


def _direct_call_program(*, returns_value: bool):
    body = bytes.fromhex("9a10000000c3")  # callf 0000:0010; ret
    callee = bytes.fromhex("b83412c3") if returns_value else bytes.fromhex("c3")
    code = body + b"\x90" * (0x10 - len(body)) + callee
    project, cfg = _project(code, [0, 0x10])
    caller = cfg.functions[0]
    target = cfg.functions[0x10]
    target.name = "game_tick" if returns_value else "game_draw"
    _set_prototype(project, caller, far=False, returns_value=returns_value)
    _set_prototype(project, target, far=True, returns_value=returns_value)
    return project, cfg, caller, target


def _ail_calls(graph):
    collector = _AILCallCollector()
    for block in graph:
        collector.walk(block)
    return collector.calls


def _c_calls(codegen):
    assert codegen.cfunc is not None
    collector = _CCallCollector()
    collector.handle(codegen.cfunc)
    return collector.calls


def _compile_generated_c(tmp_path, text: str) -> None:
    compiler = shutil.which("clang")
    if compiler is None:
        pytest.skip("clang is required for generated-C syntax validation")
    header = tmp_path / "guest_runtime.h"
    source = tmp_path / "recovered.c"
    header.write_text(
        "#define SEGMENT_GAME 1u\n"
        "void guest_far_begin(unsigned short segment);\n"
        "void guest_far_end(void);\n"
        "unsigned short game_tick(void);\n",
        encoding="utf-8",
    )
    source.write_text('#include "guest_runtime.h"\n' + text, encoding="utf-8")
    subprocess.run(
        [
            compiler,
            "-std=gnu11",
            "-ffreestanding",
            "-fsyntax-only",
            "-Werror=implicit-function-declaration",
            str(source),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def test_far_call_bindings_are_validated_and_normalized_deterministically():
    bindings = {
        "end": "leave_guest_segment",
        "external_targets": {0x30: "host_user_api"},
        "internal_targets": {0x20: "SEGMENT_B", 0x10: "SEGMENT_A"},
        "begin": "enter_guest_segment",
    }

    assert normalize_far_call_bindings(bindings) == (
        (0x10, "internal", "SEGMENT_A", "enter_guest_segment", "leave_guest_segment"),
        (0x20, "internal", "SEGMENT_B", "enter_guest_segment", "leave_guest_segment"),
        (0x30, "external", "host_user_api", None, None),
    )


@pytest.mark.parametrize(
    ("bindings", "exception", "match"),
    (
        ([], TypeError, "must be a mapping"),
        ({"fallback": "native"}, ValueError, "Unknown"),
        ({"begin": "enter"}, ValueError, "supplied together"),
        ({"internal_targets": {0x10: "SEGMENT_A"}}, ValueError, "require begin and end"),
        (
            {"begin": "enter(); exploit", "end": "leave", "internal_targets": {0x10: "SEGMENT_A"}},
            ValueError,
            "identifier",
        ),
        ({"external_targets": {0x10: "return"}}, ValueError, "identifier"),
        ({"external_targets": {True: "wrapper"}}, TypeError, "integers"),
        ({"external_targets": {-1: "wrapper"}}, ValueError, "unsigned 64-bit"),
        ({"external_targets": {1 << 64: "wrapper"}}, ValueError, "unsigned 64-bit"),
        (
            {
                "begin": "enter",
                "end": "leave",
                "internal_targets": {0x10: "SEGMENT_A"},
                "external_targets": {0x10: "wrapper"},
            },
            ValueError,
            "both internal and external",
        ),
    ),
)
def test_far_call_bindings_reject_ambiguous_or_unsafe_abi(bindings, exception, match):
    with pytest.raises(exception, match=match):
        normalize_far_call_bindings(bindings)


def test_direct_internal_far_call_with_used_result_restores_before_return_and_serializes_kind(tmp_path):
    project, cfg, caller, _ = _direct_call_program(returns_value=True)
    decompilation = _decompile(
        project,
        cfg,
        caller,
        _INTERNAL_BINDINGS,
        save_unoptimized_graph=True,
    )

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    begin = text.index("guest_far_begin(SEGMENT_GAME);")
    call = text.index("game_tick();")
    end = text.index("guest_far_end();")
    returned = text.index("return ")
    assert begin < call < end < returned
    assert "({" not in text
    assert "CS =" not in text and "cs =" not in text
    assert decompilation.codegen.unsupported_constructs == ()

    calls = _ail_calls(decompilation.ail_graph)
    far_call = next(call for call in calls if call.transfer_kind == "far")
    assert isinstance(far_call.target, Expr.Const)
    assert far_call.target.value == 0x10
    assert far_call.tags.get("far_call_direct_segmented", False)
    restored = Expression.from_bytes(far_call.to_bytes())
    assert isinstance(restored, Expr.Call)
    assert restored.transfer_kind == "far"

    _compile_generated_c(tmp_path, text)


def test_direct_internal_void_far_call_has_exact_begin_call_end_scope():
    project, cfg, caller, _ = _direct_call_program(returns_value=False)
    decompilation = _decompile(project, cfg, caller, _INTERNAL_BINDINGS)

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    assert text.index("guest_far_begin(SEGMENT_GAME);") < text.index("game_draw();")
    assert text.index("game_draw();") < text.index("guest_far_end();") < text.index("return;")
    assert decompilation.codegen.unsupported_constructs == ()


def test_internal_far_call_restores_before_post_call_register_effect():
    body = bytes.fromhex("9a1000000089d8c3")  # callf; mov ax,bx; ret
    code = body + b"\x90" * (0x10 - len(body)) + bytes.fromhex("c3")
    project, cfg = _project(code, [0, 0x10])
    caller = cfg.functions[0]
    target = cfg.functions[0x10]
    target.name = "game_update"
    _set_prototype(project, caller, far=False, returns_value=True)
    _set_prototype(project, target, far=True, returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        caller,
        _INTERNAL_BINDINGS,
        post_call_register_state_bindings={("callee_name", "game_update"): {"bx": "POST_BX"}},
    )

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    assert text.index("guest_far_begin(SEGMENT_GAME);") < text.index("game_update();")
    assert text.index("game_update();") < text.index("guest_far_end();") < text.index("POST_BX")
    assert "return POST_BX;" in text


def test_relocated_direct_external_far_call_uses_only_canonical_cfg_target_and_exact_wrapper():
    canonical_target = 0x1234_0020
    code = bytes.fromhex("9a20003412c3")  # callf 1234:0020; ret
    project, cfg = _project(code, [0], hook_addresses=(canonical_target,))
    caller = cfg.functions[0]
    target = cfg.functions[canonical_target]
    target.name = "relocated_user_api"
    _set_prototype(project, caller, far=False, returns_value=True)
    _set_prototype(project, target, far=True, returns_value=True)
    bindings = {
        "begin": "guest_far_begin",
        "end": "guest_far_end",
        "external_targets": {canonical_target: "host_user_api"},
    }

    wrong_address = _decompile(
        project,
        cfg,
        caller,
        {"external_targets": {0x20: "host_user_api"}},
    )
    assert wrong_address.codegen.unsupported_constructs
    assert "host_user_api" not in wrong_address.codegen.text

    decompilation = _decompile(project, cfg, caller, bindings)

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    assert "host_user_api()" in text
    assert "relocated_user_api" not in text
    assert "guest_far_begin" not in text and "guest_far_end" not in text
    assert "0x1234" not in text
    assert "((" not in text
    assert decompilation.codegen.unsupported_constructs == ()

    far_call = next(call for call in _ail_calls(decompilation.ail_graph) if call.transfer_kind == "far")
    assert isinstance(far_call.target, Expr.Const)
    assert far_call.target.value == canonical_target
    assert far_call.tags.get("far_call_direct_segmented", False)


def test_external_far_wrapper_preserves_recovered_arguments_calling_convention_and_return_type():
    body = bytes.fromhex("6834129a2000000083c402c3")  # push 0x1234; callf 0000:0020; add sp,2; ret
    code = body + b"\x90" * (0x20 - len(body)) + bytes.fromhex("c3")
    project, cfg = _project(code, [0, 0x20])
    caller = cfg.functions[0]
    target = cfg.functions[0x20]
    target.name = "imported_api"
    _set_prototype(project, caller, far=False, returns_value=True)
    _set_prototype(
        project,
        target,
        far=True,
        args=(SimTypeShort(signed=False),),
        returns_value=True,
    )

    decompilation = _decompile(
        project,
        cfg,
        caller,
        {"external_targets": {0x20: "host_imported_api"}},
    )

    assert decompilation.codegen is not None
    far_call = next(call for call in _ail_calls(decompilation.ail_graph) if call.transfer_kind == "far")
    assert isinstance(decompilation.clinic.variable_map.calling_convention(far_call), SimCCPCodeX86Win16FarCdecl)
    assert far_call.args is not None and len(far_call.args) == 1

    wrapper_call = next(call for call in _c_calls(decompilation.codegen) if call.callee_target == "host_imported_api")
    assert len(wrapper_call.args) == 1
    assert wrapper_call.callsite_prototype is not None
    assert len(wrapper_call.callsite_prototype.args) == 1
    assert isinstance(wrapper_call.callsite_prototype.returnty, SimTypeShort)
    assert "host_imported_api(" in decompilation.codegen.text
    assert "guest_far_begin" not in decompilation.codegen.text
    assert "((" not in decompilation.codegen.text


def test_external_near_pointer_argument_rejects_proven_native_stack_pointer_with_exact_location():
    # Source-free x86-16 fixture: form a native C stack-object address, pass its
    # stored low word to a direct external CALLF, and clean the cdecl argument.
    body = bytes.fromhex("558bec83ec028d46fe509a2000000083c4028be55dc3")
    code = body + b"\x90" * (0x20 - len(body)) + bytes.fromhex("cb")
    project, cfg = _project(code, [0, 0x20])
    caller = cfg.functions[0]
    target = cfg.functions[0x20]
    target.name = "guest_pointer_api"
    _set_prototype(project, caller, far=False, returns_value=False)
    _set_prototype(
        project,
        target,
        far=True,
        args=(SimTypePointer(SimTypeChar(signed=False)),),
        returns_value=False,
    )

    decompilation = _decompile(
        project,
        cfg,
        caller,
        {"external_targets": {0x20: "host_pointer_api"}},
    )

    assert decompilation.codegen is not None
    assert "host_pointer_api(" not in decompilation.codegen.text
    diagnostic = next(
        item for item in decompilation.codegen.unsupported_constructs if item.kind == "guest_near_pointer_boundary"
    )
    assert diagnostic.operation == "native-stack-pointer-to-16-bit-guest-near-pointer"
    assert diagnostic.count == 1
    assert diagnostic.locations[0].instruction_address == 10
    assert diagnostic.locations[0].block_address == 0


def test_external_near_pointer_argument_allows_an_ordinary_guest_offset():
    body = bytes.fromhex("6834129a2000000083c402c3")
    code = body + b"\x90" * (0x20 - len(body)) + bytes.fromhex("cb")
    project, cfg = _project(code, [0, 0x20])
    caller = cfg.functions[0]
    target = cfg.functions[0x20]
    target.name = "guest_pointer_api"
    _set_prototype(project, caller, far=False, returns_value=False)
    _set_prototype(
        project,
        target,
        far=True,
        args=(SimTypePointer(SimTypeChar(signed=False)),),
        returns_value=False,
    )

    decompilation = _decompile(
        project,
        cfg,
        caller,
        {"external_targets": {0x20: "host_pointer_api"}},
    )

    assert decompilation.codegen is not None
    assert "host_pointer_api(" in decompilation.codegen.text
    assert decompilation.codegen.unsupported_constructs == ()


def test_far_pascal_callsite_resolves_arguments_across_the_complete_return_frame():
    body = bytes.fromhex("6811116822229a20000000c3")  # push 1111; push 2222; callf 0000:0020; ret
    code = body + b"\x90" * (0x20 - len(body)) + bytes.fromhex("ca0400")  # retf 4
    project, cfg = _project(code, [0, 0x20])
    caller = cfg.functions[0]
    target = cfg.functions[0x20]
    target.name = "imported_pascal_api"
    _set_prototype(project, caller, far=False, returns_value=False)
    target.calling_convention = SimCCPCodeX86Win16FarPascal(project.arch)
    target.prototype = SimTypeFunction(
        [SimTypeShort(signed=False), SimTypeShort(signed=False)],
        SimTypeBottom(label="void"),
    ).with_arch(project.arch)
    target.prototype_source = PrototypeSource.SIGNATURES

    decompilation = _decompile(
        project,
        cfg,
        caller,
        {"external_targets": {0x20: "host_imported_pascal_api"}},
    )

    assert decompilation.codegen is not None
    far_call = next(call for call in _ail_calls(decompilation.ail_graph) if call.transfer_kind == "far")
    assert far_call.args is not None
    assert all(isinstance(argument, Expr.VirtualVariable) and argument.was_stack for argument in far_call.args)
    assert [argument.stack_offset for argument in far_call.args] == [-2, -4]
    assert "host_imported_pascal_api(v1, v0);" in decompilation.codegen.text


def test_unmapped_direct_far_call_remains_structured_unsupported_without_host_cast():
    project, cfg, caller, _ = _direct_call_program(returns_value=True)
    wrong_target_bindings = {
        "begin": "guest_far_begin",
        "end": "guest_far_end",
        "internal_targets": {0x11: "SEGMENT_WRONG"},
    }

    decompilation = _decompile(project, cfg, caller, wrong_target_bindings)

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs
    assert "unsupported AIL" in decompilation.codegen.text
    assert "guest_far_begin" not in decompilation.codegen.text
    assert "((" not in decompilation.codegen.text


def test_allowlisted_direct_far_call_without_known_function_remains_unsupported():
    project, cfg, caller, _ = _direct_call_program(returns_value=True)
    initial = _decompile(project, cfg, caller, _INTERNAL_BINDINGS)
    del project.kb.functions[0x10]

    codegen = project.analyses.CStructuredCodeGenerator(
        caller,
        initial.seq_node,
        cfg=cfg.model,
        ail_graph=initial.clinic.graph,
        func_args=initial.clinic.arg_list,
        variable_map=initial.clinic.variable_map,
        far_call_bindings=normalize_far_call_bindings(_INTERNAL_BINDINGS),
    )

    assert codegen.unsupported_constructs
    assert "guest_far_begin" not in codegen.text
    assert "game_tick" not in codegen.text


def test_indirect_far_call_remains_structured_unsupported_even_with_matching_address_binding():
    code = bytearray(b"\x90" * 0x24)
    code[0:5] = bytes.fromhex("ff1e2000c3")  # callf [0x20]; ret
    code[0x10] = 0xC3
    code[0x20:0x24] = bytes.fromhex("10000000")
    project, cfg = _project(bytes(code), [0, 0x10])
    caller = cfg.functions[0]
    target = cfg.functions[0x10]
    _set_prototype(project, caller, far=False, returns_value=False)
    _set_prototype(project, target, far=True, returns_value=False)

    decompilation = _decompile(
        project,
        cfg,
        caller,
        {"external_targets": {0x10: "host_wrapper"}},
    )

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs
    assert "host_wrapper" not in decompilation.codegen.text
    assert "((" not in decompilation.codegen.text
    far_call = next(call for call in _ail_calls(decompilation.ail_graph) if call.transfer_kind == "far")
    assert not isinstance(far_call.target, Expr.Const)


def test_internal_far_call_scopes_remain_ordered_across_multiple_calls():
    body = bytes.fromhex("9a200000009a30000000c3")
    code = body + b"\x90" * (0x20 - len(body)) + bytes.fromhex("c3")
    code += b"\x90" * (0x30 - len(code)) + bytes.fromhex("c3")
    project, cfg = _project(code, [0, 0x20, 0x30])
    caller = cfg.functions[0]
    target_a = cfg.functions[0x20]
    target_b = cfg.functions[0x30]
    target_a.name = "segment_a_tick"
    target_b.name = "segment_b_tick"
    _set_prototype(project, caller, far=False, returns_value=False)
    _set_prototype(project, target_a, far=True, returns_value=False)
    _set_prototype(project, target_b, far=True, returns_value=False)
    bindings = {
        "begin": "guest_far_begin",
        "end": "guest_far_end",
        "internal_targets": {0x20: "SEGMENT_A", 0x30: "SEGMENT_B"},
    }

    decompilation = _decompile(project, cfg, caller, bindings)

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    first_begin = text.index("guest_far_begin(SEGMENT_A);")
    first_call = text.index("segment_a_tick();")
    first_end = text.index("guest_far_end();", first_call)
    second_begin = text.index("guest_far_begin(SEGMENT_B);")
    second_call = text.index("segment_b_tick();")
    second_end = text.index("guest_far_end();", second_call)
    assert first_begin < first_call < first_end < second_begin < second_call < second_end


def test_far_call_bindings_roundtrip_through_cache_and_control_cache_identity():
    project, cfg, caller, _ = _direct_call_program(returns_value=True)
    first = _decompile(project, cfg, caller, _INTERNAL_BINDINGS, use_cache=True)
    parsed_cache = DecompilationCache.parse(
        first.cache.serialize(),
        project=project,
        kb=project.kb,
        function=caller,
        cfg=cfg.model,
    )

    assert parsed_cache.parameters["far_call_bindings"] == (
        (0x10, "internal", "SEGMENT_GAME", "guest_far_begin", "guest_far_end"),
    )
    parsed_text = parsed_cache.codegen.text
    assert parsed_text.index("guest_far_begin(SEGMENT_GAME);") < parsed_text.index("game_tick();")
    assert parsed_text.index("game_tick();") < parsed_text.index("guest_far_end();")

    project.kb.decompilations[(caller.addr, "pseudocode")] = parsed_cache
    same_bindings = _decompile(project, cfg, caller, _INTERNAL_BINDINGS, use_cache=True)
    assert same_bindings.clinic is parsed_cache.clinic
    assert "guest_far_begin(SEGMENT_GAME);" in same_bindings.codegen.text

    changed_bindings = {
        "begin": "guest_far_begin",
        "end": "guest_far_end",
        "internal_targets": {0x10: "SEGMENT_ALTERNATE"},
    }
    changed = _decompile(project, cfg, caller, changed_bindings, use_cache=True)
    assert changed.clinic is not parsed_cache.clinic
    assert "guest_far_begin(SEGMENT_ALTERNATE);" in changed.codegen.text


def test_far_call_bindings_require_c_pseudocode_output():
    project, cfg, caller, _ = _direct_call_program(returns_value=True)
    with pytest.raises(ValueError, match="require C pseudocode"):
        project.analyses.Decompiler(
            caller,
            cfg=cfg.model,
            flavor="rust",
            decompile=False,
            far_call_bindings=_INTERNAL_BINDINGS,
        )
