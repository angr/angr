from __future__ import annotations

import shutil
import subprocess

import archinfo
import pytest

import angr
from angr import ailment
from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from angr.analyses.decompiler.near_calls import normalize_indirect_near_call_bindings
from angr.analyses.decompiler.structurer_nodes import SequenceNode
from angr.engines.pcode.cc import SimCCPCodeX86Win16NearCdecl
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeInt, SimTypeNum, SimTypeShort

_ADDRESS_KIND = "x86-protected-16:16"
_DISPATCHER = "dispatch_near"
_SITE_IDENTIFIER = 0x1234_5678
_C_COMPILER = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")


def _binding(
    *,
    callsite: int = 0,
    selector: str = "cs",
    target: str = "cx",
    site_identifier: int = _SITE_IDENTIFIER,
    dispatcher: str = _DISPATCHER,
):
    return {
        callsite: {
            "dispatcher": dispatcher,
            "address_kind": _ADDRESS_KIND,
            "target_selector_register": selector,
            "target_offset_register": target,
            "site_identifier": site_identifier,
        }
    }


def _project(*, target: str = "cx", prefix: bytes = b""):
    # Source-free x86-16 fixture: an indirect near CALL through one 16-bit
    # register followed by RET. The bytes, not an upstream source program, are
    # the test input.
    call_opcode = {
        "ax": bytes.fromhex("ffd0"),
        "cx": bytes.fromhex("ffd1"),
        "dx": bytes.fromhex("ffd2"),
        "bx": bytes.fromhex("ffd3"),
        "sp": bytes.fromhex("ffd4"),
        "bp": bytes.fromhex("ffd5"),
        "si": bytes.fromhex("ffd6"),
        "di": bytes.fromhex("ffd7"),
    }[target]
    code = prefix + call_opcode + b"\xc3"
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
        function_starts=[0],
        regions=[(0, len(code))],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        resolve_indirect_jumps=True,
    )
    function = cfg.functions[0]
    function.calling_convention = SimCCPCodeX86Win16NearCdecl(arch)
    function.prototype = SimTypeFunction([], SimTypeShort(signed=False)).with_arch(arch)
    function.prototype_source = PrototypeSource.SIGNATURES
    return project, cfg, function


def _decompile(project, cfg, function, bindings, *, use_cache: bool = False):
    return project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=True,
        use_cache=use_cache,
        update_cache=use_cache,
        initial_register_state_bindings={
            "ax": "INITIAL_AX",
            "bx": "INITIAL_BX",
            "cx": "INITIAL_CX",
            "dx": "INITIAL_DX",
            "si": "INITIAL_SI",
            "di": "INITIAL_DI",
        },
        indirect_near_call_bindings=bindings,
    )


def _return_call(graph):
    for block in graph:
        for statement in block.statements:
            if (
                isinstance(statement, ailment.Stmt.Return)
                and statement.ret_exprs
                and isinstance(statement.ret_exprs[0], ailment.Expr.Call)
            ):
                return statement.ret_exprs[0]
    raise AssertionError("no returned call in AIL graph")


def test_indirect_near_call_bindings_normalize_exact_register_ranges_and_sort_callsites():
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    cs = arch.registers["cs"]
    cx = arch.registers["cx"]
    dx = arch.registers["dx"]

    bindings = {
        7: _binding(callsite=7, target="dx", site_identifier=9)[7],
        3: _binding(callsite=3, target="cx", site_identifier=5)[3],
    }
    assert normalize_indirect_near_call_bindings(arch, bindings) == (
        (3, _DISPATCHER, _ADDRESS_KIND, *cs, *cx, 5),
        (7, _DISPATCHER, _ADDRESS_KIND, *cs, *dx, 9),
    )
    assert normalize_indirect_near_call_bindings(arch, None) == ()


@pytest.mark.parametrize(
    ("bindings", "exception", "match"),
    (
        ([], TypeError, "must be a mapping"),
        ({True: _binding()[0]}, TypeError, "callsites must be integers"),
        ({-1: _binding()[0]}, ValueError, "unsigned 64-bit"),
        ({1 << 64: _binding()[0]}, ValueError, "unsigned 64-bit"),
        ({0: []}, TypeError, "must be a mapping"),
        ({0: {**_binding()[0], "fallback": "native"}}, ValueError, "Unknown"),
        ({0: {key: value for key, value in _binding()[0].items() if key != "dispatcher"}}, ValueError, "Missing"),
        ({0: {**_binding()[0], "dispatcher": None}}, TypeError, "dispatcher.*string"),
        ({0: {**_binding()[0], "dispatcher": "bad();"}}, ValueError, "identifier"),
        ({0: {**_binding()[0], "address_kind": None}}, TypeError, "address_kind.*string"),
        ({0: {**_binding()[0], "address_kind": "x86-real-16:16"}}, ValueError, "address_kind"),
        ({0: {**_binding()[0], "target_selector_register": None}}, TypeError, "register-name string"),
        ({0: {**_binding()[0], "target_selector_register": "ds"}}, ValueError, "must be 'cs'"),
        ({0: {**_binding()[0], "target_offset_register": None}}, TypeError, "register-name string"),
        ({0: {**_binding()[0], "target_offset_register": "not_a_register"}}, KeyError, "Unknown register"),
        ({0: {**_binding()[0], "target_offset_register": "eax"}}, ValueError, "must be one of"),
        ({0: {**_binding()[0], "target_offset_register": "cs"}}, ValueError, "must be one of"),
        ({0: {**_binding()[0], "target_offset_register": "sp"}}, ValueError, "must be one of"),
        ({0: {**_binding()[0], "target_offset_register": "bp"}}, ValueError, "must be one of"),
        ({0: {**_binding()[0], "target_offset_register": "ip"}}, ValueError, "must be one of"),
        ({0: {**_binding()[0], "site_identifier": True}}, TypeError, "site_identifier.*integer"),
        ({0: {**_binding()[0], "site_identifier": None}}, TypeError, "site_identifier.*integer"),
        ({0: {**_binding()[0], "site_identifier": -1}}, ValueError, "unsigned 32-bit"),
        ({0: {**_binding()[0], "site_identifier": 1 << 32}}, ValueError, "unsigned 32-bit"),
    ),
)
def test_indirect_near_call_bindings_reject_malformed_or_ambiguous_rows(bindings, exception, match):
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    with pytest.raises(exception, match=match):
        normalize_indirect_near_call_bindings(arch, bindings)


def test_exact_call_cx_becomes_a_u16_dispatcher_return_with_a_sealed_site():
    project, cfg, function = _project()
    decompilation = _decompile(project, cfg, function, _binding())

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs == ()
    assert f"return {_DISPATCHER}(INITIAL_CX, 305419896);" in decompilation.codegen.text
    assert "(*" not in decompilation.codegen.text

    dispatcher = _return_call(decompilation.ail_graph)
    assert dispatcher.target == _DISPATCHER
    assert dispatcher.bits == 16
    assert dispatcher.transfer_kind == "near"
    assert tuple(argument.bits for argument in dispatcher.args) == (16, 32)
    assert isinstance(dispatcher.args[1], ailment.Expr.Const)
    assert dispatcher.args[1].value == _SITE_IDENTIFIER
    assert dispatcher.tags["ins_addr"] == 0
    assert dispatcher.tags["indirect_near_call_dispatch"] is True
    assert dispatcher.tags["indirect_near_call_binding_authoritative"] is True
    assert dispatcher.tags["indirect_near_call_address_kind"] == _ADDRESS_KIND
    assert dispatcher.tags["indirect_near_call_selector_register"] == project.arch.registers["cs"][0]
    assert dispatcher.tags["indirect_near_call_selector_register_size"] == 2
    assert dispatcher.tags["indirect_near_call_target_register"] == project.arch.registers["cx"][0]
    assert dispatcher.tags["indirect_near_call_target_register_size"] == 2
    assert dispatcher.tags["indirect_near_call_site_identifier"] == _SITE_IDENTIFIER

    runtime_prototype = decompilation.clinic.variable_map.prototype(dispatcher)
    assert runtime_prototype is not None
    assert isinstance(runtime_prototype.returnty, (SimTypeChar, SimTypeInt, SimTypeNum))
    assert runtime_prototype.returnty.signed is False
    assert runtime_prototype.returnty.size == 16
    assert tuple(argument_type.size for argument_type in runtime_prototype.args) == (16, 32)
    assert all(argument_type.signed is False for argument_type in runtime_prototype.args)
    assert decompilation.clinic.variable_map.calling_convention(dispatcher) is None


@pytest.mark.parametrize("machine_target", ("ax", "bx", "cx", "dx", "si", "di"))
def test_each_allowed_non_stack_gpr_preserves_its_guest_value(machine_target):
    project, cfg, function = _project(target=machine_target)
    decompilation = _decompile(project, cfg, function, _binding(target=machine_target))

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs == ()
    assert f"{_DISPATCHER}(INITIAL_{machine_target.upper()}," in decompilation.codegen.text


def test_non_block_start_callsite_is_matched_at_the_instruction_address():
    prefix = bytes.fromhex("b95634")  # MOV CX,0x3456
    project, cfg, function = _project(prefix=prefix)
    decompilation = _decompile(project, cfg, function, _binding(callsite=len(prefix), site_identifier=0x27EB))

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs == ()
    assert decompilation.codegen.text.count(f"{_DISPATCHER}(") == 1
    dispatcher = _return_call(decompilation.ail_graph)
    assert all(isinstance(argument, ailment.Expr.Const) for argument in dispatcher.args)
    assert tuple(argument.value for argument in dispatcher.args) == (0x3456, 0x27EB)
    assert dispatcher.tags["ins_addr"] == len(prefix)
    assert dispatcher.tags["indirect_near_call_site_identifier"] == 0x27EB


@pytest.mark.parametrize(
    ("machine_target", "bindings"),
    (
        ("cx", _binding(callsite=1)),
        ("dx", _binding(target="cx")),
    ),
)
def test_wrong_callsite_or_target_register_cannot_authorize_the_call(machine_target, bindings):
    project, cfg, function = _project(target=machine_target)
    decompilation = _decompile(project, cfg, function, bindings)

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs
    assert any(item.kind == "segmented_address" for item in decompilation.codegen.unsupported_constructs)
    assert _DISPATCHER not in decompilation.codegen.text
    original = _return_call(decompilation.ail_graph)
    assert isinstance(original.target, ailment.Expr.SegmentedAddress)
    assert not original.tags.get("indirect_near_call_dispatch", False)


def test_exact_target_matcher_rejects_a_non_cs_selector_even_with_the_right_offset_register():
    project, cfg, function = _project()
    decompilation = _decompile(project, cfg, function, _binding())
    cs_offset, cs_size = project.arch.registers["cs"]
    ds_offset, ds_size = project.arch.registers["ds"]
    cx_offset, cx_size = project.arch.registers["cx"]
    wrong_selector = ailment.Expr.SegmentedAddress(
        1,
        ailment.Expr.Register(2, ds_offset, ds_size * project.arch.byte_width, ins_addr=0),
        ailment.Expr.Register(3, cx_offset, cx_size * project.arch.byte_width, ins_addr=0),
        _ADDRESS_KIND,
        bits=32,
        ins_addr=0,
        segment_register="ds",
    )

    assert not decompilation.clinic._matches_indirect_near_call_target(
        wrong_selector,
        {},
        callsite=0,
        address_kind=_ADDRESS_KIND,
        selector_offset=cs_offset,
        selector_size=cs_size,
        target_offset=cx_offset,
        target_size=cx_size,
    )


@pytest.mark.parametrize("machine_target", ("sp", "bp"))
def test_stack_and_frame_register_calls_remain_unsupported_instead_of_becoming_host_addresses(machine_target):
    project, cfg, function = _project(target=machine_target)
    unbound = _decompile(project, cfg, function, {})

    assert unbound.codegen is not None
    assert unbound.codegen.unsupported_constructs
    assert _DISPATCHER not in unbound.codegen.text
    with pytest.raises(ValueError, match="not safe dynamic near-call carriers"):
        _decompile(project, cfg, function, _binding(target=machine_target))


@pytest.mark.parametrize("forged_target", ("sp", "bp", "cs", "ip"))
def test_codegen_independently_rejects_a_forged_non_carrier_target_range(forged_target):
    project, cfg, function = _project()
    decompilation = _decompile(project, cfg, function, _binding())
    return_statement = decompilation.seq_node.nodes[0].statements[0].copy()
    dispatcher = return_statement.ret_exprs[0].copy()
    forged_tags = dispatcher.tags
    forged_tags["indirect_near_call_target_register"] = project.arch.registers[forged_target][0]
    dispatcher.tags = forged_tags
    return_statement.ret_exprs = [dispatcher]
    block = decompilation.seq_node.nodes[0].copy()
    block.statements = [return_statement]

    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(decompilation.seq_node.addr, nodes=[block]),
        variable_map=decompilation.clinic.variable_map,
    )
    assert codegen.unsupported_constructs
    assert _DISPATCHER not in codegen.text


def test_codegen_independently_rejects_a_forged_selector_or_site_argument():
    project, cfg, function = _project()
    decompilation = _decompile(project, cfg, function, _binding())

    for forge_selector in (True, False):
        return_statement = decompilation.seq_node.nodes[0].statements[0].copy()
        dispatcher = return_statement.ret_exprs[0].copy()
        if forge_selector:
            forged_tags = dispatcher.tags
            forged_tags["indirect_near_call_selector_register"] = project.arch.registers["ds"][0]
            dispatcher.tags = forged_tags
        else:
            arguments = list(dispatcher.args)
            arguments[1] = ailment.Expr.Const(0xCAFE, _SITE_IDENTIFIER + 1, 32, ins_addr=0)
            dispatcher.args = arguments
        return_statement.ret_exprs = [dispatcher]
        block = decompilation.seq_node.nodes[0].copy()
        block.statements = [return_statement]

        codegen = project.analyses.CStructuredCodeGenerator(
            function,
            SequenceNode(decompilation.seq_node.addr, nodes=[block]),
            variable_map=decompilation.clinic.variable_map,
        )
        assert codegen.unsupported_constructs
        assert _DISPATCHER not in codegen.text


def test_indirect_near_call_bindings_roundtrip_through_clinic_and_cache_and_control_cache_identity():
    project, cfg, function = _project()
    bindings = _binding()
    normalized = normalize_indirect_near_call_bindings(project.arch, bindings)
    first = _decompile(project, cfg, function, bindings, use_cache=True)

    clinic = type(first.clinic).parse(
        first.clinic.serialize(),
        project=project,
        kb=project.kb,
        function=function,
        cfg=cfg.model,
    )
    assert clinic.indirect_near_call_bindings == normalized

    parsed = DecompilationCache.parse(
        first.cache.serialize(),
        project=project,
        kb=project.kb,
        function=function,
        cfg=cfg.model,
    )
    assert parsed.parameters["indirect_near_call_bindings"] == normalized
    assert parsed.clinic.indirect_near_call_bindings == normalized
    assert _DISPATCHER in parsed.codegen.text

    project.kb.decompilations[(function.addr, "pseudocode")] = parsed
    same = _decompile(project, cfg, function, bindings, use_cache=True)
    assert same.clinic is parsed.clinic

    changed = _decompile(
        project,
        cfg,
        function,
        _binding(site_identifier=_SITE_IDENTIFIER + 1),
        use_cache=True,
    )
    assert changed.clinic is not parsed.clinic
    assert str(_SITE_IDENTIFIER + 1) in changed.codegen.text


@pytest.mark.skipif(_C_COMPILER is None, reason="a native C compiler is required")
def test_generated_dispatcher_c_compiles_and_executes(tmp_path):
    project, cfg, function = _project()
    decompilation = _decompile(project, cfg, function, _binding())
    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs == ()

    source = tmp_path / "near_dispatch.c"
    executable = tmp_path / "near_dispatch"
    source.write_text(
        "#include <stdint.h>\n"
        "#define _start lifted_entry\n"
        "#define INITIAL_CX ((unsigned short)0x4ace)\n"
        "static unsigned short dispatch_near(unsigned short target, uint32_t site)\n"
        "{\n"
        "    return target == 0x4ace && site == UINT32_C(0x12345678) ? 0xbeef : 0;\n"
        "}\n"
        f"{decompilation.codegen.text}\n"
        "int main(void)\n"
        "{\n"
        "    return lifted_entry() == 0xbeef ? 0 : 1;\n"
        "}\n"
    )
    assert _C_COMPILER is not None
    build = subprocess.run(
        [_C_COMPILER, "-std=c11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(executable)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    run = subprocess.run([executable], capture_output=True, check=False)
    assert run.returncode == 0, run.stderr.decode(errors="replace")


def test_indirect_near_call_bindings_require_c_pseudocode_output():
    project, cfg, function = _project()
    with pytest.raises(ValueError, match="require C pseudocode"):
        project.analyses.Decompiler(
            function,
            cfg=cfg.model,
            flavor="rust",
            decompile=False,
            indirect_near_call_bindings=_binding(),
        )
