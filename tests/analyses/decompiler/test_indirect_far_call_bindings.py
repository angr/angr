from __future__ import annotations

import re
import shutil
import subprocess

import archinfo
import networkx
import pytest

import angr
from angr import ailment
from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from angr.analyses.decompiler.far_calls import normalize_indirect_far_call_bindings
from angr.analyses.decompiler.structurer_nodes import SequenceNode
from angr.analyses.decompiler.variable_map import VariableMap
from angr.engines.pcode.cc import SimCCPCodeX86Win16NearCdecl
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import (
    SimTypeBottom,
    SimTypeChar,
    SimTypeFunction,
    SimTypeInt,
    SimTypeNum,
    SimTypePointer,
    SimTypeShort,
)
from angr.sim_variable import SimStackVariable

_ADDRESS_KIND = "x86-protected-16:16"
_SLOT_OFFSET = 0x20
_DISPATCHER = "dispatch_far_slot"
_TRAP = "trap_far_slot"


def _binding(
    *,
    callsite: int = 0,
    selector: str = "ss",
    slot_offset: int = _SLOT_OFFSET,
    slot_offset_register: str | None = None,
    site_identifier: int | None = None,
    inputs=("ax", "bx", "cx"),
    dispatcher: str = _DISPATCHER,
):
    row = {
        "dispatcher": dispatcher,
        "address_kind": _ADDRESS_KIND,
        "slot_selector_register": selector,
        "register_inputs": inputs,
    }
    if slot_offset_register is None:
        row["slot_offset"] = slot_offset
    else:
        row["slot_offset_register"] = slot_offset_register
    if site_identifier is not None:
        row["site_identifier"] = site_identifier
    return {callsite: row}


def _project(
    *,
    returns_value: bool,
    prefix: bytes = b"",
    slot_selector: str = "ss",
    slot_offset_register: str | None = None,
    reload_ds_from_ss_around_call: bool = False,
):
    # Source-free x86-16 fixture: CALLF SS:[0x20], optionally consume BX on
    # the fake-return path, then return. The slot bytes are data, not source.
    code = bytearray(b"\x90" * 0x24)
    suffix = bytes.fromhex("89d8c3" if returns_value else "c3")
    segment_override = {"ss": "36", "ds": "3e"}[slot_selector]
    ds_reload = bytes.fromhex("161f") if reload_ds_from_ss_around_call else b""
    if slot_offset_register is None:
        call = bytes.fromhex(f"{segment_override}ff1e2000")
    else:
        assert slot_offset_register == "di"
        call = bytes.fromhex(("36" if slot_selector == "ss" else "") + "ff1d")
    body = prefix + ds_reload + call + ds_reload + suffix
    code[: len(body)] = body
    code[0x20:0x24] = bytes.fromhex("10000000")

    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    project = angr.load_shellcode(
        bytes(code),
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
    return_type = SimTypeShort(signed=False) if returns_value else SimTypeBottom(label="void")
    function.prototype = SimTypeFunction([], return_type).with_arch(arch)
    function.prototype_source = PrototypeSource.SIGNATURES
    return project, cfg, function


def _decompile(
    project,
    cfg,
    function,
    bindings,
    *,
    post_call_register_state_bindings=None,
    far_call_bindings=None,
    use_cache: bool = False,
):
    return project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=True,
        use_cache=use_cache,
        update_cache=use_cache,
        initial_register_state_bindings={
            "ds": "INITIAL_DS",
            "ss": "INITIAL_SS",
            "ax": "INITIAL_AX",
            "bx": "INITIAL_BX",
            "cx": "INITIAL_CX",
            "si": "INITIAL_SI",
            "di": "INITIAL_DI",
            "df": "INITIAL_DF",
        },
        post_call_register_state_bindings=post_call_register_state_bindings,
        far_call_bindings=far_call_bindings,
        indirect_far_call_bindings=bindings,
    )


def _calls(graph):
    calls = []
    for block in graph:
        for statement in block.statements:
            if isinstance(statement, ailment.Stmt.SideEffectStatement):
                call = statement.expr
            elif isinstance(statement, ailment.Stmt.Assignment):
                call = statement.src
            else:
                continue
            if isinstance(call, ailment.Expr.Call):
                calls.append(call)
    return calls


def test_indirect_far_call_bindings_are_strict_and_preserve_input_order():
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    ax = arch.registers["ax"]
    bx = arch.registers["bx"]
    cx = arch.registers["cx"]
    ss = arch.registers["ss"]

    assert normalize_indirect_far_call_bindings(arch, _binding(inputs=("cx", "ax", "bx"))) == (
        (0, _DISPATCHER, _ADDRESS_KIND, ss[0], ss[1], ("constant", _SLOT_OFFSET, 2), None, (cx, ax, bx)),
    )

    ds = arch.registers["ds"]
    di = arch.registers["di"]
    assert normalize_indirect_far_call_bindings(
        arch,
        _binding(
            selector="ds",
            slot_offset_register="di",
            site_identifier=0x12345678,
            dispatcher=_TRAP,
            inputs=("di", "ax"),
        ),
    ) == ((0, _TRAP, _ADDRESS_KIND, ds[0], ds[1], ("register", *di), 0x12345678, (di, ax)),)


@pytest.mark.parametrize(
    ("bindings", "exception", "match"),
    (
        ([], TypeError, "must be a mapping"),
        ({True: _binding()[0]}, TypeError, "callsites must be integers"),
        ({-1: _binding()[0]}, ValueError, "unsigned 64-bit"),
        ({0: []}, TypeError, "must be a mapping"),
        ({0: {**_binding()[0], "fallback": "native"}}, ValueError, "Unknown"),
        ({0: {k: v for k, v in _binding()[0].items() if k != "dispatcher"}}, ValueError, "Missing"),
        ({0: {**_binding()[0], "dispatcher": "bad();"}}, ValueError, "identifier"),
        ({0: {**_binding()[0], "address_kind": "x86-real-16:16"}}, ValueError, "address_kind"),
        ({0: {**_binding()[0], "slot_selector_register": None}}, TypeError, "register-name string"),
        ({0: {**_binding()[0], "slot_selector_register": "es"}}, ValueError, "must be 'ds' or 'ss'"),
        ({0: {**_binding()[0], "slot_offset": True}}, TypeError, "slot_offset.*integer"),
        ({0: {**_binding()[0], "slot_offset": 0x1_0000}}, ValueError, "unsigned 16-bit"),
        (
            {0: {**_binding()[0], "slot_offset_register": "di"}},
            ValueError,
            "exactly one",
        ),
        (
            {0: {k: v for k, v in _binding()[0].items() if k != "slot_offset"}},
            ValueError,
            "exactly one",
        ),
        (
            _binding(slot_offset_register="eax"),
            ValueError,
            "slot_offset_register.*16 bits",
        ),
        ({0: {**_binding()[0], "site_identifier": True}}, TypeError, "site_identifier.*integer"),
        ({0: {**_binding()[0], "site_identifier": None}}, TypeError, "site_identifier.*integer"),
        ({0: {**_binding()[0], "site_identifier": 0x1_0000_0000}}, ValueError, "unsigned 32-bit"),
        ({0: {**_binding()[0], "register_inputs": "ax"}}, TypeError, "ordered register sequence"),
        ({0: {**_binding()[0], "register_inputs": ("not_a_register",)}}, KeyError, "Unknown register"),
        ({0: {**_binding()[0], "register_inputs": ("st0",)}}, ValueError, "unsigned scalar register"),
        ({0: {**_binding()[0], "register_inputs": ("ax", "al")}}, ValueError, "must not overlap"),
    ),
)
def test_indirect_far_call_bindings_reject_ambiguous_rows(bindings, exception, match):
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    with pytest.raises(exception, match=match):
        normalize_indirect_far_call_bindings(arch, bindings)


def test_exact_dynamic_callf_becomes_void_dispatcher_with_current_register_inputs():
    project, cfg, function = _project(returns_value=False)
    decompilation = _decompile(
        project,
        cfg,
        function,
        _binding(inputs=("cx", "ax", "bx")),
        far_call_bindings={"external_targets": {0x10: "forbidden_direct_wrapper"}},
    )

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs == ()
    call_text = next(line.strip() for line in decompilation.codegen.text.splitlines() if _DISPATCHER in line)
    assert call_text.startswith("dispatch_far_slot(INITIAL_SS, 32,")
    assert call_text.index("INITIAL_CX") < call_text.index("INITIAL_AX") < call_text.index("INITIAL_BX")
    assert "forbidden_direct_wrapper" not in decompilation.codegen.text
    assert "(*" not in call_text

    dispatcher = next(call for call in _calls(decompilation.ail_graph) if call.target == _DISPATCHER)
    assert dispatcher.transfer_kind == "far"
    assert dispatcher.tags["ins_addr"] == 0
    assert dispatcher.tags["indirect_far_call_dispatch"] is True
    assert dispatcher.tags["indirect_far_call_binding_authoritative"] is True
    assert dispatcher.tags["indirect_far_call_address_kind"] == _ADDRESS_KIND
    assert dispatcher.tags["indirect_far_call_slot_offset"] == _SLOT_OFFSET
    assert dispatcher.bits in (None, 0)
    runtime_prototype = decompilation.clinic.variable_map.prototype(dispatcher)
    assert runtime_prototype is not None
    assert isinstance(runtime_prototype.returnty, SimTypeBottom)
    assert runtime_prototype.returnty.label == "void"
    assert all(
        isinstance(arg_type, (SimTypeChar, SimTypeInt, SimTypeNum)) and arg_type.signed is False
        for arg_type in runtime_prototype.args
    )
    assert tuple(arg_type.size for arg_type in runtime_prototype.args) == (16, 16, 16, 16, 16)
    assert decompilation.clinic.variable_map.calling_convention(dispatcher) is None

    statement = next(
        statement
        for block in decompilation.ail_graph
        for statement in block.statements
        if isinstance(statement, ailment.Stmt.SideEffectStatement) and statement.expr.target == _DISPATCHER
    )
    assert statement.ret_expr is None and statement.fp_ret_expr is None


def test_exact_register_offset_callf_becomes_a_site_identified_noreturn_trap():
    project, cfg, function = _project(
        returns_value=False,
        slot_selector="ds",
        slot_offset_register="di",
    )
    decompilation = _decompile(
        project,
        cfg,
        function,
        _binding(
            selector="ds",
            slot_offset_register="di",
            site_identifier=0x12345678,
            inputs=("ax", "di", "df"),
            dispatcher=_TRAP,
        ),
    )

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs == ()
    call_text = next(line.strip() for line in decompilation.codegen.text.splitlines() if _TRAP in line)
    assert call_text.startswith("trap_far_slot(INITIAL_DS, INITIAL_DI, 305419896,")
    assert call_text.index("INITIAL_AX") < call_text.rindex("INITIAL_DI") < call_text.index("INITIAL_DF")
    assert "(*" not in call_text

    trap = next(call for call in _calls(decompilation.ail_graph) if call.target == _TRAP)
    assert trap.tags["indirect_far_call_binding_authoritative"] is True
    assert trap.tags["indirect_far_call_slot_offset_kind"] == "register"
    assert trap.tags["indirect_far_call_slot_offset_register"] == project.arch.registers["di"][0]
    assert trap.tags["indirect_far_call_slot_offset_register_size"] == 2
    assert trap.tags["indirect_far_call_site_identifier"] == 0x12345678
    assert trap.tags["indirect_far_call_noreturn"] is True
    runtime_prototype = decompilation.clinic.variable_map.prototype(trap)
    assert runtime_prototype is not None
    assert tuple(argument.bits for argument in trap.args) == (16, 16, 32, 16, 16, 8)
    assert tuple(argument_type.size for argument_type in runtime_prototype.args) == (16, 16, 32, 16, 16, 8)


def test_register_slot_argument_may_be_constant_propagated_after_exact_matching():
    prefix = bytes.fromhex("bf0200")  # mov di,2
    project, cfg, function = _project(
        returns_value=False,
        prefix=prefix,
        slot_selector="ds",
        slot_offset_register="di",
    )
    decompilation = _decompile(
        project,
        cfg,
        function,
        _binding(
            callsite=len(prefix),
            selector="ds",
            slot_offset_register="di",
            site_identifier=0x27FE,
            dispatcher=_TRAP,
        ),
    )

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs == ()
    call_text = next(line.strip() for line in decompilation.codegen.text.splitlines() if _TRAP in line)
    assert call_text.startswith("trap_far_slot(INITIAL_DS, 2, 0x27fe,")


def test_dispatcher_inputs_are_values_reaching_the_exact_callsite():
    prefix = bytes.fromhex("b81111bb2222")  # mov ax,0x1111; mov bx,0x2222
    project, cfg, function = _project(returns_value=False, prefix=prefix)
    decompilation = _decompile(project, cfg, function, _binding(callsite=len(prefix)))

    assert decompilation.codegen is not None
    call_text = next(line.strip() for line in decompilation.codegen.text.splitlines() if _DISPATCHER in line)
    assert call_text == "dispatch_far_slot(INITIAL_SS, 32, 0x1111, 0x2222, INITIAL_CX);"
    assert "INITIAL_AX" not in call_text and "INITIAL_BX" not in call_text


def test_ds_slot_dispatch_passes_the_current_ds_selector():
    project, cfg, function = _project(returns_value=False, slot_selector="ds")
    decompilation = _decompile(project, cfg, function, _binding(selector="ds"))

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs == ()
    call_text = next(line.strip() for line in decompilation.codegen.text.splitlines() if _DISPATCHER in line)
    assert call_text.startswith("dispatch_far_slot(INITIAL_DS, 32,")


def test_wide_register_inputs_keep_exact_runtime_widths_on_x86_16():
    project, cfg, function = _project(returns_value=False)
    decompilation = _decompile(project, cfg, function, _binding(inputs=("eax", "mm0")))

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs == ()
    dispatcher = next(call for call in _calls(decompilation.ail_graph) if call.target == _DISPATCHER)
    runtime_prototype = decompilation.clinic.variable_map.prototype(dispatcher)
    assert runtime_prototype is not None
    assert tuple(argument.bits for argument in dispatcher.args) == (16, 16, 32, 64)
    assert tuple(argument_type.size for argument_type in runtime_prototype.args) == (16, 16, 32, 64)


def test_segment_register_push_pop_values_survive_an_indirect_far_call():
    project, cfg, function = _project(returns_value=False, reload_ds_from_ss_around_call=True)
    decompilation = project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=True,
        use_cache=False,
        update_cache=False,
        register_state_bindings={"ds": "PBR_DS", "ss": "PBR_SS"},
        initial_register_state_bindings={"ax": "PBR_AX"},
        indirect_far_call_bindings=_binding(callsite=2, inputs=("ax",)),
    )

    assert decompilation.codegen is not None
    text = decompilation.codegen.text
    assert text.count(f"{_DISPATCHER}(") == 1
    ds_writes = list(re.finditer(r"PBR_DS = ([A-Za-z_]\w*);", text))
    assert len(ds_writes) == 2
    previous_boundary = 0
    for write in ds_writes:
        source = write.group(1)
        assignments = dict(
            re.findall(r"\b([A-Za-z_]\w*) = (PBR_SS|[A-Za-z_]\w*);", text[previous_boundary : write.start()])
        )
        seen = set()
        while source != "PBR_SS" and source not in seen:
            seen.add(source)
            source = assignments.get(source, "")
        assert source == "PBR_SS"
        previous_boundary = write.end()

    sp = project.arch.sp_offset
    expected_offsets = {
        0: (0, 0xFFFE),
        1: (0xFFFE, 0),
        2: (0, 0),
        7: (0, 0xFFFE),
        8: (0xFFFE, 0),
    }
    for ins_addr, (before, after) in expected_offsets.items():
        assert decompilation.clinic._spt.offset_before(ins_addr, sp) == before
        assert decompilation.clinic._spt.offset_after(ins_addr, sp) == after


def _pointer_dispatch_codegen():
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    project = angr.load_shellcode(
        b"\xc3",
        arch=arch,
        load_address=0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    caller = project.kb.functions.function(addr=0, name="caller", create=True)
    assert caller is not None
    caller.prototype = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(arch)

    word_type = SimTypeShort(signed=False).with_arch(arch)
    pointer_type = SimTypePointer(SimTypeChar(signed=False)).with_arch(arch)
    storage = SimStackVariable(-2, 2, ident="pointer_value", name="pointer_value", region=caller.addr)
    project.kb.dec_variables[caller.addr].set_variable_type(storage, word_type)
    pointer_value = ailment.Expr.VirtualVariable(
        1,
        1,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-2,
    )
    tags = {
        "ins_addr": 0,
        "indirect_far_call_dispatch": True,
        "indirect_far_call_binding_authoritative": True,
        "indirect_far_call_address_kind": _ADDRESS_KIND,
        "indirect_far_call_slot_offset": _SLOT_OFFSET,
    }
    call = ailment.Expr.Call(
        2,
        _DISPATCHER,
        args=[
            ailment.Expr.Const(3, 0x1234, 16),
            ailment.Expr.Const(4, _SLOT_OFFSET, 16),
            pointer_value,
        ],
        bits=0,
        transfer_kind="far",
        **tags,
    )
    variable_map = VariableMap()
    variable_map.set_variable(pointer_value, storage)
    variable_map.set_prototype(
        call,
        SimTypeFunction([word_type, word_type, word_type], SimTypeBottom(label="void")).with_arch(arch),
    )
    statement = ailment.Stmt.SideEffectStatement(5, call, ret_expr=None, **tags)
    codegen = project.analyses.CStructuredCodeGenerator(
        caller,
        SequenceNode(0, nodes=[ailment.Block(0, 1, statements=[statement])]),
        variable_map=variable_map,
    )
    assert codegen.unsupported_constructs == ()
    assert "(uint64_t)pointer_value" not in codegen.text

    project.kb.dec_variables[caller.addr].set_variable_type(storage, pointer_type)
    codegen.reload_variable_types()
    codegen.regenerate_text()
    return codegen.text


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang is required to validate generated C")
def test_pointer_shaped_register_input_is_coerced_through_an_integer_carrier():
    text = _pointer_dispatch_codegen()
    call_text = next(line.strip() for line in text.splitlines() if _DISPATCHER in line)
    assert "(uint64_t)pointer_value" in call_text
    assert "& 0xffff" in call_text
    assert "(unsigned short)" in call_text

    compiler = shutil.which("clang")
    assert compiler is not None
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
        input=(
            "typedef unsigned long long uint64_t;\n"
            "void dispatch_far_slot(unsigned short, unsigned short, unsigned short);\n" + text
        ),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "bindings",
    (
        _binding(callsite=1),
        _binding(selector="ds"),
        _binding(slot_offset=_SLOT_OFFSET + 2),
    ),
)
def test_wrong_site_or_slot_evidence_cannot_authorize_dynamic_callf(bindings):
    project, cfg, function = _project(returns_value=False)
    decompilation = _decompile(project, cfg, function, bindings)

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs
    assert _DISPATCHER not in decompilation.codegen.text
    original = next(call for call in _calls(decompilation.ail_graph) if call.transfer_kind == "far")
    assert isinstance(original.target, ailment.Expr.SegmentedAddress)
    assert not original.tags.get("indirect_far_call_dispatch", False)


def test_dynamic_dispatch_uses_existing_exact_post_call_register_outputs():
    project, cfg, function = _project(returns_value=True)
    decompilation = _decompile(
        project,
        cfg,
        function,
        _binding(),
        post_call_register_state_bindings={("callsite_addr", 0): {"bx": "POST_BX"}},
    )

    assert decompilation.codegen is not None
    assert decompilation.codegen.unsupported_constructs == ()
    assert "dispatch_far_slot(INITIAL_SS, 32," in decompilation.codegen.text
    assert "INITIAL_AX" in decompilation.codegen.text
    assert "INITIAL_BX" in decompilation.codegen.text
    assert "INITIAL_CX" in decompilation.codegen.text
    assert "return POST_BX;" in decompilation.codegen.text


def test_assignment_valued_dynamic_callf_requires_an_exact_bound_return_register():
    project, cfg, function = _project(returns_value=False)

    def assignment_graph(manager):
        tags = {"ins_addr": 0, "vex_block_addr": 0}
        ss_offset, ss_size = project.arch.registers["ss"]
        ax_offset, ax_size = project.arch.registers["ax"]
        ss = ailment.Expr.Register(
            manager.next_atom(),
            ss_offset,
            ss_size * project.arch.byte_width,
            **tags,
        )
        slot_offset = ailment.Expr.Const(manager.next_atom(), _SLOT_OFFSET, 16, **tags)
        selector_offset = ailment.Expr.BinaryOp(
            manager.next_atom(),
            "Add",
            (slot_offset, ailment.Expr.Const(manager.next_atom(), 2, 16, **tags)),
            False,
            bits=16,
            **tags,
        )
        slot_address = ailment.Expr.SegmentedAddress(
            manager.next_atom(), ss, slot_offset, _ADDRESS_KIND, bits=32, **tags
        )
        selector_address = ailment.Expr.SegmentedAddress(
            manager.next_atom(), ss, selector_offset, _ADDRESS_KIND, bits=32, **tags
        )
        target = ailment.Expr.SegmentedAddress(
            manager.next_atom(),
            ailment.Expr.Load(manager.next_atom(), selector_address, 2, project.arch.memory_endness, **tags),
            ailment.Expr.Load(manager.next_atom(), slot_address, 2, project.arch.memory_endness, **tags),
            _ADDRESS_KIND,
            bits=32,
            **tags,
        )
        call = ailment.Expr.Call(manager.next_atom(), target, args=[], bits=16, transfer_kind="far", **tags)
        assignment = ailment.Stmt.Assignment(
            manager.next_atom(),
            ailment.Expr.Register(manager.next_atom(), ax_offset, ax_size * project.arch.byte_width, **tags),
            call,
            **tags,
        )
        block = ailment.Block(0, 1, statements=[assignment])
        graph = networkx.DiGraph()
        graph.add_node(block)
        return graph

    unbound_return = _decompile(project, cfg, function, _binding())
    unbound_graph = assignment_graph(unbound_return.clinic._ail_manager)
    unbound_return.clinic._rewrite_bound_indirect_far_calls(unbound_graph)
    unbound_statement = next(iter(unbound_graph.nodes)).statements[0]
    assert isinstance(unbound_statement, ailment.Stmt.Assignment)
    assert isinstance(unbound_statement.src.target, ailment.Expr.SegmentedAddress)

    bound_return = _decompile(
        project,
        cfg,
        function,
        _binding(),
        post_call_register_state_bindings={("callsite_addr", 0): {"ax": "POST_AX"}},
    )
    bound_graph = assignment_graph(bound_return.clinic._ail_manager)
    bound_return.clinic._rewrite_bound_indirect_far_calls(bound_graph)
    bound_statement = next(iter(bound_graph.nodes)).statements[0]
    assert isinstance(bound_statement, ailment.Stmt.SideEffectStatement)
    assert bound_statement.expr.target == _DISPATCHER
    assert bound_statement.expr.tags["indirect_far_call_binding_authoritative"] is True


def test_indirect_far_call_bindings_roundtrip_and_control_cache_identity():
    project, cfg, function = _project(returns_value=False)
    first = _decompile(project, cfg, function, _binding(), use_cache=True)
    parsed = DecompilationCache.parse(
        first.cache.serialize(),
        project=project,
        kb=project.kb,
        function=function,
        cfg=cfg.model,
    )
    normalized = normalize_indirect_far_call_bindings(project.arch, _binding())

    assert parsed.parameters["indirect_far_call_bindings"] == normalized
    assert parsed.clinic.indirect_far_call_bindings == normalized
    assert _DISPATCHER in parsed.codegen.text

    project.kb.decompilations[(function.addr, "pseudocode")] = parsed
    same = _decompile(project, cfg, function, _binding(), use_cache=True)
    assert same.clinic is parsed.clinic

    changed = _decompile(project, cfg, function, _binding(inputs=("ax", "cx", "bx")), use_cache=True)
    assert changed.clinic is not parsed.clinic


def test_register_slot_source_and_site_identifier_roundtrip_through_the_cache():
    project, cfg, function = _project(
        returns_value=False,
        slot_selector="ds",
        slot_offset_register="di",
    )
    bindings = _binding(
        selector="ds",
        slot_offset_register="di",
        site_identifier=0x27FE,
        dispatcher=_TRAP,
    )
    first = _decompile(project, cfg, function, bindings, use_cache=True)
    parsed = DecompilationCache.parse(
        first.cache.serialize(),
        project=project,
        kb=project.kb,
        function=function,
        cfg=cfg.model,
    )
    normalized = normalize_indirect_far_call_bindings(project.arch, bindings)

    assert parsed.parameters["indirect_far_call_bindings"] == normalized
    assert parsed.clinic.indirect_far_call_bindings == normalized
    assert _TRAP in parsed.codegen.text


def test_indirect_far_call_bindings_require_c_pseudocode_output():
    project, cfg, function = _project(returns_value=False)
    with pytest.raises(ValueError, match="require C pseudocode"):
        project.analyses.Decompiler(
            function,
            cfg=cfg.model,
            flavor="rust",
            decompile=False,
            indirect_far_call_bindings=_binding(),
        )
