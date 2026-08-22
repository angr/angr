from __future__ import annotations

import archinfo
import pytest

import angr
from angr.knowledge_plugins.cfg import CFGModel
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction

pytest.importorskip("pypcode")


_BASE = 0x1000


def _cfg(machine_code: bytes):
    project = angr.load_shellcode(
        machine_code,
        arch=archinfo.ArchPcode("x86:LE:16:Protected Mode"),
        load_address=_BASE,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    return project.analyses.CFGFast(
        function_starts=[_BASE],
        regions=[(_BASE, _BASE + len(machine_code))],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        resolve_indirect_jumps=True,
    )


@pytest.mark.parametrize(
    ("machine_code", "return_site"),
    [
        # pop bx; jmp body; nop; body: jmp bx
        (bytes.fromhex("5beb0190ffe3"), _BASE + 4),
        # pop cx; jmp body; nop; body: jmp cx
        (bytes.fromhex("59eb0190ffe1"), _BASE + 4),
    ],
)
def test_pcode_x86_popped_return_address_register_is_return(machine_code, return_site):
    cfg = _cfg(machine_code)

    function = cfg.functions[_BASE]
    assert {site.addr for site in function.ret_sites} == {return_site}
    assert cfg.model.node_addr_has_return(return_site)
    assert return_site not in cfg.indirect_jumps
    assert return_site not in cfg.kb.unresolved_indirect_jumps


def test_proven_pcode_return_thunk_survives_decompilation():
    cfg = _cfg(bytes.fromhex("5beb0190ffe3"))
    function = cfg.functions[_BASE]
    function.calling_convention = cfg.project.factory.cc()
    function.prototype = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(cfg.project.arch)
    function.prototype_source = PrototypeSource.USER

    decompilation = cfg.project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=True,
    )

    assert decompilation.codegen is not None
    assert "return;" in decompilation.codegen.text
    assert "goto" not in decompilation.codegen.text
    assert not decompilation.codegen.unsupported_constructs


def test_pcode_x86_memory_saved_return_address_is_return_and_serializes():
    # pop word ptr [0x432]; jmp body; nop; body: jmp word ptr [0x432]
    cfg = _cfg(bytes.fromhex("8f063204eb0190ff263204"))

    function = cfg.functions[_BASE]
    return_site = _BASE + 7
    assert {site.addr for site in function.ret_sites} == {return_site}
    assert cfg.model.node_addr_has_return(return_site)
    assert return_site not in cfg.indirect_jumps
    assert return_site not in cfg.kb.unresolved_indirect_jumps

    restored_model = CFGModel.parse(cfg.model.serialize())
    assert restored_model.node_addr_has_return(return_site)
    restored_function = angr.knowledge_plugins.Function.parse(
        function.serialize(),
        function_manager=cfg.kb.functions,
        project=cfg.project,
    )
    assert {site.addr for site in restored_function.ret_sites} == {return_site}
    assert restored_function.returning is True


def test_pcode_x86_memory_saved_return_address_survives_call_fake_return():
    # pop [0x432]; call callee; jmp [0x432]; padding; callee: ret
    cfg = _cfg(bytes.fromhex("8f063204e80900ff2632049090909090c3"))

    function = cfg.functions[_BASE]
    assert {site.addr for site in function.ret_sites} == {_BASE + 7}


def test_proven_pcode_x86_memory_saved_return_survives_decompilation():
    cfg = _cfg(bytes.fromhex("8f063204eb0190ff263204"))
    function = cfg.functions[_BASE]
    function.calling_convention = cfg.project.factory.cc()
    function.prototype = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(cfg.project.arch)
    function.prototype_source = PrototypeSource.USER

    decompilation = cfg.project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=True,
        segmented_memory_bindings={
            "x86-protected-16:16": {
                "endness": archinfo.Endness.LE,
                "stores": {2: "guest_store_u16"},
            }
        },
    )

    assert decompilation.codegen is not None
    assert "return;" in decompilation.codegen.text
    assert "goto" not in decompilation.codegen.text
    assert not decompilation.codegen.unsupported_constructs


@pytest.mark.parametrize(
    "machine_code",
    [
        # No stack provenance for BX.
        bytes.fromhex("90eb0190ffe3"),
        # A full-width overwrite destroys the popped token.
        bytes.fromhex("5beb019031dbffe3"),
        # A partial-register overwrite aliases and destroys the BX token.
        bytes.fromhex("5beb0190b300ffe3"),
        # The 32-bit branch width does not match the 16-bit popped token.
        bytes.fromhex("5beb019066ffe3"),
    ],
)
def test_pcode_x86_return_thunk_classifier_fails_closed(machine_code):
    cfg = _cfg(machine_code)

    function = cfg.functions[_BASE]
    assert not function.ret_sites
    assert not cfg.model.node_addr_has_return(_BASE + 4)


@pytest.mark.parametrize(
    "machine_code",
    [
        # The terminal jump reads a different slot.
        bytes.fromhex("8f063204eb0190ff263404"),
        # A full-width write destroys the saved continuation.
        bytes.fromhex("8f063204c70632040000ff263204"),
        # A byte write partially overlaps the saved continuation.
        bytes.fromhex("8f063204c606330400ff263204"),
        # The slot address is materialized and then overwritten through an alias.
        bytes.fromhex("8f063204bb3204c7070000ff263204"),
        # Partial-register writes materialize the same alias.
        bytes.fromhex("8f063204b332b704c7070000ff263204"),
        # The slot offset escapes through the stack even without a local write.
        bytes.fromhex("8f06320468320483c402ff263204"),
        # A called function explicitly overwrites the continuation slot.
        bytes.fromhex("8f063204e80900ff2632049090909090c70632040000c3"),
        # An unrelated indirect jump has no stack-token provenance.
        bytes.fromhex("c70632041111eb0190ff263204"),
    ],
)
def test_pcode_x86_memory_saved_return_classifier_fails_closed(machine_code):
    cfg = _cfg(machine_code)

    function = cfg.functions[_BASE]
    assert not function.ret_sites
