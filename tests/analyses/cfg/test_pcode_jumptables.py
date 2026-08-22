from __future__ import annotations

from types import SimpleNamespace

import archinfo
import pytest

import angr
from angr.engines.pcode.cc import SimCCPCodeX86Win16NearCdecl
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeFunction, SimTypeShort

pytest.importorskip("pypcode")


_BASE = 0x1000


def _cfg(machine_code: bytes, *, automatic_data_segment: bool = False):
    project = angr.load_shellcode(
        machine_code,
        arch=archinfo.ArchPcode("x86:LE:16:Protected Mode"),
        load_address=_BASE,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    if automatic_data_segment:
        main = project.loader.main_object
        main.automatic_data_segment = 1
        main.segments_by_number = {
            1: SimpleNamespace(vaddr=0, initialized_size=_BASE + len(machine_code)),
        }
        main.fixups = ()
    cfg = project.analyses.CFGFast(
        function_starts=[_BASE],
        regions=[(_BASE, _BASE + len(machine_code))],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        data_references=True,
        resolve_indirect_jumps=True,
    )
    return project, cfg


@pytest.mark.parametrize(
    ("machine_code", "jump_addr", "table_addr"),
    [
        # cmp ax, 2; ja default; shl ax, 1; xchg ax, bx;
        # jmp word ptr cs:[bx + table]
        (bytes.fromhex("3d0200770fd1e0932effa70d1014101510161090c3c3c3"), 0x1005, 0x100D),
        # The same bound with jbe selecting the table path instead of fallthrough.
        (bytes.fromhex("3d02007602c390d1e0932effa70f1016101710181090c3c3c3"), 0x1007, 0x100F),
    ],
)
def test_pcode_x86_bounded_near_jump_table(machine_code, jump_addr, table_addr):
    _, cfg = _cfg(machine_code)

    jump = cfg.jump_tables[jump_addr]
    assert jump.jumptable is True
    assert jump.jumptable_addr == table_addr
    assert jump.jumptable_size == 6
    assert jump.jumptable_entry_size == 2
    expected_entries = [0x1014, 0x1015, 0x1016] if jump_addr == 0x1005 else [0x1016, 0x1017, 0x1018]
    assert jump.jumptable_entries == expected_entries
    assert jump.jumptable_entries_guessed is False
    assert jump.jumptable_resolution_evidence.resolver == "angr.PcodeX86JumpTableResolver"
    assert jump.jumptable_resolution_evidence.proof == "pcode-predecessor-unsigned-upper-bound"
    assert jump_addr not in cfg.kb.unresolved_indirect_jumps


def test_pcode_x86_jump_table_rejects_nonexecutable_entry():
    # The last entry points outside the executable blob. A partially plausible
    # table must remain unresolved instead of creating an unsound CFG edge.
    machine_code = bytes.fromhex("3d0200770fd1e0932effa70d1014101510002090c3c3c3")
    _, cfg = _cfg(machine_code)

    assert 0x1005 not in cfg.jump_tables
    assert 0x1005 in cfg.kb.unresolved_indirect_jumps


def test_pcode_x86_byte_domain_narrows_to_complete_jump_table():
    # mov al, [bx]; mov cl, 4; shr al, cl; cbw; mov bx, ax;
    # shl bx, 1; jmp word ptr cs:[bx + table]
    #
    # The loaded byte is mutable and therefore not treated as a constant. Its
    # complete domain is nevertheless narrowed by the logical shift to 0..15,
    # which proves the exact table extent without source or scan heuristics.
    dispatch = bytes.fromhex("8a07b104d2e8988bd8d1e32effa71010")
    entries = b"".join(address.to_bytes(2, "little") for address in range(0x1030, 0x1040))
    machine_code = dispatch + entries + b"\xc3" * 16

    _, cfg = _cfg(machine_code)

    jump = cfg.jump_tables[_BASE]
    assert jump.jumptable_addr == 0x1010
    assert jump.jumptable_size == 32
    assert jump.jumptable_entry_size == 2
    assert jump.jumptable_entries == list(range(0x1030, 0x1040))
    assert jump.jumptable_entries_guessed is False
    assert jump.jumptable_resolution_evidence.resolver == "angr.PcodeX86JumpTableResolver"
    assert jump.jumptable_resolution_evidence.proof == "pcode-finite-value-domain"
    assert _BASE not in cfg.kb.unresolved_indirect_jumps

    restored = type(jump).parse(jump.serialize())
    assert restored.jumptable_resolution_evidence == jump.jumptable_resolution_evidence


def test_pcode_x86_wide_unbounded_domain_remains_unresolved():
    # A 16-bit unconstrained load has 65,536 possible values. The finite-domain
    # proof deliberately refuses to guess a table extent for it.
    dispatch = bytes.fromhex("8b078bd8d1e32effa70e10")
    machine_code = dispatch + bytes.fromhex("1810191090c3c3")

    _, cfg = _cfg(machine_code)

    assert _BASE not in cfg.jump_tables
    assert _BASE in cfg.kb.unresolved_indirect_jumps


def test_pcode_x86_lookup_state_domain_proves_exact_table_extent():
    # The dispatch block models a byte-oriented state machine without using
    # compiler source: an arbitrary input is narrowed to a nibble, combined
    # with a stack-resident nibble state, translated through loader bytes, and
    # narrowed again before indexing a near jump table.
    initializer = bytes.fromhex("5589e5eb00c646ff00eb00")
    dispatch = bytes.fromhex("8a04240fb103d2e00246ffbb8010d7b104d2e88846ff988bd8d1e32effa71011")
    prefix = initializer + dispatch
    lookup = bytes((index % 8) << 4 for index in range(136))
    padding_before_lookup = b"\x00" * (0x1080 - (_BASE + len(prefix)))
    padding_before_table = b"\x00" * (0x1110 - (0x1080 + len(lookup)))
    entries = b"".join(address.to_bytes(2, "little") for address in range(0x1120, 0x1128))
    machine_code = prefix + padding_before_lookup + lookup + padding_before_table + entries + b"\xc3" * 8

    _, cfg = _cfg(machine_code, automatic_data_segment=True)

    jump = cfg.jump_tables[0x100B]
    assert jump.jumptable_addr == 0x1110
    assert jump.jumptable_size == 16
    assert jump.jumptable_entries == list(range(0x1120, 0x1128))
    assert jump.jumptable_entries_guessed is False
    assert 0x100B not in cfg.kb.unresolved_indirect_jumps


def test_cfg_normalization_rehomes_unresolved_indirect_jump_address():
    # Two roots create overlapping blocks ending at the same indirect jump:
    #   1000: nop; nop
    #   1002: jmp ax
    # The unresolved site is the normalized tail at 1002, never the stale
    # containing block at 1000. This is a machine-code-only regression.
    machine_code = bytes.fromhex("9090ffe0")
    project = angr.load_shellcode(
        machine_code,
        arch=archinfo.ArchPcode("x86:LE:16:Protected Mode"),
        load_address=_BASE,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    cfg = project.analyses.CFGFast(
        function_starts=[_BASE, _BASE + 2],
        regions=[(_BASE, _BASE + len(machine_code))],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        data_references=True,
        resolve_indirect_jumps=True,
    )

    assert set(cfg.indirect_jumps) == {_BASE + 2}
    assert cfg.kb.unresolved_indirect_jumps == {_BASE + 2}


def test_pcode_x86_bounded_jump_table_decompiles_to_complete_switch():
    # A machine-code-only regression for the normalized Win16 dispatch shape:
    # dec ax; cmp ax, 2; ja default; shl ax, 1; xchg ax, bx;
    # jmp word ptr cs:[bx + table]. No compiler source is used by this test.
    machine_code = bytes.fromhex("483d0200770ed1e0932effa70e10151016101710c3c3c3c3")
    project, cfg = _cfg(machine_code)

    jump = cfg.jump_tables[0x1006]
    assert jump.jumptable_entries == [0x1015, 0x1016, 0x1017]
    assert jump.jumptable_entries_guessed is False

    function = cfg.functions[_BASE]
    function.calling_convention = SimCCPCodeX86Win16NearCdecl(project.arch)
    function.prototype = SimTypeFunction([], SimTypeShort(signed=False)).with_arch(project.arch)
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
    assert "switch (" in decompilation.codegen.text
    assert "case 1:" in decompilation.codegen.text
    assert "case 2:" in decompilation.codegen.text
    assert "case 3:" in decompilation.codegen.text
    assert "incomplete" not in decompilation.codegen.text
    assert "goto /* computed */" not in decompilation.codegen.text
    assert not decompilation.codegen.unsupported_constructs
