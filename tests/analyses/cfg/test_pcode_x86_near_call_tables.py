from __future__ import annotations

from types import SimpleNamespace

import archinfo
import pytest
from cle.backends.region import Segment
from cle.backends.regions import Regions

import angr

pytest.importorskip("pypcode")


_HELPER = 0x100
_CALLERS = (0x00, 0x20, 0x40, 0x60)
_DEFAULT_PAIRS = ((0x10, 0x16), (0x30, 0x30), (0x16, 0x18), (0x18, 0x18))


class _FixtureSegment(Segment):
    def __init__(self, number: int, address: int, size: int, *, executable: bool, writable: bool):
        super().__init__(0, address, size, size)
        self.segment_number = number
        self.name = f"seg{number:03d}"
        self._executable = executable
        self._writable = writable

    @property
    def is_executable(self) -> bool:
        return self._executable

    @property
    def is_writable(self) -> bool:
        return self._writable


def _machine_code(
    pairs: tuple[tuple[int, int], ...],
    *,
    exact_zero_skip: bool = True,
    reverse_step: bytes = b"\x4f\x4f",
    helper_code: bytes | None = None,
    extra_code: tuple[tuple[int, bytes], ...] = (),
) -> bytes:
    code = bytearray(b"\x90" * 0x200)
    for caller, (lower, upper) in zip(_CALLERS, pairs, strict=True):
        # MOV SI, lower; JMP next; MOV DI, upper; CALL helper; RET. The jump deliberately places SI's reaching
        # definition in a predecessor block so the fixture exercises cross-block reverse constant recovery.
        code[caller : caller + 5] = b"\xbe" + lower.to_bytes(2, "little") + b"\xeb\x00"
        callsite = caller + 8
        displacement = (_HELPER - (callsite + 3)) & 0xFFFF
        code[caller + 5 : caller + 12] = (
            b"\xbf" + upper.to_bytes(2, "little") + b"\xe8" + displacement.to_bytes(2, "little") + b"\xc3"
        )

    if helper_code is None:
        zero_skip = b"\xe3\xf6" if exact_zero_skip else b"\x90\x90"
        # The NOP deliberately shares the final CFG block with CALL CX. The
        # unresolved-jump key is therefore 0x10a, while the exact CALL IMARK is
        # 0x10b; proof generation must never conflate those addresses.
        helper_code = bytes.fromhex("3bf7730b") + reverse_step + b"\x8b\x0d" + zero_skip + bytes.fromhex("90ffd1ebf1c3")
    code[_HELPER : _HELPER + len(helper_code)] = helper_code
    for address, contents in extra_code:
        code[address : address + len(contents)] = contents
    for target in (0x180, 0x190, 0x1A0):
        code[target] = 0xC3
    return bytes(code)


def _project(
    *,
    pairs: tuple[tuple[int, int], ...] = _DEFAULT_PAIRS,
    table_values: tuple[int, ...] = (0x180, 0, 0x190, 0x1A0),
    exact_zero_skip: bool = True,
    reverse_step: bytes = b"\x4f\x4f",
    helper_code: bytes | None = None,
    extra_code: tuple[tuple[int, bytes], ...] = (),
    automatic_data_segment: int = 2,
    fixups=(),
):
    code = _machine_code(
        pairs,
        exact_zero_skip=exact_zero_skip,
        reverse_step=reverse_step,
        helper_code=helper_code,
        extra_code=extra_code,
    )
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    project = angr.load_shellcode(
        code,
        arch=arch,
        load_address=0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )

    data = bytearray(0x100)
    for offset, value in zip(range(0x10, 0x18, 2), table_values, strict=True):
        data[offset : offset + 2] = value.to_bytes(2, "little")
    project.loader.memory.add_backer(0x10000, bytes(data))
    project.loader.main_object.memory.add_backer(0x10000, bytes(data))

    code_segment = _FixtureSegment(1, 0, len(code), executable=True, writable=False)
    data_segment = _FixtureSegment(2, 0x10000, len(data), executable=False, writable=True)
    main = project.loader.main_object
    main.segments = Regions([code_segment, data_segment])
    main.sections = main.segments
    main.automatic_data_segment = automatic_data_segment
    main.fixups = tuple(fixups)

    cfg = project.analyses.CFGFast(
        function_starts=[*_CALLERS, _HELPER],
        regions=[(0, len(code))],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        resolve_indirect_jumps=True,
    )
    return project, cfg


def _cfg_snapshot(cfg):
    return (
        tuple(
            sorted(
                (int(node.addr), int(node.size), int(node.function_address))
                for node in cfg.model.graph
                if node.function_address is not None
            )
        ),
        tuple(
            sorted(
                (
                    int(source.addr),
                    int(destination.addr),
                    (cfg.model.graph.get_edge_data(source, destination) or {}).get("jumpkind"),
                )
                for source, destination in cfg.model.graph.edges
            )
        ),
        tuple(sorted(int(address) for address in cfg.functions)),
        tuple(sorted(int(address) for address in cfg.kb.unresolved_indirect_jumps)),
        tuple(
            (
                int(address),
                jump.jumpkind,
                int(jump.func_addr),
                tuple(sorted(int(target) for target in jump.resolved_targets)),
            )
            for address, jump in sorted(cfg.indirect_jumps.items())
        ),
    )


def test_cross_block_reverse_near_call_table_is_dynamic_evidence_only():
    project, cfg = _project()
    before = _cfg_snapshot(cfg)

    result = project.analyses.PcodeX86NearCallTableCandidates(cfg)

    assert _cfg_snapshot(cfg) == before
    assert [candidate.address for candidate in result.candidates] == [0x180, 0x190, 0x1A0]
    assert len(result.proofs) == 1
    proof = result.proofs[0]
    assert proof["site"] == 0x10B
    assert proof["cfg_block_address"] == 0x10A
    assert proof["call_instruction_address"] == 0x10B
    assert proof["call_instruction_bytes"] == "ffd1"
    assert proof["call_instruction_size"] == 2
    assert proof["call_instruction_mnemonic"] == "CALL"
    assert proof["target_offset_register_name"] == "cx"
    assert proof["target_offset_register_range"] == [4, 2]
    assert proof["cs_segment_number"] == 1
    assert proof["pointer_register_name"] == "di"
    assert proof["pointer_register_range"] == [28, 2]
    assert proof["lower_register_name"] == "si"
    assert proof["lower_register_range"] == [24, 2]
    assert proof["fake_return_calling_convention"] == "SimCCPCodeX86Win16NearCdecl"
    assert proof["fake_return_preserved_registers"] == [
        {"name": "ds", "range": [262, 2]},
        {"name": "si", "range": [24, 2]},
        {"name": "di", "range": [28, 2]},
    ]
    assert proof["function"] == _HELPER
    assert proof["direct_caller_bound_pairs"] == list(_DEFAULT_PAIRS)
    assert proof["direct_callers"] == [
        {"site": 0x08, "lower": 0x10, "upper": 0x16},
        {"site": 0x28, "lower": 0x30, "upper": 0x30},
        {"site": 0x48, "lower": 0x16, "upper": 0x18},
        {"site": 0x68, "lower": 0x18, "upper": 0x18},
    ]
    assert proof["automatic_data_segment"] == 2
    assert proof["automatic_data_segment_rva"] == 0x10000
    assert proof["cs_segment_rva"] == 0
    assert proof["ds_table_offsets"] == [0x10, 0x12, 0x14, 0x16]
    assert proof["ds_table_locations"] == [0x10010, 0x10012, 0x10014, 0x10016]
    assert proof["ds_table_values"] == [0x180, 0, 0x190, 0x1A0]
    assert proof["zero_entry_offsets_skipped"] == [0x12]
    assert proof["cs_executable_targets"] == [0x180, 0x190, 0x1A0]
    assert proof["dynamic"] is True
    assert proof["completeness"] is False
    assert proof["fixup_overlap_rejected"] is False
    assert 0x10A in cfg.kb.unresolved_indirect_jumps


@pytest.mark.parametrize("decoded_bytes", (b"\xff\xe1", b"\xff\xd2", b"\xff"))
def test_near_call_table_rejects_machine_decode_disagreement(monkeypatch, decoded_bytes):
    project, cfg = _project()
    result = project.analyses.PcodeX86NearCallTableCandidates(cfg)
    assert result.proofs

    # Retain the already lifted p-code (which proves CALLIND via CX), but make
    # the independent byte decoder observe JMP CX, CALL DX, or truncation.
    memory_type = type(project.loader.memory)
    real_load = memory_type.load

    def inconsistent_load(memory, address, size, *args, **kwargs):
        if memory is project.loader.memory and address == 0x10B and size == 2:
            return decoded_bytes
        return real_load(memory, address, size, *args, **kwargs)

    monkeypatch.setattr(memory_type, "load", inconsistent_load)
    result.proofs.clear()
    result.candidates.clear()
    result._collect(256)

    assert not result.proofs
    assert not result.candidates


def test_near_call_table_requires_a_unique_register_name_range_round_trip(monkeypatch):
    project, cfg = _project()
    result = project.analyses.PcodeX86NearCallTableCandidates(cfg)
    assert result.proofs

    monkeypatch.setitem(project.arch.registers, "cx_alias", project.arch.registers["cx"])
    result.proofs.clear()
    result.candidates.clear()
    result._collect(256)

    assert not result.proofs
    assert not result.candidates


def test_near_call_table_rejects_a_hidden_callee_clobber_on_the_fake_return_path():
    # The extra CALL reaches a tiny callee that clobbers DI. CFG's FakeRet edge
    # does not encode that side effect, so the iterator proof must reject the
    # extra call rather than treating DI as unchanged before the table load.
    helper_code = bytes.fromhex("3bf7730ee839004f4f8b0de3f390ffd1ebeec3")
    project, cfg = _project(helper_code=helper_code, extra_code=((0x140, b"\x4f\xc3"),))

    result = project.analyses.PcodeX86NearCallTableCandidates(cfg)

    assert not result.proofs
    assert not result.candidates


def test_near_call_table_requires_the_fake_return_contract_to_preserve_the_iterator(monkeypatch):
    project, cfg = _project()
    result = project.analyses.PcodeX86NearCallTableCandidates(cfg)
    assert result.proofs

    calling_convention_type = type(project.factory.cc())
    monkeypatch.setattr(
        calling_convention_type,
        "CALLER_SAVED_REGS",
        [*calling_convention_type.CALLER_SAVED_REGS, "di"],
    )
    result.proofs.clear()
    result.candidates.clear()
    result._collect(256)

    assert not result.proofs
    assert not result.candidates


def test_near_call_table_rejects_a_direct_caller_decode_target_disagreement(monkeypatch):
    project, cfg = _project()
    result = project.analyses.PcodeX86NearCallTableCandidates(cfg)
    assert result.proofs

    # Retain p-code/CFG for CALL 0x100, while independent decoding observes a
    # valid direct CALL to 0x120 at the first caller site.
    memory_type = type(project.loader.memory)
    real_load = memory_type.load

    def inconsistent_load(memory, address, size, *args, **kwargs):
        if memory is project.loader.memory and address == 0x08 and size == 3:
            return bytes.fromhex("e81501")
        return real_load(memory, address, size, *args, **kwargs)

    monkeypatch.setattr(memory_type, "load", inconsistent_load)
    result.proofs.clear()
    result.candidates.clear()
    result._collect(256)

    assert not result.proofs
    assert not result.candidates


@pytest.mark.parametrize(
    ("source_type", "source_rva"),
    ((0, 0x10010), (2, 0x1000F), (3, 0x1000E), (5, 0x10016)),
)
def test_near_call_table_rejects_any_fixup_byte_overlap(source_type, source_rva):
    fixup = SimpleNamespace(source_type=source_type, source_rvas=(source_rva,))
    project, cfg = _project(fixups=(fixup,))

    result = project.analyses.PcodeX86NearCallTableCandidates(cfg)

    assert not result.proofs
    assert not result.candidates


def test_near_call_table_accepts_an_adjacent_nonoverlapping_fixup():
    fixup = SimpleNamespace(source_type=5, source_rvas=(0x1000E,))
    project, cfg = _project(fixups=(fixup,))

    result = project.analyses.PcodeX86NearCallTableCandidates(cfg)

    assert [candidate.address for candidate in result.candidates] == [0x180, 0x190, 0x1A0]


@pytest.mark.parametrize("automatic_data_segment", (0, 1, 3))
def test_near_call_table_requires_the_writable_automatic_data_segment(automatic_data_segment):
    project, cfg = _project(automatic_data_segment=automatic_data_segment)

    assert not project.analyses.PcodeX86NearCallTableCandidates(cfg).proofs


def test_near_call_table_rejects_a_target_outside_the_actual_cs_segment():
    project, cfg = _project(table_values=(0x180, 0, 0x190, 0x300))

    assert not project.analyses.PcodeX86NearCallTableCandidates(cfg).proofs


@pytest.mark.parametrize(
    "pairs",
    (
        ((0x11, 0x16), (0x30, 0x30), (0x16, 0x18), (0x18, 0x18)),
        ((0x10, 0x17), (0x30, 0x30), (0x16, 0x18), (0x18, 0x18)),
        ((0xFFFE, 0x0000), (0x30, 0x30), (0x16, 0x18), (0x18, 0x18)),
        ((0x0000, 0x0202), (0x30, 0x30), (0x16, 0x18), (0x18, 0x18)),
    ),
)
def test_near_call_table_rejects_unaligned_wrapping_or_uncapped_ranges(pairs):
    project, cfg = _project(pairs=pairs)

    assert not project.analyses.PcodeX86NearCallTableCandidates(cfg).proofs


@pytest.mark.parametrize("max_entries", (0, 2, 257))
def test_near_call_table_enforces_the_requested_and_global_entry_caps(max_entries):
    project, cfg = _project()

    assert not project.analyses.PcodeX86NearCallTableCandidates(cfg, max_entries=max_entries).proofs


def test_near_call_table_requires_an_exact_zero_skip_before_the_indirect_call():
    project, cfg = _project(exact_zero_skip=False)

    assert not project.analyses.PcodeX86NearCallTableCandidates(cfg).proofs


@pytest.mark.parametrize(
    "helper_code",
    (
        bytes.fromhex("3bf7730c4f4f8b0db180e3f4ffd1ebf0c3"),  # MOV CL, 80h corrupts the loaded CX
        bytes.fromhex("3bf7730c4f4f8b0d7502e3f4ffd1ebf0c3"),  # JNZ bypasses the zero check
    ),
)
def test_near_call_table_rejects_corruption_or_bypass_between_load_and_zero_check(helper_code):
    project, cfg = _project(helper_code=helper_code)

    result = project.analyses.PcodeX86NearCallTableCandidates(cfg)

    assert not result.proofs
    assert not result.candidates


def test_near_call_table_requires_one_exact_entry_sized_reverse_step():
    project, cfg = _project(reverse_step=b"\x4f\x47")  # DEC DI; INC DI: net step zero

    assert not project.analyses.PcodeX86NearCallTableCandidates(cfg).proofs
