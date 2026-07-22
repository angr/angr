from __future__ import annotations

from itertools import combinations

import archinfo

import angr
from angr.analyses.decompiler.clinic import Clinic, ClinicMode
from angr.codenode import BlockNode


def _block_ranges(function):
    return sorted((node.addr, node.size) for node in function.graph if isinstance(node, BlockNode))


def _overlapping_pairs(blocks):
    return [
        (left, right)
        for left, right in combinations(blocks, 2)
        if left[0] < right[0] + right[1] and right[0] < left[0] + left[1]
    ]


def test_cfgfast_rebuilds_function_graphs_for_fresh_pcode_model(monkeypatch):
    # The branch at 0x8000 targets the end of the raw block that begins at 0x8002. The first CFGFast run therefore
    # presents Clinic with a valid provisional overlap: [0x8002, 0x8007) and [0x8005, 0x8007). Normalization splits
    # the former at 0x8005. A later CFGFast run on the same knowledge base creates a fresh CFG model and must rebuild
    # the function graph as well. Otherwise it registers a new [0x8002, 0x8007) block alongside the normalized
    # [0x8002, 0x8005) block left by the first model.
    code = bytes.fromhex("d003 eaeaea d000 d000 d000 d000 d000 d000 d000 4c1380")
    project = angr.load_shellcode(
        code,
        arch=archinfo.ArchPcode("6502:LE:16:default"),
        load_address=0x8000,
        engine=angr.engines.UberEnginePcode,
    )

    original_clinic_init = Clinic.__init__
    clinic_block_ranges = []
    clinic_normalized = []

    def clinic_init(self, function, *args, **kwargs):
        if kwargs.get("mode", ClinicMode.DECOMPILE) == ClinicMode.COLLECT_DATA_REFS:
            assert function is project.kb.functions[function.addr]
            blocks = _block_ranges(function)
            clinic_block_ranges.append(blocks)
            clinic_normalized.append(function.normalized)
            assert not any(left[0] == right[0] for left, right in combinations(blocks, 2))
        original_clinic_init(self, function, *args, **kwargs)

    monkeypatch.setattr(Clinic, "__init__", clinic_init)

    cfgs = []
    for _ in range(2):
        cfg = project.analyses.CFGFast(
            function_starts=[0x8000],
            force_smart_scan=False,
            normalize=True,
            data_references=True,
        )
        cfgs.append(cfg)
        assert cfg.functions[0x8000].normalized
        assert not _overlapping_pairs(_block_ranges(cfg.functions[0x8000]))

    assert len(clinic_block_ranges) == 2
    assert clinic_normalized == [False, False]
    assert ((0x8002, 5), (0x8005, 2)) in _overlapping_pairs(clinic_block_ranges[0])
    assert ((0x8002, 5), (0x8005, 2)) in _overlapping_pairs(clinic_block_ranges[1])
    assert (0x8002, 3) in {(node.addr, node.size) for node in cfgs[1].model.nodes()}
    assert (0x8002, 5) not in {(node.addr, node.size) for node in cfgs[1].model.nodes()}
