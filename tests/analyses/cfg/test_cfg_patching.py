#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest
import logging
import tempfile
from typing import TYPE_CHECKING
from collections.abc import Sequence

import angr
from angr.analyses import CFGFast
from angr.knowledge_plugins.cfg import MemoryData, MemoryDataSort

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg import CFGModel
    from angr.knowledge_plugins.functions import Function, FunctionManager

from ...common import bin_location


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
FAUXWARE_PATH = os.path.join(bin_location, "tests", "x86_64", "fauxware")


def apply_patches(proj: angr.Project, patches: list[tuple[int, str]]):
    for addr, asm in patches:
        patch_bytes = proj.arch.keystone.asm(asm, addr, as_bytes=True)[0]
        proj.kb.patches.add_patch(addr, patch_bytes)


def assert_models_equal(model_a: CFGModel, model_b: CFGModel):
    assert model_a.graph.nodes() == model_b.graph.nodes()
    assert model_a.graph.edges() == model_b.graph.edges()
    # FIXME: Check more


def assert_function_graphs_equal(function_a: Function, function_b: Function):
    nodes_a = function_a.graph.nodes()
    nodes_b = function_b.graph.nodes()
    if nodes_a != nodes_b:
        log.error("Differing nodes!\nFunction:%s\nNodes A: %s\nNodes B: %s", function_a, nodes_a, nodes_b)
        assert False
    # FIXME: Check more


def assert_all_function_equal(functions_a: FunctionManager, functions_b: FunctionManager):
    for f in functions_b:
        assert f in functions_a, f"Extra function: {functions_b[f]}"
    for f in functions_a:
        assert f in functions_b, f"Missing function: {functions_a[f]}"
        assert_function_graphs_equal(functions_a[f], functions_b[f])


class TestCfgCombination(unittest.TestCase):
    """
    Tests that CFGFast can run with a prior model.
    """

    def test_cfgfast_combine_with_full_model(self):
        """Run CFGFast once, then again with the model of the first."""
        proj = angr.Project(FAUXWARE_PATH, auto_load_libs=False)
        cfg_a = proj.analyses[CFGFast].prep()()
        cfg_b = proj.analyses[CFGFast].prep()(model=cfg_a.model.copy())
        assert_models_equal(cfg_a.model, cfg_b.model)
        assert_all_function_equal(cfg_a.functions, cfg_b.functions)

    def test_cfgfast_combine_with_partial_model(self):
        """Run CFGFast on a region, then again on a second region with the model of the first."""

        # Initial analysis just to pick up expected addresses
        proj = angr.Project(FAUXWARE_PATH, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()()
        accepted_addr = cfg.functions["accepted"].addr
        rejected_addr = cfg.functions["rejected"].addr
        accepted_regions = [(n.addr, n.addr + n.size) for n in cfg.functions["accepted"].nodes]
        rejected_regions = [(n.addr, n.addr + n.size) for n in cfg.functions["rejected"].nodes]

        # Run partial analysis on the nodes we care about
        proj = angr.Project(FAUXWARE_PATH, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(regions=accepted_regions)
        assert accepted_addr in cfg.functions.function_addrs_set
        assert rejected_addr not in cfg.functions.function_addrs_set

        # Check continued analysis over another region combines correctly
        cfg = proj.analyses[CFGFast].prep()(regions=rejected_regions, model=cfg.model.copy())
        assert accepted_addr in cfg.functions.function_addrs_set
        assert rejected_addr in cfg.functions.function_addrs_set

        # Check analysis over union of regions yields same result
        proj = angr.Project(FAUXWARE_PATH, auto_load_libs=False)
        regions = accepted_regions + rejected_regions
        cfg_combined = proj.analyses[CFGFast].prep()(regions=regions)
        assert_models_equal(cfg.model, cfg_combined.model)
        assert_all_function_equal(cfg.functions, cfg_combined.functions)

    # FIXME: Add test of first analyzing a function A, then analyzing a function B called by A


class TestCfgReclassification(unittest.TestCase):
    """
    Tests that code/data can be reclassified in CFG.
    """

    def test_cfgfast_preclassify_code_as_data(self):
        """Classify a code region as data in an empty model, run CFGFast, ensure region remains classified as data."""
        proj = angr.Project(FAUXWARE_PATH, auto_load_libs=False)
        model = proj.kb.cfgs.new_model("initial")
        md = MemoryData(0x40069D, 22, MemoryDataSort.String)
        model.memory_data[md.addr] = md.copy()
        cfg = proj.analyses[CFGFast].prep()(model=model)
        assert cfg.model.memory_data[md.addr] == md

        # Make sure the memory data item is not covered by any node
        assert len(cfg.functions["authenticate"].graph.nodes) == 5
        for n in cfg.functions["authenticate"].graph.nodes:
            assert md.addr >= (n.addr + n.size) or n.addr >= (md.addr + md.size)
            if (n.addr + n.size) == md.addr:
                log.debug("Found adjacent node %s", n)
                # FIXME: Successor address is still the same

        # FIXME: Also test at function boundary

    def test_cfgfast_reclassify_code_as_data(self):
        """Run CFGFast, re-classify code within a function as data, then re-flow the function."""
        proj = angr.Project(FAUXWARE_PATH, auto_load_libs=False)

        # Initial analysis
        cfg = proj.analyses[CFGFast].prep()()
        func = cfg.functions["authenticate"]
        function_addr = func.addr
        original_number_of_nodes = len(func.graph.nodes)

        # Define the data region and run analysis for function reconstruction
        md = MemoryData(0x40069D, 22, MemoryDataSort.String)
        cfg.model.memory_data[md.addr] = md.copy()
        cfg.model.clear_region_for_reflow(func.addr)
        cfg = proj.analyses[CFGFast].prep()(
            symbols=False,
            function_prologues=False,
            start_at_entry=False,
            force_smart_scan=False,
            force_complete_scan=False,
            function_starts=[function_addr],
            model=cfg.model,
        )

        # Check memory data remains as configured and is not overlapped by any node
        assert cfg.model.memory_data[md.addr] == md
        assert len(cfg.functions["authenticate"].graph.nodes) == 5
        for n in cfg.functions["authenticate"].graph.nodes:
            assert md.addr >= (n.addr + n.size) or n.addr >= (md.addr + md.size)

        # Now re-define the data as code again and ensure we have the correct number of nodes
        del cfg.model.memory_data[md.addr]
        cfg.model.clear_region_for_reflow(func.addr)
        cfg = proj.analyses[CFGFast].prep()(
            symbols=False,
            function_prologues=False,
            start_at_entry=False,
            force_smart_scan=False,
            force_complete_scan=False,
            function_starts=[function_addr],
            model=cfg.model,
        )

        assert len(cfg.functions["authenticate"].graph.nodes) == original_number_of_nodes

        # FIXME: Test at function boundary

    # FIXME: Test at partial offset into some data item
    def test_cfgfast_preclassify_data_as_code(self):
        """Classify some code that would not normally be classified as code."""
        code = """
        _start:
            ret

        not_discovered:
            xor rax, rax
            mov rcx, 5
            .here:
            inc rax
            dec rcx
            jnz .here
            ret
        """

        not_discovered_addr = 0x1
        proj = angr.load_shellcode(code, "AMD64")
        cfg = proj.analyses[CFGFast].prep()(force_smart_scan=False)
        assert len(cfg.functions) == 1

        proj = angr.load_shellcode(code, "AMD64")
        cfg = proj.analyses[CFGFast].prep()(force_smart_scan=False, function_starts=[not_discovered_addr])
        assert len(cfg.functions) == 2
        assert len(cfg.functions[not_discovered_addr].block_addrs) == 3

    def test_cfgfast_reclassify_data_as_code(self):
        """Run CFGFast, then re-classify some assumed data as code and run again."""
        code = """
        _start:
            mov rax, [not_discovered]
            ret

        not_discovered:
            xor rax, rax
            mov rcx, 5
            .here:
            inc rax
            dec rcx
            jnz .here
            ret
        """

        proj = angr.load_shellcode(code, "AMD64")
        cfg = proj.analyses[CFGFast].prep()(force_smart_scan=False)
        assert len(cfg.functions) == 1
        not_discovered_addr = 0xB
        del cfg.model.memory_data[not_discovered_addr]
        cfg = proj.analyses[CFGFast].prep()(
            start_at_entry=False, force_smart_scan=False, function_starts=[not_discovered_addr], model=cfg.model
        )
        assert len(cfg.functions) == 2
        assert len(cfg.functions[0xB].block_addrs) == 3


class TestCfgPatching(unittest.TestCase):
    """
    Test that patches made to the binary are correctly reflected in CFG.
    """

    def _test_patch(self, patches: Sequence[tuple[int, str]]):
        unpatched_binary_path = FAUXWARE_PATH
        common_cfg_options = {
            "normalize": True,
            "resolve_indirect_jumps": True,
            "data_references": True,
            # "force_smart_scan": False,
        }

        # Create and load a pre-patched binary
        log.debug("Recovering pre-patched CFG")
        proj = angr.Project(unpatched_binary_path, auto_load_libs=False)
        apply_patches(proj, patches)

        with tempfile.NamedTemporaryFile(prefix="fauxware-patched-", delete=False) as f:
            f.write(proj.kb.patches.apply_patches_to_binary())
            f.close()
            prepatched_proj = angr.Project(f.name, auto_load_libs=False)
            expected_cfg = prepatched_proj.analyses[CFGFast].prep()(**common_cfg_options)

            # Now create a new project, recover CFG, then patch and recover CFG again
            proj = angr.Project(unpatched_binary_path, auto_load_libs=False)
            log.debug("Recovering CFG before patching")
            cfg_before_patching = proj.analyses[CFGFast].prep()(**common_cfg_options)
            apply_patches(proj, patches)

            log.debug("Recovering CFG after patching")
            for p in proj.kb.patches.values():
                cfg_before_patching.model.clear_region_for_reflow(p.addr, len(p.new_bytes))
            cfg_after_patching = proj.analyses[CFGFast].prep()(**common_cfg_options, model=cfg_before_patching.model)

            # Verify that the CFG of the patched binary matches the CFG of the pre-patched binary
            assert_models_equal(expected_cfg.model, cfg_after_patching.model)

            os.unlink(f.name)

    #
    # Patches that do not change block or function size
    #

    def test_cfg_patch_const_operand(self):
        """
        Patch a block, changing a data reference, with no effect on control.

        Change print of "Username: " to "Password: ".
        """
        self._test_patch([(0x400734, "mov edi, 0x400920")])

    def test_cfg_patch_ret_value(self):
        """
        Patch a block to redirect control, without changing the graph.

        Change return value of `authenticate` in rejection branch to 1.
        """
        self._test_patch([(0x4006E6, "mov eax, 1")])

    def test_cfg_patch_branch(self):
        """
        Patch a block, changing the graph.

        Patch `authenticate` to always jump to accept branch, eliminating 1 block.
        """
        self._test_patch([(0x4006DD, "jne 0x4006df")])

    def test_cfg_patch_call_target(self):
        """
        Patch a block, changing the graph, eliminate a cross reference.

        Change call of `rejected` to `accepted`.
        """
        self._test_patch([(0x4007CE, "call 0x4006ed")])

    # FIXME: Patches that change indirect jumps

    #
    # Patches that shrink blocks/function
    #

    def test_cfg_patch_shrink_encoding(self):
        """
        Shorten a block, but do not change graph.

        Use a shorter instruction encoding.
        """
        self._test_patch([(0x4006DF, "xor eax, eax;  inc eax;  jmp 0x4006eb")])

    def test_cfg_patch_shrink_branch(self):
        """
        Shorten a block, changing the graph.

        Remove `strcmp` check in `authenticate`, just jump to accept branch.
        """
        self._test_patch([(0x4006DB, "jmp 0x4006df")])

    def test_cfg_patch_shrink_ret_value(self):
        """
        Shorten a block, truncating a function.

        Patch `authenticate` to always return 1
        """
        self._test_patch([(0x400664, "xor rax, rax;  inc rax;  ret")])

    #
    # Patches that grow blocks
    #

    def test_cfg_patch_grow_block_fallthru(self):
        """
        Patch a block to cover another block.

        Ignore return value of `authenticate`, fallthru to accept branch.
        """
        self._test_patch([(0x4007BB, "nop;  nop;")])

    def test_cfg_patch_grow_nocall(self):
        """
        Patch a block to eliminate all cross references to a function.

        Patch out call to `authenticate`, fall thru.
        """
        self._test_patch([(0x4007AE, "xor rax, rax;  nop;  nop")])

    def test_cfg_patch_grow_into_inter_function_padding(self):
        """
        Patch a block to grow into padded space between functions.

        Prepend several NOPs to the last block of `main`.
        """
        self._test_patch([(0x4007D3, "nop; nop; nop; nop; leave; ret")])

    def test_cfg_patch_grow_function_fallthru(self):
        """
        Patch a block that extends into another function.

        Cut off the end of `authenticate` so it falls into `accepted`.
        """
        self._test_patch([(0x4006EC, "nop")])
        # Will we have two functions? accepted() is still called so it will probably mark a function


if __name__ == "__main__":
    logging.basicConfig()
    log.setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.cfg.cfg_fast").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.cfg.cfg_base").setLevel(logging.DEBUG)
    unittest.main()
