# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import time
from unittest import TestCase, main

import angr
from angr.knowledge_plugins.key_definitions.atoms import Register

# A basic block excerpted from a stripped x86-64 binary: 22 and/cmp/cmov steps on rcx/rdx, ending in a
# call that is replaced with ret. ReachingDefinitions used to double its value sets on every cmov.
CMOV_CHAIN = (
    bytes.fromhex(
        "554889e553504889fb488b87f8050000c7870807000000020000c6872806000001488b48080f57c00f11870006000048c787100600"
        "0000000000488d05f73744004889ca4881ca0000060083780c00480f44d14889d14881e1fbffdfff83781000480f45ca4889ca4881"
        "e2f7ffbfff83781400480f45d14889d14881e1fffbffff83783800480f45ca4889ca4881e2ff7fffff83784800480f45d14889d148"
        "83e1ef83780800480f44d183781800480f44d14889d14883e1df83781c00480f45ca4889ca4881e2bffffffd83782000480f45d148"
        "89d14881e17ffffffb83782400480f45ca48bafffffefff7ffffff4821ca83784c00480f45d14889d14881e1fffeffff83782800480f"
        "45ca4889ca4881e2ffdfffff83783400480f45d14889d14881e1fffdffff83782c00480f45ca4889ca4881e2fffff7ff8378300048"
        "0f45d148b9ffbffffffdffffff4821d183784400480f45ca4889ca4881e2fff7ffbf83783c00480f45d148bfffefff7fffffffff48"
        "21d783784000480f45fa"
    )
    + b"\xc3"
)


class TestCmovChain(TestCase):
    def test_rda_cmov_chain_value_sets_are_bounded(self):
        proj = angr.load_shellcode(CMOV_CHAIN, "AMD64", load_address=0xA07A20)
        cfg = proj.analyses.CFGFast()
        func = cfg.functions[0xA07A20]
        assert len(func.block_addrs_set) == 1

        start = time.time()
        rda = proj.analyses.ReachingDefinitions(func, observe_all=True)
        elapsed = time.time() - start
        assert elapsed < 5.0, f"RDA took {elapsed:.1f}s"

        end_state = rda.model.observed_results[("node", 0xA07A20, 1)]
        limit = end_state.registers._element_limit
        for reg_name in ("rcx", "rdx", "rdi"):
            reg_offset, reg_size = proj.arch.registers[reg_name]
            mv = end_state.registers.load(reg_offset, size=reg_size)
            for values in mv.values():
                assert len(values) <= limit

        # the definitions of rdi at the end of the block must survive the collapse
        rdi_defs = list(end_state.get_definitions(Register(proj.arch.registers["rdi"][0], 8, proj.arch)))
        assert rdi_defs


if __name__ == "__main__":
    main()
