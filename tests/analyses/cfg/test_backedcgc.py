from __future__ import annotations

from pathlib import Path

import angr
from tests.common import bin_location


def test_cfgfast_consumes_backed_cgc_register_mapping():
    entry = 0x8048FB4
    binary = Path(bin_location) / "tests" / "i386" / "patchrex" / "indirect_jump_test_Ofast"
    project = angr.Project(
        binary,
        auto_load_libs=False,
        main_opts={
            "backend": "backedcgc",
            "memory_backer": {},
            "register_backer": {"eip": entry},
        },
    )

    cfg = project.analyses.CFGFast(
        normalize=True,
        regions=[(entry, entry + 0x100)],
        function_starts=[entry],
    )

    assert entry in cfg.functions
