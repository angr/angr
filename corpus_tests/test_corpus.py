"""
Tests using angr's decompiler. We use pytest-insta to create snapshots.
"""

# pylint: disable=import-error
from __future__ import annotations
import logging
import os
import traceback

import angr
from angr.analyses.decompiler.decompilation_options import PARAM_TO_OPTION

bin_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries")

# Invoke this test script with the `pytest --insta` switch to enable the snapshot mechanism

logging.basicConfig(level=logging.CRITICAL, force=True)


def analyze_binary(binary_path: str) -> dict[int, str]:
    """
    Run the binary through CFG generation and extract the decompilation from the
    Decompiler analysis.

    The intention of this analysis function is to use as little angr interfaces
    as possible since they may change over time. If they change, this script
    will need updating.
    """
    project = angr.Project(binary_path, auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True)
    decompilation = {}

    function: angr.knowledge_plugins.functions.function.Function
    for function in sorted(cfg.functions.values(), key=lambda func: func.addr):
        if function.is_plt or function.is_simprocedure:
            continue

        try:
            decomp = project.analyses.Decompiler(
                func=function,
                cfg=cfg,
                # setting show_casts to false because of non-determinism
                options=[
                    (
                        PARAM_TO_OPTION["structurer_cls"],
                        "Phoenix",
                    ),
                    (
                        PARAM_TO_OPTION["show_casts"],
                        False,
                    ),
                ],
            )
        except Exception:  # pylint:disable=broad-exception-caught
            decompilation[function.addr] = traceback.format_exc()
        else:
            if decomp.codegen:
                decompilation[function.addr] = decomp.codegen.text
            else:
                decompilation[function.addr] = "Missing...?"

    return decompilation


def test_decompilation(binary, snapshot):
    decompilation = analyze_binary(os.path.join(bin_location, binary))
    for key in sorted(decompilation):
        assert snapshot(f"{key:x}.txt") == decompilation[key]
