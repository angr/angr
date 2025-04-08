"""
Tests using angr's decompiler. We use pytest-insta to create snapshots.
"""

# pylint: disable=import-error
from __future__ import annotations
import json
import logging
import re

import angr
from angr.analyses.decompiler.decompilation_options import PARAM_TO_OPTION

# Invoke this test script with the `pytest --insta` switch to enable the snapshot mechanism

logging.basicConfig(level=logging.CRITICAL, force=True)

SNAPSHOTS_REPO_BASE_URL = "https://github.com/project-purcellville/snapshots-0000/"


def analyze_binary(binary_path: str) -> dict:
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
    for function in cfg.functions.values():
        function.normalize()
        func_key = f"{function.addr}:{function.name}"

        # Wrapping in a try/except because the decompiler sometimes fails
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
        except Exception as ex:  # pylint:disable=broad-exception-caught
            print(
                "\n".join(
                    [
                        f'Exception decompiling "{func_key}()" in "{binary_path}":',
                        f"{ex}\nContinuing with other functions.",
                    ]
                )
            )

        if decomp.codegen:
            decompilation[func_key] = decomp.codegen.text
        else:
            decompilation[func_key] = None

    return decompilation


def create_diffable_decompilation(decompiler_output: dict) -> str | None:
    """
    Convert the decompiler output `dict` into JSON, but also modify it to
    allow easy diffing (appending actual newlines '\n' to escaped newlines
    '\\n', etc.), returning the result as a string.
    """
    try:
        decompiler_json = json.dumps(decompiler_output)
        decompiler_json_newlined = re.sub("\\\\n", "\\\\n\n", decompiler_json)
    except Exception as ex:  # pylint:disable=broad-exception-caught
        print(f"Exception converting decompiler output to newlined-JSON:\n{ex}")
        return None
    return decompiler_json_newlined


def test_decompilation(binary, snapshot):
    decompilation = analyze_binary(binary)
    if not decompilation:
        # Message already emitted.
        return

    # Adds newlines after each newline literal '\\n'.
    diffable_decompilation = create_diffable_decompilation(decompilation)

    print(f'Loading snapshot "{binary}".')
    assert snapshot(binary) == diffable_decompilation
