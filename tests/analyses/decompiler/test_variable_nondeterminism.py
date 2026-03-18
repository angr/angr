#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import subprocess
import sys
import unittest
import difflib

from tests.common import bin_location, is_testing

DECOMPILE_SCRIPT = """\
import sys
import angr

project = angr.Project(sys.argv[1], auto_load_libs=False)
project.analyses.CFGFast(normalize=True)
dec = project.analyses.Decompiler(
    sys.argv[2],
    preset="malware",
    use_cache=False,
    update_cache=False,
)
print(dec.codegen.text)
"""


def _decompile_with_seed(seed: int, binary_path: str) -> str:
    """Run the decompiler in a subprocess with a specific PYTHONHASHSEED."""
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = str(seed)
    result = subprocess.run(
        [sys.executable, "-c", DECOMPILE_SCRIPT, binary_path, "sub_4012f5"],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
    assert result.returncode == 0, f"Decompilation failed (seed={seed}):\n{result.stderr}"
    if not is_testing:
        print(result.stdout)
    return result.stdout


class TestVariableNondeterminism(unittest.TestCase):
    def test_stack_variable_naming_stability(self):
        """Regression test for https://github.com/angr/angr/issues/6246.

        The decompiler should produce identical variable names regardless of PYTHONHASHSEED.  We run the decompiler in
        subprocesses with different seeds and compare the output.
        """

        binary_path = os.path.join(
            bin_location,
            "tests",
            "i386",
            "windows",
            "4a00ae5dacc4d7ab43d1da71db43c7df837053a4ed86846fd2d7fcf02a3f861c",
        )
        seeds = list(range(10))
        outputs = {seed: _decompile_with_seed(seed, binary_path) for seed in seeds}
        baseline = outputs[seeds[0]]
        for seed in seeds[1:]:
            if outputs[seed] != baseline:
                if not is_testing:
                    baseline_lines = baseline.splitlines()
                    output_lines = outputs[seed].splitlines()

                    d = difflib.Differ()
                    diff = list(d.compare(baseline_lines, output_lines))
                    for line in diff:
                        print(line)

                assert False, f"Decompiler output differs between PYTHONHASHSEED={seeds[0]} and PYTHONHASHSEED={seed}"


if __name__ == "__main__":
    unittest.main()
