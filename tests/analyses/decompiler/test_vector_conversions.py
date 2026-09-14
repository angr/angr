# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
from unittest import TestCase, main

import angr

binaries_base = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "..", "binaries", "tests")


class TestVectorConversions(TestCase):
    """
    Lane-wise SSE conversions (cvttps2dq, cvtdq2ps, cvtps2dq) decompile to intrinsic-style conversions instead of
    failing (issue #7134).
    """

    def test_sse_conversions_decompile(self):
        bin_path = os.path.join(binaries_base, "x86_64", "vector_conversions")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions()

        expected = {
            "truncate_to_ints": "ConvF32toI32Sx4(",
            "round_to_ints": "ConvF32toI32Sx4(",
            "ints_to_floats": "ConvI32toF32x4(",
        }
        for name, intrinsic in expected.items():
            for flavor in ("pseudocode", "rust"):
                dec = proj.analyses.Decompiler(proj.kb.functions[name], cfg=cfg.model, flavor=flavor)
                assert dec.codegen is not None, f"{name} ({flavor}) failed to decompile"
                text = dec.codegen.text
                assert intrinsic in text, f"{name} ({flavor}):\n{text}"
                assert "unsupported_" not in text and "UnaryOp V" not in text, text


if __name__ == "__main__":
    main()
