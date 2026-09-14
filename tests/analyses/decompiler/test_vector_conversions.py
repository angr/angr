# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
from unittest import TestCase, main

import angr

binaries_base = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "..", "binaries", "tests")


class TestVectorConversions(TestCase):
    """
    Lane-wise float/int conversions decompile to intrinsic-style conversions in both flavors instead of failing
    (issue #7134). The binaries come from binaries/tests_src/vector_conversions*.c.
    """

    def _check(self, arch: str, expected: dict[str, str]):
        proj = angr.Project(os.path.join(binaries_base, arch, "vector_conversions"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions()

        for name, intrinsic in expected.items():
            for flavor in ("pseudocode", "rust"):
                dec = proj.analyses.Decompiler(proj.kb.functions[name], cfg=cfg.model, flavor=flavor)
                assert dec.codegen is not None, f"{name} ({flavor}) failed to decompile"
                text = dec.codegen.text
                assert text is not None
                assert intrinsic in text, f"{name} ({flavor}):\n{text}"
                assert "unsupported_" not in text and "UnaryOp V" not in text, text

    def test_amd64_sse(self):
        # cvttps2dq / cvtps2dq -> Iop_F32toI32Sx4, cvtdq2ps -> Iop_I32StoF32x4
        self._check(
            "x86_64",
            {
                "truncate_to_ints": "ConvF32toI32Sx4(",
                "round_to_ints": "ConvF32toI32Sx4(",
                "ints_to_floats": "ConvI32StoF32x4(",
            },
        )

    def test_armhf_neon(self):
        # vcvt.{s32,u32}.f32 -> Iop_F32toI32{S,U}x4_RZ, vcvt.f32.{s32,u32} -> Iop_I32{S,U}toF32x4_DEP
        self._check(
            "armhf",
            {
                "truncate_to_ints": "ConvF32toI32Sx4(",
                "truncate_to_uints": "ConvF32toI32Ux4(",
                "ints_to_floats": "ConvI32StoF32x4(",
                "uints_to_floats": "ConvI32UtoF32x4(",
            },
        )


if __name__ == "__main__":
    main()
