#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from angr.sim_type import SimTypePointer, SimStruct, TypeRef

from tests.common import bin_location, print_decompilation_result, WORKER

test_location = os.path.join(bin_location, "tests")


class TestTypePropagation(unittest.TestCase):
    def test_reverse_type_propagation(self):
        bin_path = os.path.join(test_location, "x86_64", "type_inference_2")
        proj = angr.Project(bin_path)
        cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=not WORKER)
        proj.analyses.CompleteCallingConventions()

        func_evaluate = cfg.functions["evaluate"]
        dec = proj.analyses.Decompiler(func_evaluate)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        func_evaluate_proto = func_evaluate.prototype
        assert func_evaluate_proto is not None
        assert len(func_evaluate_proto.args) == 2
        assert isinstance(func_evaluate_proto.args[0], SimTypePointer)
        assert isinstance(func_evaluate_proto.args[0].pts_to, TypeRef)
        assert isinstance(func_evaluate_proto.args[0].pts_to.ty, SimStruct)
        struct_ty = func_evaluate_proto.args[0].pts_to.ty

        func_run = cfg.functions["run_calculator"]
        dec = proj.analyses.Decompiler(func_run)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert re.search(struct_ty.name + r" v\d+;", dec.codegen.text) is not None


if __name__ == "__main__":
    unittest.main()
