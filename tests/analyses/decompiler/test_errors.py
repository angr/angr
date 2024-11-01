from __future__ import annotations
import os
import tempfile
import unittest
import angr
from angr.angrdb import AngrDB
from angr.analyses.decompiler.peephole_optimizations import PeepholeOptimizationStmtBase
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class BadOptimizerException(Exception):
    pass


class BadPeepholeException(Exception):
    pass


class BadOptimizationPass(angr.analyses.decompiler.optimization_passes.optimization_pass.OptimizationPass):
    def __init__(self, *args, **kwargs):
        raise BadOptimizerException("bad")

    STAGE = angr.analyses.decompiler.optimization_passes.OptimizationPassStage.AFTER_AIL_GRAPH_CREATION


class BadPeepholeOptimization(PeepholeOptimizationStmtBase):
    def optimize(self, *args, **kwargs):
        raise BadPeepholeException("Bad")


class TestDecompilerErrors(unittest.TestCase):
    def test_errors(self):
        bin_path = os.path.join(test_location, "x86_64", "all")
        p = angr.Project(bin_path, auto_load_libs=False)
        main = p.loader.find_symbol("main").rebased_addr
        p.analyses.CFGFast(normalize=True)
        try:
            _result = p.analyses[angr.analyses.Decompiler].prep(fail_fast=True)(
                func=main, optimization_passes=[BadOptimizationPass], peephole_optimizations=[BadPeepholeOptimization]
            )
        except BadOptimizerException:
            pass
        else:
            assert False, "Must raise BadException"

        try:
            decomp = p.analyses[angr.analyses.Decompiler].prep(fail_fast=False)(
                func=main, optimization_passes=[BadOptimizationPass], peephole_optimizations=[BadPeepholeOptimization]
            )
        except (BadPeepholeException, BadOptimizerException):
            assert False, "Must not raise BadException"

        assert decomp.codegen is None
        assert decomp.errors

        dtemp = tempfile.mkdtemp()
        db_file = os.path.join(dtemp, "fauxware.adb")
        db = AngrDB(p)
        db.dump(db_file)

        p2 = AngrDB().load(db_file)
        cached = p2.kb.decompilations[(main, "pseudocode")]
        assert cached.errors

        try:
            decomp = p.analyses[angr.analyses.Decompiler].prep(fail_fast=False)(
                func=main, optimization_passes=[BadOptimizationPass]
            )
        except (BadPeepholeException, BadOptimizerException):
            assert False, "Must not raise BadException"

        assert decomp.codegen.text is not None
