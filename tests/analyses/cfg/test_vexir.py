#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import struct
import unittest

import pyvex
from archinfo.arch_arm import ArchARM
from pyvex import expr as E
from pyvex import stmt as S
from pyvex.enums import get_int_from_enum
from pyvex.lifting.libvex import _libvex_lock

import angr
from angr.rustylib.vexlift import VexLifter
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _const(c):
    if c.tag in ("Ico_F32", "Ico_F32i"):
        return c.tag, struct.unpack("<I", struct.pack("<f", c.value))[0]
    if c.tag in ("Ico_F64", "Ico_F64i"):
        return c.tag, struct.unpack("<Q", struct.pack("<d", c.value))[0]
    return c.tag, int(c.value)


def _expr(e):  # pylint:disable=too-many-return-statements
    if e is None:
        return None
    t = type(e)
    if t is E.Binder:
        return ("Binder", e.binder)
    if t is E.Get:
        return ("Get", e.offset, e.ty)
    if t is E.GetI:
        return ("GetI", (e.descr.base, e.descr.elemTy, e.descr.nElems), _expr(e.ix), e.bias)
    if t is E.RdTmp:
        return ("RdTmp", e.tmp)
    if t in (E.Qop, E.Triop, E.Binop, E.Unop):
        return (t.__name__, e.op, tuple(_expr(a) for a in e.args))
    if t is E.Load:
        return ("Load", e.end, e.ty, _expr(e.addr))
    if t is E.Const:
        return ("Const", _const(e.con))
    if t is E.ITE:
        return ("ITE", _expr(e.cond), _expr(e.iftrue), _expr(e.iffalse))
    if t is E.CCall:
        return ("CCall", e.retty, e.cee.name, tuple(_expr(a) for a in e.args))
    if t is E.VECRET:
        return ("VECRET",)
    if t is E.GSPTR:
        return ("GSPTR",)
    raise TypeError(t)


def _stmt(s):  # pylint:disable=too-many-return-statements
    t = type(s)
    if t is S.NoOp:
        return ("NoOp",)
    if t is S.IMark:
        return ("IMark", s.addr, s.len, s.delta)
    if t is S.AbiHint:
        return ("AbiHint", _expr(s.base), s.len, _expr(s.nia))
    if t is S.Put:
        return ("Put", s.offset, _expr(s.data))
    if t is S.PutI:
        return ("PutI", (s.descr.base, s.descr.elemTy, s.descr.nElems), _expr(s.ix), s.bias, _expr(s.data))
    if t is S.WrTmp:
        return ("WrTmp", s.tmp, _expr(s.data))
    if t is S.Store:
        return ("Store", s.end, _expr(s.addr), _expr(s.data))
    if t is S.LoadG:
        return ("LoadG", s.end, get_int_from_enum(s.cvt), s.dst, _expr(s.addr), _expr(s.alt), _expr(s.guard))
    if t is S.StoreG:
        return ("StoreG", s.end, _expr(s.addr), _expr(s.data), _expr(s.guard))
    if t is S.CAS:
        return (
            "CAS",
            _expr(s.addr),
            _expr(s.dataLo),
            _expr(s.dataHi),
            _expr(s.expdLo),
            _expr(s.expdHi),
            s.oldLo,
            s.oldHi,
            s.end,
        )
    if t is S.LLSC:
        return ("LLSC", s.end, s.result, _expr(s.addr), _expr(s.storedata))
    if t is S.Dirty:
        args = tuple(_expr(a) for a in s.args)
        return ("Dirty", s.cee.name, _expr(s.guard), args, s.tmp, s.mFx, _expr(s.mAddr), s.mSize, s.nFxState)
    if t is S.MBE:
        return ("MBE", s.event)
    if t is S.Exit:
        return ("Exit", _expr(s.guard), _const(s.dst), s.jk, s.offsIP)
    raise TypeError(t)


def canonical(irsb: pyvex.IRSB):
    return [_stmt(s) for s in irsb.statements], _expr(irsb.next), list(irsb.tyenv.types)


class TestVexIr(unittest.TestCase):
    def _check(self, name: str, max_blocks: int = 400):
        proj = angr.Project(os.path.join(test_location, name), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.loader.gen_ro_memview()
        memory = proj.loader.memory_ro_view
        assert memory is not None
        lifter = VexLifter(
            proj.arch.vex_arch,
            proj.arch.vex_archinfo,
            isinstance(proj.arch, ArchARM),
            memory._flattened_backers,
            _libvex_lock,
        )
        stops = set(cfg._known_thunks)
        engine = proj.factory.default_engine
        compared = 0
        nodes = sorted((n for n in cfg.graph.nodes() if n.size and not n.is_simprocedure), key=lambda n: n.addr)
        for node in nodes[:max_blocks]:
            # the lifts the resolvers see: _create_jobs's sized lift, Blade's and the deferred loop's max-size lifts
            for size, cross, with_stops in ((node.size, False, True), (None, True, False), (None, False, True)):
                engine.clear_cache()
                ref = proj.factory.block(
                    node.addr, size=size, cross_insn_opt=cross, extra_stop_points=stops if with_stops else None
                ).vex
                ir = lifter.lift_ir(
                    node.addr, size or 400, 1, cross, False, proj._sim_procedures, stops if with_stops else None
                )
                if ir is None:
                    continue
                stmts, nxt, tyenv = ir.to_tuple()
                assert (list(stmts), nxt, list(tyenv)) == canonical(ref), hex(node.addr)
                assert (ir.addr, ir.size, ir.jumpkind, ir.instructions) == (
                    ref.addr,
                    ref.size,
                    ref.jumpkind,
                    ref.instructions,
                )
                assert list(ir.instruction_addresses) == list(ref.instruction_addresses)
                compared += 1
        assert compared > 0

    def test_amd64(self):
        self._check("x86_64/fauxware")

    def test_x86(self):
        self._check("i386/fauxware")

    def test_armel(self):
        self._check("armel/fauxware")

    def test_thumb(self):
        self._check("armel/arm_thumb_filter_jump_successors")

    def test_mips(self):
        self._check("mips/fauxware")

    def test_aarch64(self):
        self._check("aarch64/test_arrays")

    def test_ppc64(self):
        self._check("ppc64/fauxware")

    def test_stop_point_cut(self):
        # a hook in the middle of a block cuts the statement lift there, as VEXLifter._first_stoppoint does
        proj = angr.Project(os.path.join(test_location, "x86_64/fauxware"), auto_load_libs=False)
        proj.loader.gen_ro_memview()
        memory = proj.loader.memory_ro_view
        assert memory is not None
        lifter = VexLifter(proj.arch.vex_arch, proj.arch.vex_archinfo, False, memory._flattened_backers, _libvex_lock)
        main = proj.loader.find_symbol("main").rebased_addr
        full = proj.factory.block(main).vex
        cut_at = full.instruction_addresses[2]
        ir = lifter.lift_ir(main, 400, 1, False, False, proj._sim_procedures, {cut_at})
        assert ir is not None
        assert ir.addr + ir.size == cut_at
        ref = proj.factory.block(main, cross_insn_opt=False, extra_stop_points={cut_at}).vex
        assert list(ir.to_tuple()[0]) == canonical(ref)[0]


if __name__ == "__main__":
    unittest.main()
