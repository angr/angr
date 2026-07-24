# pylint:disable=broad-exception-caught,missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

import os
import pickle
import unittest

import archinfo
import pypcode
import pyvex
from pyvex.enums import irop_enums_to_ints

import angr
from angr import ailment
from angr.engines.vex.claripy import irop
from angr.rustylib.ailment import RoundingMode, VEXIRSBConverter, _vexop_debug

# pylint: disable=missing-class-docstring
# pylint: disable=line-too-long


class TestIrsb(unittest.TestCase):
    block_bytes = bytes.fromhex(
        "554889E54883EC40897DCC488975C048C745F89508400048C745F0B6064000488B45C04883C008488B00BEA70840004889C7E883FEFFFF"
    )
    block_addr = 0x4006C6

    def test_convert_from_vex_irsb(self):
        arch = archinfo.arch_from_id("AMD64")
        manager = ailment.Manager(arch=arch)
        irsb = pyvex.IRSB(self.block_bytes, self.block_addr, arch, opt_level=0)
        ablock = ailment.IRSBConverter.convert(irsb, manager)
        assert ablock  # TODO: test if this conversion is valid

    def test_convert_from_pcode_irsb(self):
        arch = archinfo.arch_from_id("AMD64")
        manager = ailment.Manager(arch=arch)
        p = angr.load_shellcode(
            self.block_bytes, arch, self.block_addr, self.block_addr, engine=angr.engines.UberEnginePcode
        )
        irsb = p.factory.block(self.block_addr).vex
        ablock = ailment.IRSBConverter.convert(irsb, manager)
        assert ablock  # TODO: test if this conversion is valid

    def test_convert_pcode_uppercase_memory_space(self):
        arch = archinfo.ArchPcode("6502:LE:16:default")
        manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
        translation = pypcode.Context(arch.name).translate(bytes.fromhex("ad34128d7856"), base_address=0)
        load_varnode = translation.ops[1].inputs[0]
        store_varnode = translation.ops[5].output
        assert load_varnode is not None
        assert store_varnode is not None
        assert load_varnode.space.name == store_varnode.space.name == "RAM"

        converter = object.__new__(ailment.PCodeIRSBConverter)
        converter._manager = manager
        converter._statement_idx = 0

        load = converter._get_value(load_varnode)
        store = converter._set_value(store_varnode, ailment.Expr.Const(None, 0xAA, 8))

        assert isinstance(load, ailment.Expr.Load)
        assert isinstance(load.addr, ailment.Expr.Const)
        assert load.addr.value == 0x1234
        assert load.size == 1
        assert isinstance(store, ailment.Stmt.Store)
        assert isinstance(store.addr, ailment.Expr.Const)
        assert store.addr.value == 0x5678
        assert store.size == 1

    def test_lift_path_matches_python_path(self):
        """The direct libVEX-lift fast path must produce the same AIL block as
        converting a cached pyvex Python IRSB."""
        arch = archinfo.arch_from_id("AMD64")
        irsb = pyvex.IRSB(self.block_bytes, self.block_addr, arch, opt_level=0)
        from_py = VEXIRSBConverter.convert(irsb, ailment.Manager(arch=arch))
        from_lift = VEXIRSBConverter.convert_from_lift(
            arch, self.block_addr, self.block_bytes, ailment.Manager(arch=arch), opt_level=0
        )
        assert from_py == from_lift
        assert from_py.statements  # non-empty


class TestNonConstRoundingMode(unittest.TestCase):
    """VEX sometimes carries the rounding mode in a tmp (e.g. ARM ``vcvtr``
    reads it from FPSCR); the converter must pass it through as an AIL
    ``Expression`` rather than dropping it, so the decompilation pipeline can
    resolve it to a constant later."""

    # vcvtr.s32.f64 s0, d1 ; bx lr -- F64toI32S(t_rm, t_val) with a computed rm
    block_bytes = bytes.fromhex("410bbdee1eff2fe1")

    @staticmethod
    def _find_convert(expr):
        if isinstance(expr, ailment.Expr.Convert):
            return expr
        for attr in ("operand", "src"):
            inner = getattr(expr, attr, None)
            if inner is not None:
                found = TestNonConstRoundingMode._find_convert(inner)
                if found is not None:
                    return found
        return None

    def test_tmp_rounding_mode_is_expression(self):
        arch = archinfo.arch_from_id("armel")
        irsb = pyvex.IRSB(self.block_bytes, 0x1000, arch, opt_level=1)
        from_py = VEXIRSBConverter.convert(irsb, ailment.Manager(arch=arch))
        from_lift = VEXIRSBConverter.convert_from_lift(
            arch, 0x1000, self.block_bytes, ailment.Manager(arch=arch), opt_level=1
        )
        assert from_py == from_lift

        conv = next(c for c in (self._find_convert(getattr(s, "src", s)) for s in from_py.statements) if c is not None)
        rm = conv.rounding_mode
        assert isinstance(rm, ailment.expression.Expression)
        assert isinstance(rm, ailment.Expr.Tmp)
        # a rebuilt Convert accepts the expression form back
        rebuilt = ailment.Expr.Convert(
            conv.idx,
            conv.from_bits,
            conv.to_bits,
            conv.is_signed,
            conv.operand,
            from_type=conv.from_type,
            to_type=conv.to_type,
            rounding_mode=rm,
            **dict(conv.tags),
        )
        assert rebuilt == conv
        # serde round-trip keeps the expression form
        assert pickle.loads(pickle.dumps(from_py)) == from_py

    def test_const_rounding_mode_still_enum(self):
        arch = archinfo.arch_from_id("i386")
        irsb = pyvex.IRSB(bytes.fromhex("d8c1c3"), 0x1000, arch, opt_level=1)  # fadd st0, st1 ; ret
        blk = VEXIRSBConverter.convert(irsb, ailment.Manager(arch=arch))
        binop = next(
            s.src
            for s in blk.statements
            if isinstance(getattr(s, "src", None), ailment.Expr.BinaryOp) and s.src.floating_point
        )
        assert isinstance(binop.rounding_mode, RoundingMode)


class TestVexConverterAcrossArches(unittest.TestCase):
    """Convert real blocks from test binaries through both the Python-IRSB path
    and the libVEX-lift path, and assert the two agree."""

    BINARIES = [
        ("x86_64", "x86_64/1after909"),
        ("i386", "i386/fauxware"),
        ("armel", "armel/fauxware"),
        ("ppc", "ppc/fauxware"),
        ("mips", "mips/fauxware"),
        ("s390x", "s390x/fauxware"),
    ]

    def _check_binary(self, path):
        if not os.path.exists(path):
            self.skipTest(f"missing binary {path}")
        p = angr.Project(path, auto_load_libs=False)
        arch = p.arch
        cfg = p.analyses.CFGFast(normalize=True)
        checked = 0
        for node in cfg.model.nodes():
            if not node.size:
                continue
            thumb = bool(getattr(node, "thumb", False))
            lift_addr = (node.addr | 1) if thumb else node.addr
            bytes_offset = 1 if thumb else 0
            try:
                # Generous trailing bytes so thumb boundary decode is deterministic.
                data = bytes(p.loader.memory.load(node.addr, node.size + 32))
            except Exception:
                continue
            try:
                irsb = pyvex.IRSB(data, lift_addr, arch, opt_level=1, bytes_offset=bytes_offset)
            except Exception:
                continue
            if irsb.size == 0:
                continue
            try:
                from_py = VEXIRSBConverter.convert(
                    pyvex.IRSB(data, lift_addr, arch, opt_level=1, bytes_offset=bytes_offset),
                    ailment.Manager(arch=arch),
                )
            except Exception:
                continue
            try:
                from_lift = VEXIRSBConverter.convert_from_lift(
                    arch, lift_addr, data, ailment.Manager(arch=arch), opt_level=1, bytes_offset=bytes_offset
                )
            except Exception:
                # The fast path defers blocks with statements/expressions it can't
                # render byte-identically (MBE/LLSC/PutI, GetI/Qop, ...) to the
                # Python-IRSB path; those are exercised by the fallback.
                continue
            assert from_py == from_lift, f"mismatch at {node.addr:#x} in {path}"
            checked += 1
        assert checked > 0, f"no blocks checked in {path}"

    def test_arches(self):
        base = os.path.join(os.path.dirname(__file__), "..", "..", "..", "binaries", "tests")
        for _name, rel in self.BINARIES:
            with self.subTest(binary=rel):
                self._check_binary(os.path.normpath(os.path.join(base, rel)))


class TestLiftWindowOverread(unittest.TestCase):
    """libVEX decoders may read the full length of an instruction that starts
    inside the lift window, i.e. a few bytes past ``max_bytes`` -- and past the
    end of the buffer when the window ends at it. The fast path must pad such
    windows with NULs (mirroring pyvex) instead of lifting adjacent heap
    garbage, which made the block content (jumpkind, temp numbering)
    nondeterministic."""

    # 38 bytes at 0x400b5a in s390x/fauxware: nopr padding + function prologue,
    # ending with the first 4 bytes of a 6-byte `lg` at 0x400b7c. The last two
    # bytes of the `lg` fall outside the window; whether it decodes depends
    # entirely on out-of-window bytes.
    window = bytes.fromhex("070707070707eb6ff0300024b904001fa7fbff60e310f0000024c0c000000a060707e340f110")
    addr = 0x400B5A

    def test_lift_does_not_read_past_window(self):
        arch = archinfo.arch_from_id("s390x")
        from_py = VEXIRSBConverter.convert(
            pyvex.IRSB(self.window, self.addr, arch, opt_level=1), ailment.Manager(arch=arch)
        )
        # 0x04 completes the truncated `lg`: an unguarded overread decodes it
        # and ends the block Ijk_Boring instead of Ijk_NoDecode.
        backing = bytearray(self.window + b"\x04" * 8)
        from_lift_mv = VEXIRSBConverter.convert_from_lift(
            arch, self.addr, memoryview(backing)[: len(self.window)], ailment.Manager(arch=arch), opt_level=1
        )
        from_lift_bytes = VEXIRSBConverter.convert_from_lift(
            arch, self.addr, self.window, ailment.Manager(arch=arch), opt_level=1
        )
        assert from_py == from_lift_mv
        assert from_py == from_lift_bytes


class TestVexOpParity(unittest.TestCase):
    """The Rust vexop classifier must match Python ``vexop_to_simop`` for every
    VEX op (guards against drift in the hand-ported claripy/irop name-sets)."""

    def test_vexop_parity(self):
        mismatches = []
        for name, op_int in irop_enums_to_ints.items():
            if name in ("Iop_INVALID", "Iop_LAST"):
                continue
            rust = _vexop_debug(op_int)
            try:
                simop = irop.vexop_to_simop(name)
            except Exception:
                # Python considers it unsupported; Rust must too.
                if rust is not None:
                    mismatches.append((name, "python-unsupported but rust-supported"))
                continue
            if rust is None:
                mismatches.append((name, "rust-unsupported but python-supported"))
                continue
            checks = {
                "generic_name": simop._generic_name,
                "output_size_bits": simop._output_size_bits,
                "is_signed": simop.is_signed,
                "is_conversion": simop._conversion is not None,
                "float": simop._float,
                "from_size": simop._from_size,
                "to_size": simop._to_size,
                "vector_count": simop._vector_count,
                "vector_size": simop._vector_size,
            }
            for key, expected in checks.items():
                if rust[key] != expected:
                    mismatches.append((name, f"{key}: rust={rust[key]!r} py={expected!r}"))

        assert not mismatches, "vexop parity mismatches:\n" + "\n".join(f"  {n}: {m}" for n, m in mismatches[:50])


if __name__ == "__main__":
    unittest.main()
