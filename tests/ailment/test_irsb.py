# pylint:disable=broad-exception-caught,missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

import os
import pickle
import re
import unittest
from typing import cast

import archinfo
import pypcode
import pyvex
from pyvex.enums import enums_to_ints, irop_enums_to_ints
from pyvex.types import Arch as PyvexArch

import angr
from angr import ailment
from angr.engines.pcode.lifter import IRSB as PCodeIRSB
from angr.engines.vex.claripy import irop
from angr.rustylib.ailment import (  # pylint:disable=import-error,no-name-in-module
    RoundingMode,
    VEXIRSBConverter,
    _vexop_debug,
)

# pylint: disable=missing-class-docstring
# pylint: disable=line-too-long


def _vex_arch(arch: archinfo.Arch) -> PyvexArch:
    """archinfo's Arch does not nominally satisfy pyvex's Arch protocol (RegisterOffset/Endness vs int/str)."""
    return cast(PyvexArch, arch)


class TestIrsb(unittest.TestCase):
    block_bytes = bytes.fromhex(
        "554889E54883EC40897DCC488975C048C745F89508400048C745F0B6064000488B45C04883C008488B00BEA70840004889C7E883FEFFFF"
    )
    block_addr = 0x4006C6

    def test_convert_from_vex_irsb(self):
        arch = archinfo.arch_from_id("AMD64")
        manager = ailment.Manager()
        irsb = pyvex.IRSB(self.block_bytes, self.block_addr, _vex_arch(arch), opt_level=0)
        ablock = ailment.IRSBConverter.convert(irsb, manager)
        assert ablock  # TODO: test if this conversion is valid

    def test_convert_from_pcode_irsb(self):
        arch = archinfo.arch_from_id("AMD64")
        manager = ailment.Manager()
        p = angr.load_shellcode(
            self.block_bytes, arch, self.block_addr, self.block_addr, engine=angr.engines.UberEnginePcode
        )
        irsb = p.factory.block(self.block_addr).vex
        ablock = ailment.IRSBConverter.convert(irsb, manager)
        assert ablock  # TODO: test if this conversion is valid

    def test_convert_pcode_uppercase_memory_space(self):
        arch = archinfo.ArchPcode("6502:LE:16:default")
        manager = ailment.Manager()
        translation = pypcode.Context(arch.name).translate(bytes.fromhex("ad34128d7856"), base_address=0)
        load_varnode = translation.ops[1].inputs[0]
        store_varnode = translation.ops[5].output
        assert load_varnode is not None
        assert store_varnode is not None
        assert load_varnode.space.name == store_varnode.space.name == "RAM"

        converter = object.__new__(ailment.PCodeIRSBConverter)
        converter._irsb = PCodeIRSB.empty_block(arch, 0)
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
        irsb = pyvex.IRSB(self.block_bytes, self.block_addr, _vex_arch(arch), opt_level=0)
        from_py = VEXIRSBConverter.convert(irsb, ailment.Manager())
        from_lift = VEXIRSBConverter.convert_from_lift(
            arch, self.block_addr, self.block_bytes, ailment.Manager(), opt_level=0
        )
        assert from_py == from_lift
        assert from_py.statements  # non-empty


class TestSkippedExits(unittest.TestCase):
    def test_sigbus_alignment_exit_is_dropped(self):
        # ldar x1, [x1] ; str x1, [sp, #0x28]
        # libVEX guards ldar with an Ijk_SigBUS alignment-check exit to the instruction itself. Converting it would
        # leave a mid-block ConditionalJump that later passes mistake for a head-controlled loop.
        arch = archinfo.arch_from_id("AARCH64")
        irsb = pyvex.IRSB(bytes.fromhex("21fcdfc8e11700f9"), 0x1000, _vex_arch(arch), opt_level=1)
        assert any(isinstance(stmt, pyvex.IRStmt.Exit) and stmt.jumpkind == "Ijk_SigBUS" for stmt in irsb.statements)
        block = VEXIRSBConverter.convert(irsb, ailment.Manager())
        assert not any(isinstance(stmt, ailment.Stmt.ConditionalJump) for stmt in block.statements)
        assert isinstance(block.statements[-1], ailment.Stmt.Jump)
        assert block.statements[-1].target.value == 0x1008


class TestDirtyWithoutMemoryEffect(unittest.TestCase):
    def test_rdmsr_dirty_helper(self):
        # rdmsr lifts to a DIRTY helper whose pyvex mFx/mSize are None (no memory effect); the converter must
        # accept them instead of failing on a missing str.
        arch = archinfo.arch_from_id("AMD64")
        irsb = pyvex.IRSB(bytes.fromhex("0f32c3"), 0x1000, _vex_arch(arch), opt_level=1)
        dirty = next(stmt for stmt in irsb.statements if isinstance(stmt, pyvex.IRStmt.Dirty))
        assert dirty.mFx is None
        block = VEXIRSBConverter.convert(irsb, ailment.Manager())
        assert any(
            isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.DirtyExpression)
            for stmt in block.statements
        )


class TestGetITmpWidth(unittest.TestCase):
    """A tmp defined by ``GetI`` (x87 stack access) must carry the element width on the fast path."""

    # fadd word ptr [edi-0x5915e261] ; ...  -- WrTmp(GetI(F64x8)) and WrTmp(GetI(I8x8))
    block_bytes = bytes.fromhex("de879f9de1a6")
    block_addr = 0x4097B5

    def test_geti_tmps_keep_width(self):
        arch = archinfo.arch_from_id("X86")
        from_lift = VEXIRSBConverter.convert_from_lift(arch, self.block_addr, self.block_bytes, ailment.Manager())
        seen = 0
        for stmt in from_lift.statements:
            if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.dst, ailment.Expr.Tmp):
                assert stmt.dst.bits == stmt.src.bits, stmt
                seen += isinstance(stmt.src, ailment.Expr.IRegister)
        assert seen == 2


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
        irsb = pyvex.IRSB(self.block_bytes, 0x1000, _vex_arch(arch), opt_level=1)
        from_py = VEXIRSBConverter.convert(irsb, ailment.Manager())
        from_lift = VEXIRSBConverter.convert_from_lift(arch, 0x1000, self.block_bytes, ailment.Manager(), opt_level=1)
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
        irsb = pyvex.IRSB(bytes.fromhex("d8c1c3"), 0x1000, _vex_arch(arch), opt_level=1)  # fadd st0, st1 ; ret
        blk = VEXIRSBConverter.convert(irsb, ailment.Manager())
        binop = next(
            src
            for s in blk.statements
            if isinstance(src := getattr(s, "src", None), ailment.Expr.BinaryOp) and src.floating_point
        )
        assert isinstance(binop.rounding_mode, RoundingMode)


class TestVectorSignedness(unittest.TestCase):
    @staticmethod
    def _find_haddv(block):
        return next(
            stmt.src
            for stmt in block.statements
            if isinstance(getattr(stmt, "src", None), ailment.Expr.BinaryOp) and stmt.src.op == "HAddV"
        )

    def test_haddv_signedness(self):
        arch = archinfo.arch_from_id("armel")

        for name, block_bytes, expected_signed in (
            ("sadd8", bytes.fromhex("920f11e6"), True),
            ("uadd8", bytes.fromhex("920f51e6"), False),
        ):
            with self.subTest(instruction=name):
                irsb = pyvex.IRSB(block_bytes, 0x1000, _vex_arch(arch), opt_level=0)
                from_py = VEXIRSBConverter.convert(irsb, ailment.Manager())
                from_lift = VEXIRSBConverter.convert_from_lift(
                    arch, 0x1000, block_bytes, ailment.Manager(), opt_level=0
                )

                assert from_py == from_lift
                for block in (from_py, from_lift):
                    haddv = self._find_haddv(block)
                    assert haddv.signed is expected_signed
                    assert haddv.vector_count == 4
                    assert haddv.vector_size == 8


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
            assert isinstance(node.addr, int)
            thumb = bool(getattr(node, "thumb", False))
            lift_addr = (node.addr | 1) if thumb else node.addr
            bytes_offset = 1 if thumb else 0
            try:
                # Generous trailing bytes so thumb boundary decode is deterministic.
                data = bytes(p.loader.memory.load(node.addr, node.size + 32))
            except Exception:
                continue
            try:
                irsb = pyvex.IRSB(data, lift_addr, _vex_arch(arch), opt_level=1, bytes_offset=bytes_offset)
            except Exception:
                continue
            if irsb.size == 0:
                continue
            try:
                from_py = VEXIRSBConverter.convert(
                    pyvex.IRSB(data, lift_addr, _vex_arch(arch), opt_level=1, bytes_offset=bytes_offset),
                    ailment.Manager(),
                )
            except Exception:
                continue
            try:
                from_lift = VEXIRSBConverter.convert_from_lift(
                    arch, lift_addr, data, ailment.Manager(), opt_level=1, bytes_offset=bytes_offset
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
            pyvex.IRSB(self.window, self.addr, _vex_arch(arch), opt_level=1), ailment.Manager()
        )
        # 0x04 completes the truncated `lg`: an unguarded overread decodes it
        # and ends the block Ijk_Boring instead of Ijk_NoDecode.
        backing = bytearray(self.window + b"\x04" * 8)
        from_lift_mv = VEXIRSBConverter.convert_from_lift(
            arch, self.addr, memoryview(backing)[: len(self.window)], ailment.Manager(), opt_level=1
        )
        from_lift_bytes = VEXIRSBConverter.convert_from_lift(
            arch, self.addr, self.window, ailment.Manager(), opt_level=1
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


class TestVexEnumParity(unittest.TestCase):
    """The Rust converter hardcodes libVEX enum values (IRConstTag, IRType,
    IRLoadGOp, ...); libVEX inserts members mid-enum between releases
    (Valgrind 3.27.1 added Ico_U128), so pin them to the values pyvex's cffi
    layer reads from the real headers."""

    RUST_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "native", "angr", "src", "ailment")

    def test_hardcoded_vex_enum_values_match_libvex(self):
        ffi_path = os.path.join(self.RUST_SRC, "vex_ffi.rs")
        conv_path = os.path.join(self.RUST_SRC, "convert_vex.rs")
        if not (os.path.exists(ffi_path) and os.path.exists(conv_path)):
            self.skipTest("Rust sources not available")

        by_upper = {}
        for name, value in enums_to_ints.items():
            by_upper.setdefault(name.upper(), set()).add(value)

        checked = {}
        mismatches = []
        with open(ffi_path, encoding="utf-8") as f:
            for name, value in re.findall(r"pub const ([A-Z0-9_]+): u32 = (0x[0-9A-Fa-f]+|\d+);", f.read()):
                checked[name] = int(value, 0)
        # inline int -> name tables (e.g. IRLoadGOp) in the converter
        with open(conv_path, encoding="utf-8") as f:
            for value, name in re.findall(r'(0x1[0-9A-Fa-f]{3}) => "(I[A-Za-z0-9_]+)"', f.read()):
                checked[name.upper()] = int(value, 0)

        for name, value in sorted(checked.items()):
            vex_values = by_upper.get(name)
            if vex_values is None:
                continue  # not a VEX enum member (e.g. angr-side constants)
            if value not in vex_values:
                mismatches.append(f"{name}: rust={value:#x} libvex={sorted(hex(v) for v in vex_values)}")

        assert not mismatches, "hardcoded VEX enum values are stale:\n  " + "\n  ".join(mismatches)
        # guard against the test going vacuous if the constants are renamed/moved
        for must in ("ICO_U128", "ICO_V256", "ILGOP_16UTO32", "IJK_BORING", "ITY_V256"):
            assert must in checked and must in by_upper, must

    def test_lift_path_reads_wide_constants(self):
        """convert_from_lift reads IRConst tags straight from the C IRSB; the
        pyvex path resolves them by name and is the reference."""
        arch = archinfo.arch_from_id("AMD64")
        cases = [
            ("c5fdefc0", 256, 0),  # vpxor ymm0, ymm0, ymm0     -> Ico_V256 0x0
            ("c5fd76c0", 256, (1 << 256) - 1),  # vpcmpeqd ymm0, ymm0, ymm0  -> Ico_V256 0xffffffff
            ("660fefc0", 128, 0),  # pxor xmm0, xmm0            -> Ico_V128 0x0
            ("660f76c0", 128, (1 << 128) - 1),  # pcmpeqd xmm0, xmm0         -> Ico_V128 0xffff
        ]
        for hexbytes, bits, value in cases:
            data = bytes.fromhex(hexbytes)
            from_py = VEXIRSBConverter.convert(
                pyvex.IRSB(data, 0x400000, _vex_arch(arch), opt_level=1), ailment.Manager()
            )
            from_lift = VEXIRSBConverter.convert_from_lift(arch, 0x400000, data, ailment.Manager(), opt_level=1)
            assert from_py == from_lift, hexbytes
            # keep the wrappers alive while inspecting them: Rust-backed AIL
            # objects are fresh Python wrappers on every attribute access
            srcs = [stmt.src for stmt in from_lift.statements if isinstance(stmt, ailment.Stmt.Assignment)]
            consts = [(src.bits, src.value) for src in srcs if isinstance(src, ailment.Expr.Const)]
            assert (bits, value) in consts, (hexbytes, consts)


class TestVectorConversions(unittest.TestCase):
    """
    Lane-wise conversions (Iop_F32toI32Sx4 & co.) become Convert expressions with a vector_count; they used to become
    a BinaryOp named "V" (issue #7134).
    """

    @staticmethod
    def _converts(arch, block_bytes):
        irsb = pyvex.IRSB(block_bytes, 0x1000, _vex_arch(arch), opt_level=1)
        from_py = VEXIRSBConverter.convert(irsb, ailment.Manager())
        from_lift = VEXIRSBConverter.convert_from_lift(arch, 0x1000, block_bytes, ailment.Manager(), opt_level=1)
        assert [str(s) for s in from_lift.statements] == [str(s) for s in from_py.statements]
        assert all(
            src.op != "V"
            for stmt in from_py.statements
            if isinstance(src := getattr(stmt, "src", None), ailment.Expr.BinaryOp)
        )
        return [
            stmt.src
            for stmt in from_py.statements
            if isinstance(stmt, ailment.Stmt.Assignment)
            and isinstance(stmt.src, ailment.Expr.Convert)
            and stmt.src.vector_count is not None
        ]

    def test_sse_float_int_conversions(self):
        # cvttps2dq xmm0, xmm0 ; cvtdq2ps xmm0, xmm0 ; ret
        arch = archinfo.arch_from_id("AMD64")
        f2i, i2f = self._converts(arch, bytes.fromhex("f30f5bc00f5bc0c3"))

        # Iop_F32toI32Sx4 with a constant rounding mode (truncation)
        assert (f2i.from_bits, f2i.to_bits, f2i.vector_count) == (128, 128, 4)
        assert f2i.from_type == ailment.Expr.Convert.TYPE_FP and f2i.to_type == ailment.Expr.Convert.TYPE_INT
        assert f2i.is_signed
        assert f2i.rounding_mode == RoundingMode.RM_TowardsZero
        assert str(f2i).startswith("ConvV(32F->s32x4, ")

        # Iop_I32StoF32x4; cvtdq2ps takes its rounding mode from MXCSR, so it stays an expression
        assert (i2f.from_bits, i2f.to_bits, i2f.vector_count) == (128, 128, 4)
        assert i2f.from_type == ailment.Expr.Convert.TYPE_INT and i2f.to_type == ailment.Expr.Convert.TYPE_FP
        assert i2f.is_signed
        assert isinstance(i2f.rounding_mode, ailment.Expr.Expression)

        # the field survives a rebuild, equality, hashing, and pickling
        rebuilt = ailment.Expr.Convert(
            f2i.idx,
            f2i.from_bits,
            f2i.to_bits,
            f2i.is_signed,
            f2i.operand,
            from_type=f2i.from_type,
            to_type=f2i.to_type,
            rounding_mode=f2i.rounding_mode,
            vector_count=f2i.vector_count,
            **f2i.tags,
        )
        assert rebuilt == f2i and hash(rebuilt) == hash(f2i)
        scalar = ailment.Expr.Convert(
            f2i.idx, f2i.from_bits, f2i.to_bits, f2i.is_signed, f2i.operand, f2i.from_type, f2i.to_type, **f2i.tags
        )
        assert scalar != f2i
        assert pickle.loads(pickle.dumps(f2i)) == f2i

    def test_neon_conversions_with_suffix_rounding(self):
        # vcvt.s32.f32 q0, q0 ; vcvt.f32.s32 q0, q0 ; vcvt.s32.f32 d0, d0 ; bx lr
        arch = archinfo.arch_from_id("ARMEL")
        rz4, dep4, rz2 = self._converts(arch, bytes.fromhex("4007bbf3" + "4006bbf3" + "0007bbf3" + "1eff2fe1"))

        # Iop_F32toI32Sx4_RZ: the rounding mode is baked into the op name
        assert (rz4.from_bits, rz4.to_bits, rz4.vector_count) == (128, 128, 4)
        assert rz4.from_type == ailment.Expr.Convert.TYPE_FP and rz4.to_type == ailment.Expr.Convert.TYPE_INT
        assert rz4.is_signed and rz4.rounding_mode == RoundingMode.RM_TowardsZero

        # Iop_I32StoF32x4_DEP: no rounding mode at all
        assert (dep4.from_bits, dep4.to_bits, dep4.vector_count) == (128, 128, 4)
        assert dep4.from_type == ailment.Expr.Convert.TYPE_INT and dep4.to_type == ailment.Expr.Convert.TYPE_FP
        assert dep4.is_signed and dep4.rounding_mode is None

        # Iop_F32toI32Sx2_RZ on a D register
        assert (rz2.from_bits, rz2.to_bits, rz2.vector_count) == (64, 64, 2)

    def test_scalar_fp_to_int_signedness(self):
        # cvttsd2si eax, xmm0 ; ret -> Iop_F64toI32S: the S belongs to the target
        arch = archinfo.arch_from_id("AMD64")
        irsb = pyvex.IRSB(bytes.fromhex("f20f2cc0c3"), 0x1000, _vex_arch(arch), opt_level=1)
        blk = VEXIRSBConverter.convert(irsb, ailment.Manager())
        conv = next(
            stmt.src
            for stmt in blk.statements
            if isinstance(stmt, ailment.Stmt.Assignment)
            and isinstance(stmt.src, ailment.Expr.Convert)
            and stmt.src.from_type == ailment.Expr.Convert.TYPE_FP
        )
        assert conv.vector_count is None
        assert conv.is_signed
        assert (conv.from_bits, conv.to_bits) == (64, 32)


class TestX87MathOps(unittest.TestCase):
    """
    The x87 transcendental / remainder ops (and a few SSE ones) have no symbolic-engine model, so
    `vexop_to_simop` rejects them; the converter still maps them to AIL ops with their operands instead
    of an operand-less `unsupported_Iop_*` DirtyExpression.
    """

    @staticmethod
    def _assignments(arch_name: str, block_hex: str) -> list[ailment.Expr.Expression]:
        arch = archinfo.arch_from_id(arch_name)
        block_bytes = bytes.fromhex(block_hex)
        irsb = pyvex.IRSB(block_bytes, 0x1000, _vex_arch(arch), opt_level=1)
        from_py = VEXIRSBConverter.convert(irsb, ailment.Manager())
        from_lift = VEXIRSBConverter.convert_from_lift(arch, 0x1000, block_bytes, ailment.Manager(), opt_level=1)
        assert from_py == from_lift
        srcs = [stmt.src for stmt in from_py.statements if isinstance(stmt, ailment.Stmt.Assignment)]
        assert not any(isinstance(s, ailment.Expr.DirtyExpression) and "unsupported_" in s.callee for s in srcs)
        return srcs

    def _x87(self, insn_hex: str) -> list[ailment.Expr.Expression]:
        # <insn> ; ret
        return self._assignments("X86", insn_hex + "c3")

    @staticmethod
    def _only(srcs, kind, pred):
        matches = [s for s in srcs if isinstance(s, kind) and pred(s)]
        assert len(matches) == 1, matches
        return matches[0]

    def test_unary_x87_ops(self):
        # Iop_XxxF64(rm, x) -> UnaryOp(Xxx, x): fsqrt, fsin, fcos, fptan
        for insn, op in (("d9fa", "Sqrt"), ("d9fe", "Sin"), ("d9ff", "Cos"), ("d9f2", "Tan")):
            unop = self._only(self._x87(insn), ailment.Expr.UnaryOp, lambda e, op=op: e.op == op)
            assert unop.floating_point and unop.bits == 64
            assert isinstance(unop.operand, ailment.Expr.Expression)

    def test_fprem_and_status_bits(self):
        # fprem: ST0 = fmod(ST0, ST1); C3210 = x87_fprem_c3210(ST0, ST1)
        srcs = self._x87("d9f8")
        prem = self._only(srcs, ailment.Expr.BinaryOp, lambda e: e.op == "PRem")
        assert prem.floating_point and prem.bits == 64
        flags = self._only(srcs, ailment.Expr.DirtyExpression, lambda e: e.callee == "x87_fprem_c3210")
        assert flags.bits == 32
        assert [str(o) for o in flags.operands] == [str(o) for o in prem.operands]
        # fprem1 is the IEEE remainder
        srcs = self._x87("d9f5")
        self._only(srcs, ailment.Expr.BinaryOp, lambda e: e.op == "PRem1")
        self._only(srcs, ailment.Expr.DirtyExpression, lambda e: e.callee == "x87_fprem1_c3210")

    def test_fpatan(self):
        # fpatan: atan2(ST1, ST0)
        binop = self._only(self._x87("d9f3"), ailment.Expr.BinaryOp, lambda e: e.op == "Atan2")
        assert binop.floating_point and binop.bits == 64

    def test_fscale(self):
        # fscale: ST0 * 2^trunc(ST1) == Scale(ST0, Conv(64F->s32 RZ, ST1))
        binop = self._only(self._x87("d9fd"), ailment.Expr.BinaryOp, lambda e: e.op == "Scale")
        exp = binop.operands[1]
        assert isinstance(exp, ailment.Expr.Convert)
        assert exp.from_type == ailment.Expr.Convert.TYPE_FP and exp.to_type == ailment.Expr.Convert.TYPE_INT
        assert (exp.from_bits, exp.to_bits, exp.is_signed) == (64, 32, True)
        assert exp.rounding_mode == RoundingMode.RM_TowardsZero

    def test_f2xm1_and_fyl2x(self):
        # f2xm1: 2^x - 1
        sub = self._only(self._x87("d9f0"), ailment.Expr.BinaryOp, lambda e: e.op == "Sub")
        assert isinstance(sub.operands[0], ailment.Expr.UnaryOp) and sub.operands[0].op == "Exp2"
        assert isinstance(sub.operands[1], ailment.Expr.Const) and sub.operands[1].value == 1.0
        # fyl2x: y * log2(x); fyl2xp1: y * log2(x + 1)
        mul = self._only(self._x87("d9f1"), ailment.Expr.BinaryOp, lambda e: e.op == "Mul")
        assert mul.floating_point
        assert isinstance(mul.operands[1], ailment.Expr.UnaryOp) and mul.operands[1].op == "Log2"
        mul = self._only(self._x87("d9f9"), ailment.Expr.BinaryOp, lambda e: e.op == "Mul")
        log2 = mul.operands[1]
        assert isinstance(log2, ailment.Expr.UnaryOp) and log2.op == "Log2"
        assert isinstance(log2.operand, ailment.Expr.BinaryOp) and log2.operand.op == "Add"

    def test_sse_sqrt_and_unordered_compare(self):
        # sqrtpd xmm0, xmm0 ; ret -> Iop_Sqrt64Fx2(rm, x)
        unop = self._only(self._assignments("AMD64", "660f51c0c3"), ailment.Expr.UnaryOp, lambda e: e.op == "SqrtV")
        assert unop.floating_point and unop.bits == 128
        # cmpunordps xmm0, xmm1 ; ret -> Iop_CmpUN32Fx4(a, b)
        binop = self._only(self._assignments("AMD64", "0fc2c103c3"), ailment.Expr.BinaryOp, lambda e: e.op == "CmpUNV")
        assert binop.floating_point and (binop.bits, binop.vector_count, binop.vector_size) == (128, 4, 32)


class TestPackedFPOps(unittest.TestCase):
    """
    Packed SSE FP ops keep their lane layout and FP nature: mulpd is MulV (not a 128-bit integer Mul) and cmpeqsd is
    a floating-point CmpEQV.
    """

    def test_mulpd_cmpeqsd_psubq(self):
        # mulpd xmm0, xmm1 ; cmpeqsd xmm0, xmm1 ; psubq xmm0, xmm1 ; ret
        arch = archinfo.arch_from_id("AMD64")
        block_bytes = bytes.fromhex("660f59c1f20fc2c100660ffbc1c3")
        irsb = pyvex.IRSB(block_bytes, 0x1000, _vex_arch(arch), opt_level=1)
        from_py = VEXIRSBConverter.convert(irsb, ailment.Manager())
        from_lift = VEXIRSBConverter.convert_from_lift(arch, 0x1000, block_bytes, ailment.Manager(), opt_level=1)
        assert [str(s) for s in from_lift.statements] == [str(s) for s in from_py.statements]
        binops = [
            stmt.src
            for stmt in from_py.statements
            if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.BinaryOp)
        ]
        mul, cmp, sub = binops[:3]
        assert mul.op == "MulV" and mul.floating_point and (mul.vector_count, mul.vector_size) == (2, 64)
        assert mul.rounding_mode == RoundingMode.RM_NearestTiesEven
        assert cmp.op == "CmpEQV" and cmp.floating_point and (cmp.vector_count, cmp.vector_size) == (2, 64)
        assert sub.op == "SubV" and not sub.floating_point and (sub.vector_count, sub.vector_size) == (2, 64)


class TestFusedMultiplyAdd(unittest.TestCase):
    """
    `Iop_M{Add,Sub}F{32,64}(rm, a, b, c)` are Qops. The lift path used to reject them and the Python-IRSB path
    labelled them `unsupported_<class 'pyvex.expr.Qop'>`, so fmadd/vfmadd/madbr lost all three operands. They are
    `a * b +/- c` floating-point BinaryOps on both paths.
    """

    @staticmethod
    def _fma(arch_name: str, block_hex: str, op: str, bits: int) -> ailment.Expr.BinaryOp:
        srcs = TestX87MathOps._assignments(arch_name, block_hex)
        outer = TestX87MathOps._only(srcs, ailment.Expr.BinaryOp, lambda e: e.op == op and e.floating_point)
        assert outer.bits == bits
        mul = outer.operands[0]
        assert isinstance(mul, ailment.Expr.BinaryOp) and mul.op == "Mul" and mul.floating_point
        assert mul.bits == bits
        assert mul.rounding_mode == outer.rounding_mode
        assert len({str(e) for e in (*mul.operands, outer.operands[1])}) == 3
        return outer

    def test_amd64_vfmadd(self):
        # vfmadd213sd xmm0, xmm1, xmm2 ; ret -> MAddF64(0, xmm1, xmm0, xmm2)
        outer = self._fma("AMD64", "c4e2f1a9c2c3", "Add", 64)
        assert outer.rounding_mode == RoundingMode.RM_NearestTiesEven
        # vfmadd213ss
        self._fma("AMD64", "c4e271a9c2c3", "Add", 32)

    def test_ppc64_fmadd_fmsub(self):
        # fmadd f1, f1, f12, f0 ; blr: the rounding mode is a tmp derived from fpround
        outer = self._fma("PPC64", "fc21033a4e800020", "Add", 64)
        assert isinstance(outer.rounding_mode, ailment.Expr.Expression)
        # fmsub f1, f1, f12, f0 ; blr
        self._fma("PPC64", "fc21033c4e800020", "Sub", 64)

    def test_aarch64_fmadd_fmsub(self):
        # fmadd d0, d0, d1, d2 ; ret / fmsub d0, d0, d1, d2 ; ret / fmadd s0, s0, s1, s2 ; ret
        self._fma("AARCH64", "0008411fc0035fd6", "Add", 64)
        self._fma("AARCH64", "0088411fc0035fd6", "Sub", 64)
        self._fma("AARCH64", "0008011fc0035fd6", "Add", 32)

    def test_s390x_madbr_msdbr_maebr(self):
        # madbr / msdbr / maebr %f4, %f0, %f2 ; br %r14
        self._fma("S390X", "b31e400207fe", "Add", 64)
        self._fma("S390X", "b31f400207fe", "Sub", 64)
        self._fma("S390X", "b30e400207fe", "Add", 32)


class TestPPCSinglePrecisionOps(unittest.TestCase):
    """
    PPC single-precision arithmetic on double registers: `fadds`/`fsubs`/`fmuls`/`fdivs` (Iop_<Op>F64r32),
    `fmadds` (Iop_MAddF64r32) and `frsp` (Iop_RoundF64toF32) round an F64 result to single precision
    (`Conv(32F->64F, Conv(64F->32F, x))`); `stfs` (Iop_TruncF64asF32) narrows to an F32.
    """

    @staticmethod
    def _f32_rounded(srcs: list[ailment.Expr.Expression]) -> list[ailment.Expr.Expression]:
        inner = []
        for e in srcs:
            if not (isinstance(e, ailment.Expr.Convert) and (e.from_bits, e.to_bits) == (32, 64)):
                continue
            assert e.from_type == ailment.Expr.Convert.TYPE_FP and e.to_type == ailment.Expr.Convert.TYPE_FP
            narrow = e.operand
            assert isinstance(narrow, ailment.Expr.Convert) and (narrow.from_bits, narrow.to_bits) == (64, 32)
            assert narrow.from_type == ailment.Expr.Convert.TYPE_FP and narrow.to_type == ailment.Expr.Convert.TYPE_FP
            assert isinstance(narrow.rounding_mode, ailment.Expr.Expression)
            inner.append(narrow.operand)
        return inner

    def test_fmuls_stfs(self):
        # fmuls f1, f1, f2 ; stfs f1, -0x10(r1) ; blr
        srcs = TestX87MathOps._assignments("PPC64", "ec2100b2d021fff04e800020")
        (mul,) = self._f32_rounded(srcs)
        assert isinstance(mul, ailment.Expr.BinaryOp) and mul.op == "Mul" and mul.floating_point and mul.bits == 64
        trunc = TestX87MathOps._only(
            srcs, ailment.Expr.Convert, lambda e: (e.from_bits, e.to_bits) == (64, 32) and e.rounding_mode is None
        )
        assert trunc.from_type == ailment.Expr.Convert.TYPE_FP and trunc.to_type == ailment.Expr.Convert.TYPE_FP

    def test_fadds_fsubs_fdivs(self):
        # fadds f1, f1, f2 ; fsubs f1, f1, f2 ; fdivs f1, f1, f2 ; blr
        srcs = TestX87MathOps._assignments("PPC64", "ec21102aec211028ec2110244e800020")
        ops = self._f32_rounded(srcs)
        assert all(isinstance(e, ailment.Expr.BinaryOp) and e.floating_point and e.bits == 64 for e in ops)
        assert [e.op for e in ops] == ["Add", "Sub", "Div"]

    def test_fmadds_frsp(self):
        # fmadds f1, f1, f12, f0 ; blr
        (add,) = self._f32_rounded(TestX87MathOps._assignments("PPC64", "ec21033a4e800020"))
        assert isinstance(add, ailment.Expr.BinaryOp) and add.op == "Add" and add.floating_point
        assert isinstance(add.operands[0], ailment.Expr.BinaryOp) and add.operands[0].op == "Mul"
        # frsp f1, f1 ; blr
        (x,) = self._f32_rounded(TestX87MathOps._assignments("PPC64", "fc2008184e800020"))
        assert isinstance(x, ailment.Expr.Tmp) and x.bits == 64


class TestF128Ops(unittest.TestCase):
    def test_s390x_sqxbr(self):
        # sqxbr %f0, %f0 ; br %r14 -> Iop_SqrtF128(rm, F64HLtoF128(f0, f2))
        srcs = TestX87MathOps._assignments("S390X", "b316000007fe")
        sqrt = TestX87MathOps._only(srcs, ailment.Expr.UnaryOp, lambda e: e.op == "Sqrt")
        assert sqrt.floating_point and sqrt.bits == 128
        assert isinstance(sqrt.operand, ailment.Expr.Tmp) and sqrt.operand.bits == 128


class TestMiscFPOps(unittest.TestCase):
    def test_arm_vmaxnm_vminnm(self):
        # vmaxnm.f64 d0, d0, d1 ; vminnm.f64 d0, d0, d1 ; bx lr -> Iop_MaxNumF64 / Iop_MinNumF64 = fmax / fmin
        srcs = TestX87MathOps._assignments("ARMEL", "010b80fe410b80fe1eff2fe1")
        for op in ("MaxF", "MinF"):
            e = TestX87MathOps._only(srcs, ailment.Expr.BinaryOp, lambda e, op=op: e.op == op)
            assert e.floating_point and e.bits == 64

    def test_amd64_vsqrtpd_ymm(self):
        # vsqrtpd ymm0, ymm1 ; ret -> Iop_Sqrt64Fx4 (a unop)
        srcs = TestX87MathOps._assignments("AMD64", "c5fd51c1c3")
        e = TestX87MathOps._only(srcs, ailment.Expr.UnaryOp, lambda e: e.op == "SqrtV")
        assert e.floating_point and e.bits == 256


class TestUnsupportedOpsKeepOperands(unittest.TestCase):
    """An op with no AIL mapping becomes an `unsupported_<Iop>` DirtyExpression that keeps its operands."""

    @staticmethod
    def _dirty(arch_name: str, block_hex: str) -> ailment.Expr.DirtyExpression:
        arch = archinfo.arch_from_id(arch_name)
        block_bytes = bytes.fromhex(block_hex)
        irsb = pyvex.IRSB(block_bytes, 0x1000, _vex_arch(arch), opt_level=1)
        from_py = VEXIRSBConverter.convert(irsb, ailment.Manager())
        from_lift = VEXIRSBConverter.convert_from_lift(arch, 0x1000, block_bytes, ailment.Manager(), opt_level=1)
        assert from_py == from_lift
        dirties = [
            stmt.src
            for stmt in from_py.statements
            if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.DirtyExpression)
        ]
        assert len(dirties) == 1, dirties
        return dirties[0]

    def test_s390x_adtr_decimal(self):
        # adtr %f4, %f0, %f2 ; br %r14 -> Iop_AddD64(rm, a, b): decimal FP has no AIL mapping
        d = self._dirty("S390X", "b3d2400207fe")
        assert d.callee == "unsupported_Iop_AddD64" and d.bits == 64
        assert [o.bits for o in d.operands] == [32, 64, 64]

    def test_amd64_vcmppd_mask(self):
        # vcmppd k1, zmm0, zmm1, 0 ; ret -> Iop_Cmp64Fx8(a, b, imm, mask): a deliberately unsupported AVX-512 Qop
        d = self._dirty("AMD64", "62f1fd48c2c900c3")
        assert d.callee == "unsupported_Iop_Cmp64Fx8"
        assert len(d.operands) == 4 and isinstance(d.operands[3], ailment.Expr.Const)
