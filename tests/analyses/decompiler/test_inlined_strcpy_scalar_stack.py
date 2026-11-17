#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
"""
Regression tests for angr issue #7294.

"Synthetic strncpy causes scalar loads to inherit array types"

A 4-byte scalar stack store of a "printable-looking" integer (e.g. ``0x2c2d2e2f``,
which decodes to ``"/.-,"``) followed by a scalar load of the same stack slot was
historically turned into a synthetic ``strncpy`` and reconstructed as a
``char v0[4]`` return value, losing the original scalar semantics.

The fixtures and helper blocks below must remain free of RXRE-specific
references; they only exercise angr itself.
"""
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Load,
    Register,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import (
    Assignment,
    Return,
    SideEffectStatement,
    Store,
)
from angr.analyses.decompiler.optimization_passes.inlined_strcpy_simplifier import (
    InlinedStrcpySimplifier,
)

from tests.analyses.decompiler.test_inlined_string_simplifiers import (
    _StackWriteBlockBuilder,
    _strcpy_copies,
)

X86_7294 = bytes.fromhex(
    "83ec04"          # sub esp, 4
    "c704242f2e2d2c"  # mov dword ptr [esp], 0x2c2d2e2f
    "8b0424"          # mov eax, [esp]
    "83c404c3"        # add esp, 4; ret
)

# conditional branch on the value loaded from the stack slot (two blocks)
X86_7294_BRANCH = bytes.fromhex(
    "83ec04"      # sub esp, 4
    "c704242f2e2d2c"  # mov dword ptr [esp], 0x2c2d2e2f
    "8b0424"      # mov eax, [esp]
    "3d2f2e2d2c"  # cmp eax, 0x2c2d2e2f
    "7402"        # je +2
    "33c0"        # xor eax, eax
    "83c404"      # add esp, 4
    "c3"          # ret
)

X86_ABCD = bytes.fromhex(
    "83ec04"      # sub esp, 4
    "c7042441424344"  # mov dword ptr [esp], 0x44434241 ("ABCD")
    "33c0"        # xor eax, eax
    "83c404c3"    # add esp, 4; ret
)


def _decompile(shellcode: bytes, arch: str):
    project = angr.load_shellcode(shellcode, arch=arch, load_address=0x400000)
    project.analyses.CFGFast(normalize=True)
    project.analyses.CompleteCallingConventions(workers=0)
    result = project.analyses.Decompiler(project.kb.functions[0x400000], preset="malware")
    text = result.codegen.text if result.codegen else ""
    return text


class TestScalarStackRegression(unittest.TestCase):
    """#7294 must not turn scalar stack stores of printable-byte integers into arrays."""

    def test_x86_scalar_fixture(self):
        text = _decompile(X86_7294, "x86")
        self.assertNotIn("char v0[", text)
        self.assertNotIn("strncpy", text)
        self.assertIn("741158447", text)

    def test_stack_scalar_vvar_in_value_position(self):
        # post-SSA shape of the candidate:
        #   vvar_stack(-4) = 741158447 ; Return(vvar_stack(-4))
        # A vvar with was_stack in value position IS a scalar use and must not
        # be stringified.
        builder = _StackWriteBlockBuilder()
        dst = builder.vvar(-4, 32)
        atom = builder.manager.next_atom()
        builder.statements.append(Assignment(atom, dst, Const(builder.manager.next_atom(), 741158447, 32)))
        builder.statements.append(Return(builder.manager.next_atom(), [dst]))
        _, statements = builder.run(InlinedStrcpySimplifier)
        self.assertFalse(
            any(
                isinstance(stmt, SideEffectStatement)
                and getattr(stmt.expr, "target", None) in ("strcpy", "strncpy")
                for stmt in statements
            ),
        )

    def test_cross_block_branch_preserves_scalar(self):
        text = _decompile(X86_7294_BRANCH, "x86")
        self.assertNotIn("char v0[", text)
        self.assertIn("741158447", text)

    def test_opaque_store_is_not_a_read_and_folds_legitimately(self):
        # for compatibility with test_inlined_string_simplifiers: barrier Store
        # with register-addressed opaque byte store must not block the fold
        pointer = VirtualVariable(0, 100, 64, VirtualVariableCategory.REGISTER, oident=0)
        builder = _StackWriteBlockBuilder()
        builder.store_bytes(-108, b"hello, ")
        builder.statements.append(
            Store(builder.manager.next_atom(), pointer,
                  Const(builder.manager.next_atom(), 0x41, 8), 1, "Iend_LE")
        )
        builder.store_bytes(-101, b"world!!")
        simplifier, statements = builder.run(InlinedStrcpySimplifier)
        copies = _strcpy_copies(builder, simplifier, statements)
        self.assertEqual(copies, [(-108, b"hello, ", 7), (-101, b"world!!", 7)])
        barrier_idx = next(
            i for i, stmt in enumerate(statements)
            if not isinstance(stmt, SideEffectStatement)
        )
        barrier = statements[barrier_idx]
        self.assertIsInstance(barrier, Store)
        self.assertEqual(barrier.addr.varid, pointer.varid)

    def test_unresolvable_load_address_aborts_fold_chain(self):
        # an unresolvable Load address after the store aborts transformation:
        # no strncpy is synthesised in that case
        builder = _StackWriteBlockBuilder()
        dst = builder.vvar(-4, 32)
        builder.statements.append(Assignment(builder.manager.next_atom(), dst,
                                             Const(builder.manager.next_atom(), 741158447, 32)))
        addr = BinaryOp(builder.manager.next_atom(), "Add",
                        [StackBaseOffset(builder.manager.next_atom(), 64, -4),
                         Register(builder.manager.next_atom(), 7, 64)],
                        signed=False, bits=64)
        builder.statements.append(Return(builder.manager.next_atom(),
                                         [Load(builder.manager.next_atom(), addr, 4, "Iend_LE")]))
        _, statements = builder.run(InlinedStrcpySimplifier)
        self.assertFalse(
            any(isinstance(stmt, SideEffectStatement)
                and getattr(stmt.expr, "target", None) in ("strcpy", "strncpy")
                for stmt in statements)
        )

    def test_const_printable_store_with_no_readers_still_folds(self):
        text = _decompile(X86_ABCD, "x86")
        self.assertIn("strncpy", text)
        self.assertIn("ABCD", text)


if __name__ == "__main__":
    unittest.main()
