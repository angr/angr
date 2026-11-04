#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import itertools
import random
import unittest

import networkx

from angr import claripy
from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Load,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, Return, SideEffectStatement, Store
from angr.analyses.decompiler.vm_canonical_forms import CanonicalFormResolver

_ids = itertools.count(1000)
GLOBAL = 0x585210


def _c(value: int, bits: int = 32) -> Const:
    return Const(next(_ids), value & ((1 << bits) - 1), bits)


def _tmp(varid: int, bits: int = 32) -> VirtualVariable:
    return VirtualVariable(next(_ids), varid, bits, VirtualVariableCategory.TMP, oident=varid)


def _reg(varid: int, bits: int = 32) -> VirtualVariable:
    return VirtualVariable(next(_ids), varid, bits, VirtualVariableCategory.REGISTER, oident=16)


def _slot(varid: int, offset: int, bits: int = 32) -> VirtualVariable:
    return VirtualVariable(next(_ids), varid, bits, VirtualVariableCategory.STACK, oident=offset)


def _ref(varid: int, offset: int) -> UnaryOp:
    return UnaryOp(next(_ids), "Reference", _slot(varid, offset), bits=32)


def _op(op: str, a, b) -> BinaryOp:
    return BinaryOp(next(_ids), op, [a, b], False, bits=a.bits)


def _load(addr, bits: int = 32) -> Load:
    return Load(next(_ids), _c(addr) if isinstance(addr, int) else addr, bits // 8, "Iend_LE")


def _def(dst: VirtualVariable, src) -> Assignment:
    return Assignment(next(_ids), dst, src, ins_addr=1)


def _resolve(*blocks, edges=()):
    graph = networkx.DiGraph()
    graph.add_nodes_from(blocks)
    graph.add_edges_from(edges)
    new_ids = itertools.count(5000)
    resolver = CanonicalFormResolver(graph, 32, Manager(), lambda: next(new_ids))
    repl = resolver.run()
    return resolver.resolved, repl, resolver


def _flag_term(x):
    # Themida's flag-derived offset: a few bits of x after masking
    return _op("Or", _op("And", _op("Sub", _op("And", x, _c(144)), _c(5788063)), _c(171)), _c(7))


class _Z3:
    """AIL to claripy over SSA definitions; a stack reference is the stack base plus its offset."""

    def __init__(self, blocks):
        self.defs = {}
        for block in blocks:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and not stmt.dst.was_stack:
                    self.defs[stmt.dst.varid] = stmt.src
        self.sb = claripy.BVS("sb", 32, explicit_name=True)

    def __call__(self, e):
        if isinstance(e, Const):
            return claripy.BVV(e.value_int, e.bits)
        if isinstance(e, UnaryOp) and e.op == "Reference":
            return self.sb + e.operand.stack_offset
        if isinstance(e, VirtualVariable):
            if e.varid in self.defs and not isinstance(self.defs[e.varid], Load):
                return self(self.defs[e.varid])
            return claripy.BVS(f"v{e.varid}", e.bits, explicit_name=True)
        if isinstance(e, Load):
            return claripy.BVS(f"load{e.idx}", e.bits, explicit_name=True)
        a, b = self(e.operands[0]), self(e.operands[1])
        return {"Add": a + b, "Sub": a - b, "Xor": a ^ b, "And": a & b, "Or": a | b, "Mul": a * b}[e.op]

    def equivalent(self, a, b) -> bool:
        return not claripy.Solver().satisfiable(extra_constraints=[self(a) != self(b)])


class TestCanonicalFormResolver(unittest.TestCase):
    def _keyed_load(self, k_defs, k, k_prime, t):
        """Load(&frame ^ (k - 87) ^ ((k' + t) - 87))"""
        addr = _op("Xor", _op("Xor", _ref(50, -904), _op("Sub", k, _c(87))), _op("Sub", _op("Add", k_prime, t), _c(87)))
        return Block(0x1000, 1, statements=[*k_defs, _def(_tmp(9), _load(addr)), Return(next(_ids), [_tmp(9)])])

    def test_equal_keys_through_different_chains(self):
        x = _reg(1)
        # k = (x + 0x1000) + t1 through v2, v3; k' = (x + 0x800) + 0x800 through v4, v5; t1 and t spelled anew
        defs = [
            _def(_tmp(2), _op("Add", x, _c(0x1000))),
            _def(_tmp(3), _op("Add", _tmp(2), _flag_term(x))),
            _def(_tmp(4), _op("Add", x, _c(0x800))),
            _def(_tmp(5), _op("Add", _tmp(4), _c(0x800))),
        ]
        block = self._keyed_load(defs, _tmp(3), _tmp(5), _flag_term(x))
        count, repl, resolver = _resolve(block)
        assert resolver.resolved == 1
        new_addr = repl[block].statements[4].src.addr
        assert isinstance(new_addr, UnaryOp) and new_addr.op == "Reference" and new_addr.operand.stack_offset == -904
        assert _Z3([block]).equivalent(block.statements[4].src.addr, new_addr)

    def test_different_keys_stay(self):
        x = _reg(1)
        defs = [_def(_tmp(3), _op("Add", x, _flag_term(x)))]
        # the masked terms differ in one bit of the flag mask
        other = _op("Or", _op("And", _op("Sub", _op("And", x, _c(128)), _c(5788063)), _c(171)), _c(7))
        block = self._keyed_load(defs, _tmp(3), x, other)
        _, repl, resolver = _resolve(block)
        assert resolver.resolved == 0 and not repl

    def test_loads_read_the_same_memory_only_without_writes_between(self):
        # k = Load(G) + 1 and k' = Load(G) + 1 in two statements of one block
        def run(between):
            defs = [
                _def(_tmp(3), _op("Add", _load(GLOBAL), _c(1))),
                *between,
                _def(_tmp(4), _op("Add", _load(GLOBAL), _c(1))),
            ]
            return _resolve(self._keyed_load(defs, _tmp(3), _tmp(4), _c(0)))[2].resolved

        store = lambda addr: Store(next(_ids), addr, _reg(8), 4, "Iend_LE", ins_addr=1)  # noqa:E731
        call = SideEffectStatement(next(_ids), Call(next(_ids), "rand", args=[], bits=32), ins_addr=1)
        assert run([]) == 1
        # a stack store cannot write G, and neither can a store to other bytes
        assert run([store(_op("Add", _ref(60, -32), _c(4))), store(_c(GLOBAL + 4))]) == 1
        # a store to G's bytes, through an unknown pointer, or a call may
        assert run([store(_c(GLOBAL + 2))]) == 0
        assert run([store(_reg(9))]) == 0
        assert run([call]) == 0
        # different blocks are not compared
        head = Block(0x900, 1, statements=[_def(_tmp(3), _op("Add", _load(GLOBAL), _c(1)))])
        tail = self._keyed_load([_def(_tmp(4), _op("Add", _load(GLOBAL), _c(1)))], _tmp(3), _tmp(4), _c(0))
        assert _resolve(head, tail, edges=[(head, tail)])[2].resolved == 0

    def test_earlier_load_of_the_same_bytes_holds_the_value(self):
        # v1 = Load(G); v2 = (Load(G) ^ k) ^ k  ==>  v2 = v1, but not with a store to G between or v1 after
        k = _op("Sub", _op("Xor", _reg(1), _c(0x5D)), _c(0x41))
        keyed = lambda: _op("Xor", _op("Xor", _load(GLOBAL), k), _op("Sub", _op("Xor", _reg(1), _c(0x5D)), _c(0x41)))  # noqa
        holder = _def(_tmp(1), _load(GLOBAL))
        use = _def(_tmp(2), keyed())
        block = Block(0x1000, 1, statements=[holder, use, Return(next(_ids), [_tmp(2)])])
        _, repl, resolver = _resolve(block)
        assert resolver.resolved == 1 and repl[block].statements[1].src.likes(_tmp(1))
        block = Block(0x1000, 1, statements=[_def(_tmp(2), keyed()), _def(_tmp(1), _load(GLOBAL)), Return(next(_ids), [])])
        _, repl, _ = _resolve(block)
        assert not repl or not isinstance(repl[block].statements[0].src, VirtualVariable)
        store = Store(next(_ids), _c(GLOBAL), _reg(8), 4, "Iend_LE", ins_addr=1)
        block = Block(0x1000, 1, statements=[holder, store, _def(_tmp(2), keyed()), Return(next(_ids), [])])
        _, repl, _ = _resolve(block)
        assert not repl or not repl[block].statements[2].src.likes(_tmp(1))

    def test_stack_slot_and_call_definitions_are_atoms(self):
        x = _reg(1)
        # a stack slot's single definition is not trusted
        defs = [_def(_slot(3, -16), x)]
        block = self._keyed_load(defs, _slot(3, -16), x, _c(0))
        _, repl, resolver = _resolve(block)
        assert resolver.resolved == 0 and not repl
        # two calls are two values
        call = lambda: Call(next(_ids), "rand", args=[], bits=32)  # noqa:E731
        defs = [_def(_tmp(3), _op("Add", call(), _c(1))), _def(_tmp(4), _op("Add", call(), _c(1)))]
        block = self._keyed_load(defs, _tmp(3), _tmp(4), _c(0))
        _, repl, resolver = _resolve(block)
        assert resolver.resolved == 0 and not repl

    def test_stack_address_is_spelled_from_the_base_it_is_computed_from(self):
        # v2 = &frame + 0x100; Load(((v2 ^ k) ^ k) + 8)  ==>  Load(&frame + 0x108)
        k = lambda: _op("Sub", _op("Xor", _reg(1), _c(0x5D)), _c(0x41))  # noqa:E731
        frame = _ref(50, -904)
        addr = _op("Add", _op("Xor", _op("Xor", _tmp(2), k()), k()), _c(8))
        block = Block(
            0x1000,
            1,
            statements=[_def(_tmp(2), _op("Add", frame, _c(0x100))), _def(_tmp(9), _load(addr)), Return(next(_ids), [])],
        )
        _, repl, _ = _resolve(block)
        assert repl[block].statements[1].src.addr.likes(_op("Add", frame, _c(0x108)))
        # without a stack address to spell it from (-(-&frame)), nothing new is made up
        addr = _op("Xor", _op("Xor", UnaryOp(next(_ids), "Neg", _tmp(3), bits=32), k()), k())
        block = Block(
            0x1000,
            1,
            statements=[
                _def(_tmp(3), UnaryOp(next(_ids), "Neg", frame, bits=32)),
                _def(_tmp(9), _load(addr)),
                Return(next(_ids), []),
            ],
        )
        _, repl, _ = _resolve(block)
        assert not repl or not repl[block].statements[1].src.addr.likes(frame)

    def test_calls_are_never_rewritten_away(self):
        # v2 = (f() & 0) + x is x in value, but f still has to run
        call = Call(next(_ids), "f", args=[], bits=32)
        block = Block(
            0x1000,
            1,
            statements=[_def(_tmp(2), _op("Add", _op("And", call, _c(0)), _reg(1))), Return(next(_ids), [_tmp(2)])],
        )
        _, repl, _ = _resolve(block)
        assert not repl or "Call(" in str(repl[block].statements[0])

    def test_lane_wise_sums_are_not_scalar_sums(self):
        x, y = _reg(1), _reg(2)
        lanes = BinaryOp(next(_ids), "Add", [x, y], False, bits=32, vector_count=4, vector_size=8)
        block = self._keyed_load([], lanes, _op("Add", x, y), _c(0))
        _, repl, resolver = _resolve(block)
        assert resolver.resolved == 0 and not repl

    def test_pointer_variable_plus_offset(self):
        # ((p ^ k) ^ k) - 4 reads as p - 4, for a temporary p
        x = _reg(1)
        p = _tmp(7)
        k = _op("Sub", _op("Xor", x, _c(0x5D)), _c(0x41))
        addr = _op("Sub", _op("Xor", _op("Xor", p, k), _op("Sub", _op("Xor", x, _c(0x5D)), _c(0x41))), _c(4))
        block = Block(
            0x1000,
            1,
            statements=[_def(p, _load(_ref(50, -896))), _def(_tmp(9), _load(addr)), Return(next(_ids), [_tmp(9)])],
        )
        _, repl, resolver = _resolve(block)
        assert resolver.resolved == 1
        new_addr = repl[block].statements[1].src.addr
        assert new_addr.likes(_op("Sub", p, _c(4)))

    def test_load_inside_a_definition_gets_a_name(self):
        # v80 = Load(&s + 8) + k; *((v80 - k) + 416) = 0  ==>  t = Load(&s + 8); v80 = t + k; *(t + 416) = 0
        x = _reg(1)
        k = _tmp(76)
        slot_load = _load(_op("Add", _ref(50, -72), _c(80)))
        block = Block(
            0x1000,
            1,
            statements=[
                _def(k, _op("Xor", _op("Add", x, _c(0x1234)), _c(0x55))),
                _def(_tmp(80), _op("Add", slot_load, k)),
                Store(next(_ids), _op("Add", _op("Sub", _tmp(80), k), _c(416)), _c(0), 4, "Iend_LE", ins_addr=1),
                Return(next(_ids), []),
            ],
        )
        _, repl, resolver = _resolve(block)
        assert resolver.resolved == 1 and resolver.named == 1
        stmts = repl[block].statements
        assert len(stmts) == 5
        name = stmts[1]
        assert isinstance(name, Assignment) and name.dst.was_tmp and name.src.likes(slot_load)
        assert stmts[2].src.likes(_op("Add", name.dst, k))
        assert stmts[3].addr.likes(_op("Add", name.dst, _c(416)))

    def test_random_spellings(self):
        # an expression bound through temporaries against the same expression inline: always equal; a perturbed copy
        # may or may not be, and is rewritten only if the solver agrees
        rng = random.Random(7)
        inputs = [_reg(1), _reg(2)]
        ops = ["Add", "Sub", "Xor", "And", "Or"]

        def gen(depth, defs, bind):
            if depth == 0 or rng.random() < 0.2:
                return rng.choice(inputs) if rng.random() < 0.7 else _c(rng.getrandbits(32))
            op = rng.choice(ops)
            e = _op(op, gen(depth - 1, defs, bind), gen(depth - 1, defs, bind))
            if bind and rng.random() < 0.5:
                v = _tmp(100 + len(defs))
                defs.append(_def(v, e))
                return v
            return e

        def copy(e, perturb):
            if isinstance(e, VirtualVariable) and e.varid >= 100:
                return copy(srcs[e.varid], perturb)
            if isinstance(e, Const):
                return _c(e.value ^ 1) if perturb and rng.random() < 0.3 else _c(e.value)
            if isinstance(e, BinaryOp):
                return _op(e.op, copy(e.operands[0], perturb), copy(e.operands[1], perturb))
            return e

        rewritten = 0
        for _ in range(40):
            defs = []
            e = gen(4, defs, True)
            srcs = {d.dst.varid: d.src for d in defs}
            for perturb in (False, True):
                block = self._keyed_load(list(defs), e, copy(e, perturb), _c(0))
                _, repl, resolver = _resolve(block)
                new_addr = repl[block].statements[len(defs)].src.addr if repl else None
                if not perturb:
                    assert isinstance(new_addr, UnaryOp) and new_addr.op == "Reference"
                if not repl:
                    continue
                z = _Z3([block])
                for old, new in zip(block.statements, repl[block].statements):
                    if old.likes(new):
                        continue
                    rewritten += 1
                    if isinstance(old.src, Load):
                        assert z.equivalent(old.src.addr, new.src.addr)
                    else:
                        assert z.equivalent(old.src, new.src)
        assert rewritten >= 40


if __name__ == "__main__":
    unittest.main()
