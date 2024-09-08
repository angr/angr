from __future__ import annotations
import logging
import unittest
import operator
from dataclasses import dataclass

import claripy

import angr
from angr.engines.pcode.behavior import BehaviorFactory
from angr.engines.pcode.emulate import PcodeEmulatorMixin
from angr.sim_state import SimState
from angr.engines import SimSuccessors


try:
    import pypcode
    from pypcode import OpCode
except ImportError:
    pypcode = None


log = logging.getLogger(__name__)


@dataclass(eq=True)
class MockAddrSpace:
    """
    Mock AddrSpace
    """

    name: str


CONST_SPACE = MockAddrSpace("const")
RAM_SPACE = MockAddrSpace("ram")
REGISTER_SPACE = MockAddrSpace("register")
UNIQUE_SPACE = MockAddrSpace("unique")


@dataclass(eq=True)
class MockVarnode:
    """
    Mock Varnode
    """

    space: MockAddrSpace
    offset: int
    size: int

    register_name: str = "<mock>"
    space_encoded_in_offset: MockAddrSpace | None = None

    def getRegisterName(self) -> str:
        return self.register_name

    def getSpaceFromConst(self) -> MockAddrSpace | None:
        return self.space_encoded_in_offset


@dataclass(eq=True)
class MockPcodeOp:
    """
    Mock P-Code Op
    """

    opcode: OpCode
    output: MockVarnode | None
    inputs: list[MockVarnode]


BEHAVIORS = BehaviorFactory()


@dataclass
class MockIRSB:
    """
    Mock IRSB
    """

    _ops: list[MockPcodeOp]
    addr: int = 0
    behaviors: BehaviorFactory = BEHAVIORS


OP = MockPcodeOp
VN = MockVarnode


@unittest.skipUnless(pypcode, "pypcode is not available")
class TestPcodeEmulatorMixin(unittest.TestCase):
    """
    Test P-Code engine emulator mixin
    """

    @staticmethod
    def _step_irsb(irsb, state=None):
        emulator = PcodeEmulatorMixin()
        # FIMXE: *sigh* it's not so easy to use the mixin in isolation

        emulator.project = angr.load_shellcode(b"\x90", arch="AMD64")
        if state is None:
            state = SimState(arch="AMD64")
        emulator.state = state
        emulator.state.history.recent_bbl_addrs.append(0)
        emulator.successors = SimSuccessors(0, emulator.state)
        emulator.handle_pcode_block(irsb)
        emulator.successors.processed = True
        return emulator.successors

    def _test_branch_and_call_common(self, opcode: OpCode):
        target_addr = 0x12345678
        successors = self._step_irsb(
            MockIRSB(
                [
                    OP(
                        OpCode.IMARK,
                        None,
                        [VN(RAM_SPACE, 0, 1)],
                    ),
                    OP(
                        opcode,
                        None,
                        [VN(RAM_SPACE, target_addr, 1)],
                    ),
                ]
            )
        )

        assert len(successors.all_successors) == 1
        state = successors.all_successors[0]
        assert state.solver.eval(state.regs.pc == target_addr)

    def test_branch(self):
        self._test_branch_and_call_common(OpCode.BRANCH)

    def test_call(self):
        self._test_branch_and_call_common(OpCode.CALL)

    def _test_branchind_and_callind_common(self, opcode: OpCode):
        target_addr = 0x12345678
        target_pointer_addr = 0x100000
        target_pointer_size = 8

        state = SimState(arch="AMD64")
        state.memory.store(target_pointer_addr, claripy.BVV(target_addr, 8 * target_pointer_size), endness="IEnd_LE")

        successors = self._step_irsb(
            MockIRSB(
                [
                    OP(
                        OpCode.IMARK,
                        None,
                        [VN(RAM_SPACE, 0, 1)],
                    ),
                    OP(
                        opcode,
                        None,
                        [VN(RAM_SPACE, target_pointer_addr, target_pointer_size)],
                    ),
                ]
            ),
            state,
        )

        assert len(successors.all_successors) == 1
        state = successors.all_successors[0]
        assert state.solver.eval(state.regs.pc == target_addr)

    def test_branchind(self):
        self._test_branchind_and_callind_common(OpCode.BRANCHIND)

    def test_callind(self):
        self._test_branchind_and_callind_common(OpCode.CALLIND)

    def _test_cbranch_common(self, cond: claripy.BVV):
        condition_addr = 0x100000
        target_addr = 0x12345678
        fallthru_addr = 1

        state = SimState(arch="AMD64")
        state.memory.store(condition_addr, cond)

        successors = self._step_irsb(
            MockIRSB(
                [
                    OP(
                        OpCode.IMARK,
                        None,
                        [VN(RAM_SPACE, 0, fallthru_addr)],
                    ),
                    OP(
                        OpCode.CBRANCH,
                        None,
                        [VN(RAM_SPACE, target_addr, 8), VN(RAM_SPACE, condition_addr, 1)],
                    ),
                ]
            ),
            state,
        )

        if cond.concrete:
            if state.solver.eval(cond):
                sat_pc, unsat_pc = target_addr, fallthru_addr
            else:
                sat_pc, unsat_pc = fallthru_addr, target_addr

            assert len(successors.successors) == 1
            state = successors.successors[0]
            assert state.solver.eval(state.regs.pc == sat_pc)

            assert len(successors.unsat_successors) == 1
            state = successors.unsat_successors[0]
            assert state.solver.eval(state.regs.pc == unsat_pc)
        else:
            assert len(successors.successors) == 2
            pcs = {state.solver.eval(state.regs.pc) for state in successors.successors}
            assert pcs == {target_addr, fallthru_addr}

    def test_cbranch_taken(self):
        self._test_cbranch_common(claripy.BVV(1, 8))
        self._test_cbranch_common(claripy.BVV(2, 8))

    def test_cbranch_not_taken(self):
        self._test_cbranch_common(claripy.BVV(0, 8))

    def test_cbranch_symbolic(self):
        self._test_cbranch_common(claripy.BVS("condition", 8))

    def _test_rel_cbranch_common(self, cond: claripy.BVV):
        condition_addr = 0x100000
        start_addr = 0
        target_addr = start_addr
        target_stmt = 1
        instruction_len = 1
        fallthru_addr = start_addr + instruction_len
        cbranch_idx = 2

        state = SimState(arch="AMD64")
        state.memory.store(condition_addr, cond)

        successors = self._step_irsb(
            MockIRSB(
                [
                    # Op 0
                    OP(
                        OpCode.IMARK,
                        None,
                        [VN(RAM_SPACE, start_addr, instruction_len)],
                    ),
                    # Op 1
                    OP(
                        OpCode.INT_ADD,
                        VN(UNIQUE_SPACE, 0, 8),
                        [VN(UNIQUE_SPACE, 0, 8), VN(CONST_SPACE, 1, 8)],
                    ),
                    # Op 2
                    OP(
                        OpCode.CBRANCH,
                        None,
                        [VN(CONST_SPACE, target_stmt - cbranch_idx, 8), VN(RAM_SPACE, condition_addr, 1)],
                    ),
                ]
            ),
            state,
        )

        if cond.concrete:
            if state.solver.eval(cond):
                sat_pc, unsat_pc = target_addr, fallthru_addr
                sat_stmt, unsat_stmt = target_stmt, 0
            else:
                sat_pc, unsat_pc = fallthru_addr, target_addr
                sat_stmt, unsat_stmt = 0, target_stmt

            assert len(successors.successors) == 1
            state = successors.successors[0]
            assert state.solver.eval(state.regs.pc == sat_pc)
            assert state.scratch.statement_offset == sat_stmt

            assert len(successors.unsat_successors) == 1
            state = successors.unsat_successors[0]
            assert state.solver.eval(state.regs.pc == unsat_pc)
            assert state.scratch.statement_offset == unsat_stmt

        else:
            assert len(successors.successors) == 2
            pcs = {
                (state.solver.eval(state.regs.pc), state.scratch.statement_offset) for state in successors.successors
            }
            assert pcs == {(target_addr, target_stmt), (fallthru_addr, 0)}

    def test_rel_cbranch_taken(self):
        self._test_rel_cbranch_common(claripy.BVV(1, 8))
        self._test_rel_cbranch_common(claripy.BVV(2, 8))

    def test_rel_cbranch_not_taken(self):
        self._test_rel_cbranch_common(claripy.BVV(0, 8))

    def test_rel_cbranch_symbolic(self):
        self._test_cbranch_common(claripy.BVS("condition", 8))

    def test_load_store(self):
        addr = 0x133700000
        addr2 = 0x999900000
        value = claripy.BVV(0xFEDCBA9876543210, 64)
        state = SimState(arch="AMD64")
        state.memory.store(addr, value)
        state.regs.rax = addr

        # Load value from RAM[addr] and store it into RAM[addr2]

        successors = self._step_irsb(
            MockIRSB(
                [
                    OP(
                        OpCode.IMARK,
                        None,
                        [VN(RAM_SPACE, 0, 1)],
                    ),
                    OP(
                        OpCode.COPY,
                        VN(UNIQUE_SPACE, 0, 8),
                        [VN(CONST_SPACE, addr, 8)],
                    ),
                    OP(
                        OpCode.LOAD,
                        VN(UNIQUE_SPACE, 8, 8),
                        [VN(CONST_SPACE, 0xCACACACA, 0, space_encoded_in_offset=RAM_SPACE), VN(UNIQUE_SPACE, 0, 8)],
                    ),
                    OP(
                        OpCode.COPY,
                        VN(UNIQUE_SPACE, 0, 8),
                        [VN(CONST_SPACE, addr2, 8)],
                    ),
                    OP(
                        OpCode.STORE,
                        None,
                        [
                            VN(CONST_SPACE, 0xCACACACA, 0, space_encoded_in_offset=RAM_SPACE),
                            VN(UNIQUE_SPACE, 0, 8),
                            VN(UNIQUE_SPACE, 8, 8),
                        ],
                    ),
                ],
            ),
            state,
        )

        new_state = successors.successors[0]
        assert new_state.solver.is_true(new_state.memory.load(addr2, 8) == value)

    def _test_single_arith_binary_op(self, opcode: OpCode):
        opcode_to_operation = {
            OpCode.BOOL_AND: operator.and_,
            OpCode.BOOL_OR: operator.or_,
            OpCode.BOOL_XOR: operator.xor,
            OpCode.INT_ADD: operator.add,
            OpCode.INT_AND: operator.and_,
            OpCode.INT_DIV: operator.floordiv,
            OpCode.INT_EQUAL: operator.eq,
            OpCode.INT_LEFT: operator.lshift,
            OpCode.INT_LESS: operator.lt,
            OpCode.INT_LESSEQUAL: operator.le,
            OpCode.INT_MULT: operator.mul,
            OpCode.INT_NOTEQUAL: operator.ne,
            OpCode.INT_OR: operator.or_,
            OpCode.INT_REM: operator.mod,
            OpCode.INT_RIGHT: claripy.LShR,
            OpCode.INT_SLESS: claripy.SLT,
            OpCode.INT_SLESSEQUAL: claripy.SLE,
            OpCode.INT_SRIGHT: operator.rshift,
            OpCode.INT_SUB: operator.sub,
            OpCode.INT_XOR: operator.xor,
        }

        operation = opcode_to_operation.get(opcode)
        assert operation is not None

        is_boolean = opcode in {OpCode.BOOL_AND, OpCode.BOOL_OR, OpCode.BOOL_XOR}
        is_comparison = opcode in {
            OpCode.INT_EQUAL,
            OpCode.INT_LESS,
            OpCode.INT_LESSEQUAL,
            OpCode.INT_NOTEQUAL,
            OpCode.INT_SLESS,
            OpCode.INT_SLESSEQUAL,
        }

        operand_size = 1 if is_boolean else 4

        result_addr = 0x100000
        result_size = 1 if is_comparison else operand_size

        x_addr, x = 0, claripy.BVS("x", operand_size * 8)
        y_addr, y = operand_size, claripy.BVS("y", operand_size * 8)

        state = SimState(arch="AMD64", remove_options={"SIMPLIFY_MEMORY_WRITES"})
        state.memory.store(x_addr, x, endness="Iend_LE")
        state.memory.store(y_addr, y, endness="Iend_LE")

        successors = self._step_irsb(
            MockIRSB(
                [
                    OP(
                        OpCode.IMARK,
                        None,
                        [VN(RAM_SPACE, 0, 1)],
                    ),
                    OP(
                        opcode,
                        VN(RAM_SPACE, result_addr, operand_size),
                        [VN(RAM_SPACE, x_addr, operand_size), VN(RAM_SPACE, y_addr, operand_size)],
                    ),
                ]
            ),
            state,
        )

        assert len(successors.all_successors) == 1
        state = successors.all_successors[0]
        assert state.solver.eval(state.regs.pc == 1)

        result = state.memory.load(result_addr, result_size, endness="Iend_LE")

        if is_boolean:
            booleanize = angr.engines.pcode.behavior.OpBehavior.booleanize
            expected_result = operation(booleanize(x), booleanize(y)).zero_extend(7)
        elif is_comparison:
            expected_result = claripy.If(operation(x, y), claripy.BVV(1, 1), claripy.BVV(0, 1)).zero_extend(7)
        else:
            expected_result = operation(x, y)

        solver = claripy.Solver()
        maybe_true = solver.eval(result == expected_result, 1)[0]
        assert solver.is_true(maybe_true)

    def test_arith_binary_ops(self):
        for opcode in [
            OpCode.BOOL_AND,
            OpCode.BOOL_OR,
            OpCode.BOOL_XOR,
            OpCode.INT_ADD,
            OpCode.INT_AND,
            OpCode.INT_DIV,
            OpCode.INT_EQUAL,
            OpCode.INT_LEFT,
            OpCode.INT_LESS,
            OpCode.INT_LESSEQUAL,
            OpCode.INT_MULT,
            OpCode.INT_NOTEQUAL,
            OpCode.INT_OR,
            OpCode.INT_REM,
            OpCode.INT_RIGHT,
            # OpCode.INT_SDIV,  # FIXME
            OpCode.INT_SLESS,
            OpCode.INT_SLESSEQUAL,
            OpCode.INT_SRIGHT,
            OpCode.INT_SUB,
            OpCode.INT_XOR,
        ]:
            with self.subTest(opcode):
                self._test_single_arith_binary_op(opcode)

    def _test_single_arith_unary_op(self, opcode: OpCode):
        opcode_to_operation = {
            OpCode.INT_NEGATE: operator.inv,
            OpCode.INT_2COMP: operator.neg,
        }

        operation = opcode_to_operation.get(opcode)
        assert operation is not None

        operand_size = 4

        result_size = operand_size
        result_addr = 0x100000

        x_addr, x = 0, claripy.BVS("x", operand_size * 8)

        state = SimState(arch="AMD64", remove_options={"SIMPLIFY_MEMORY_WRITES"})
        state.memory.store(x_addr, x, endness="Iend_LE")

        successors = self._step_irsb(
            MockIRSB(
                [
                    OP(
                        OpCode.IMARK,
                        None,
                        [VN(RAM_SPACE, 0, 1)],
                    ),
                    OP(
                        opcode,
                        VN(RAM_SPACE, result_addr, operand_size),
                        [VN(RAM_SPACE, x_addr, operand_size)],
                    ),
                ]
            ),
            state,
        )

        assert len(successors.all_successors) == 1
        state = successors.all_successors[0]
        assert state.solver.eval(state.regs.pc == 1)

        result = state.memory.load(result_addr, result_size, endness="Iend_LE")
        expected_result = operation(x)

        assert claripy.Solver().is_true(result == expected_result)

    def test_arith_unary_ops(self):
        for opcode in [
            OpCode.INT_NEGATE,
            OpCode.INT_2COMP,
        ]:
            with self.subTest(opcode):
                self._test_single_arith_unary_op(opcode)

    def _test_other_unary_common(self, opcode, input_value, expected_value):
        operand_addr = 0x200000
        operand_size = input_value.size() // 8

        result_addr = 0x100000
        result_size = expected_value.size() // 8

        state = SimState(arch="AMD64", remove_options={"SIMPLIFY_MEMORY_WRITES"})
        state.memory.store(operand_addr, input_value, endness="Iend_LE")
        state.memory.store(result_addr, claripy.BVV(b"\xCA" * result_size), endness="Iend_LE")

        successors = self._step_irsb(
            MockIRSB(
                [
                    OP(
                        OpCode.IMARK,
                        None,
                        [VN(RAM_SPACE, 0, 1)],
                    ),
                    OP(
                        opcode,
                        VN(RAM_SPACE, result_addr, result_size),
                        [VN(RAM_SPACE, operand_addr, operand_size)],
                    ),
                ],
            ),
            state,
        )

        assert len(successors.all_successors) == 1
        state = successors.successors[0]
        v = state.memory.load(result_addr, result_size, endness="Iend_LE")
        assert state.solver.eval(v == expected_value)

    def test_bool_negate(self):
        # FIXME: Should values >1 be considered true? If some op only clears the 0th bit this may be incorrect
        self._test_other_unary_common(OpCode.BOOL_NEGATE, claripy.BVV(0, 8), claripy.BVV(1, 8))
        self._test_other_unary_common(OpCode.BOOL_NEGATE, claripy.BVV(1, 8), claripy.BVV(0, 8))
        self._test_other_unary_common(OpCode.BOOL_NEGATE, claripy.BVV(0xFF, 8), claripy.BVV(0, 8))

    def test_zext(self):
        self._test_other_unary_common(OpCode.INT_ZEXT, claripy.BVV(0x7234, 16), claripy.BVV(0x7234, 16))
        self._test_other_unary_common(OpCode.INT_ZEXT, claripy.BVV(0x7234, 16), claripy.BVV(0x0000_7234, 32))
        self._test_other_unary_common(OpCode.INT_ZEXT, claripy.BVV(0x8234, 16), claripy.BVV(0x0000_8234, 32))

    def test_sext(self):
        self._test_other_unary_common(OpCode.INT_SEXT, claripy.BVV(0x7234, 16), claripy.BVV(0x7234, 16))
        self._test_other_unary_common(OpCode.INT_SEXT, claripy.BVV(0x7234, 16), claripy.BVV(0x0000_7234, 32))
        self._test_other_unary_common(OpCode.INT_SEXT, claripy.BVV(0x8234, 16), claripy.BVV(0xFFFF_8234, 32))

    def test_popcount(self):
        self._test_other_unary_common(OpCode.POPCOUNT, claripy.BVV(0, 32), claripy.BVV(0, 32))
        self._test_other_unary_common(OpCode.POPCOUNT, claripy.BVV(0x12345678, 32), claripy.BVV(13, 32))
        self._test_other_unary_common(OpCode.POPCOUNT, claripy.BVV(0xFFFFFFFF, 32), claripy.BVV(32, 32))

    def test_lzcount(self):
        self._test_other_unary_common(OpCode.LZCOUNT, claripy.BVV(0xFFFF, 16), claripy.BVV(0, 16))
        self._test_other_unary_common(OpCode.LZCOUNT, claripy.BVV(0x7FFF, 16), claripy.BVV(1, 16))
        self._test_other_unary_common(OpCode.LZCOUNT, claripy.BVV(0x3F0F, 16), claripy.BVV(2, 16))
        self._test_other_unary_common(OpCode.LZCOUNT, claripy.BVV(0x0080, 16), claripy.BVV(8, 16))
        self._test_other_unary_common(OpCode.LZCOUNT, claripy.BVV(0x0001, 16), claripy.BVV(15, 16))
        self._test_other_unary_common(OpCode.LZCOUNT, claripy.BVV(0x0000, 16), claripy.BVV(16, 16))

    # TODO: Add tests for the following ops:
    # * = FIXME
    # ! = Not Implemented
    #
    # ! OpCode.CPOOLREF
    #   OpCode.FLOAT_ABS
    #   OpCode.FLOAT_ADD
    #   OpCode.FLOAT_CEIL
    #   OpCode.FLOAT_DIV
    #   OpCode.FLOAT_EQUAL
    #   OpCode.FLOAT_FLOAT2FLOAT
    #   OpCode.FLOAT_FLOOR
    #   OpCode.FLOAT_INT2FLOAT
    #   OpCode.FLOAT_LESS
    #   OpCode.FLOAT_LESSEQUAL
    #   OpCode.FLOAT_MULT
    #   OpCode.FLOAT_NAN
    #   OpCode.FLOAT_NEG
    #   OpCode.FLOAT_NOTEQUAL
    #   OpCode.FLOAT_ROUND
    #   OpCode.FLOAT_SQRT
    #   OpCode.FLOAT_SUB
    #   OpCode.FLOAT_TRUNC
    #   OpCode.INT_CARRY
    #   OpCode.INT_SBORROW
    #   OpCode.INT_SCARRY
    # * OpCode.INT_SDIV
    # * OpCode.INT_SREM
    # ! OpCode.NEW
    #   OpCode.RETURN


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    logging.getLogger("angr.engines.pcode").setLevel(logging.DEBUG)
    unittest.main()
