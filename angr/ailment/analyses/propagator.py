
import logging
from collections import defaultdict

from .. import Stmt, Expr, Block

from angr.engines.light import SimEngineLightVEX, SimEngineLightAIL, SpOffset, RegisterOffset
from angr import Analysis, register_analysis
from angr.analyses.forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor
from angr.utils.constants import is_alignment_mask


l = logging.getLogger('ailment.analyses.propagator')


class PropagatorState:
    def __init__(self, arch):

        self.arch = arch

        self._replacements = { }
        self._final_replacements = [ ]

    def __repr__(self):
        return "<PropagatorState>"

    def copy(self):
        rd = PropagatorState(
            self.arch,
        )

        rd._replacements = self._replacements.copy()
        rd._final_replacements = self._final_replacements[ :: ]

        return rd

    def merge(self, *others):

        state = self.copy()

        keys_to_remove = set()

        for o in others:
            for k, v in o._replacements.items():
                if k not in state._replacements:
                    state._replacements[k] = v
                else:
                    if state._replacements[k] != o._replacements[k]:
                        keys_to_remove.add(k)

        for k in keys_to_remove:
            del state._replacements[k]

        return state

    def add_replacement(self, old, new):
        if new is not None:
            self._replacements[old] = new

    def get_replacement(self, old):
        return self._replacements.get(old, None)

    def remove_replacement(self, old):
        self._replacements.pop(old, None)

    def filter_replacements(self, atom):
        keys_to_remove = set()

        for k, v in self._replacements.items():
            if isinstance(v, Expr.Expression) and (v == atom or v.has_atom(atom)):
                keys_to_remove.add(k)

        for k in keys_to_remove:
            self._replacements.pop(k)

    def add_final_replacement(self, codeloc, old, new):
        self._final_replacements.append((codeloc, old, new))


def get_engine(base_engine):
    class SimEnginePropagator(base_engine):
        def __init__(self, stack_pointer_tracker=None):
            super(SimEnginePropagator, self).__init__()
            self._stack_pointer_tracker = stack_pointer_tracker

        def _process(self, state, successors, block=None):
            super(SimEnginePropagator, self)._process(state, successors, block=block)

        #
        # VEX statement handlers
        #

        def _handle_Put(self, stmt):
            raise NotImplementedError()

        def _handle_Store(self, stmt):
            raise NotImplementedError()

        #
        # VEX expression handlers
        #

        def _handle_Get(self, expr):
            raise NotImplementedError()

        def _handle_Load(self, expr):
            raise NotImplementedError()

        def _handle_DirtyExpression(self, expr):
            raise NotImplementedError()

        #
        # AIL statement handlers
        #

        def _ail_handle_Assignment(self, stmt):
            """

            :param Stmt.Assignment stmt:
            :return:
            """

            src = self._expr(stmt.src)
            dst = stmt.dst

            if type(dst) is Expr.Tmp:
                new_src = self.state.get_replacement(src)
                if new_src is not None:
                    l.debug("%s = %s, replace %s with %s.", dst, src, src, new_src)
                    self.state.add_replacement(dst, new_src)
                else:
                    l.debug("Replacing %s with %s.", dst, src)
                    self.state.add_replacement(dst, src)

            elif type(dst) is Expr.Register:
                l.debug("New replacement: %s with %s", dst, src)
                self.state.add_replacement(dst, src)

                # remove previous replacements whose source contains this register
                self.state.filter_replacements(dst)
            else:
                l.warning('Unsupported type of Assignment dst %s.', type(dst).__name__)

        def _ail_handle_Store(self, stmt):
            addr = self._expr(stmt.addr)
            data = self._expr(stmt.data)

            if isinstance(addr, Expr.StackBaseOffset):
                # Storing data to a stack variable
                self.state.add_replacement(Expr.Load(None, addr, data.bits // 8, stmt.endness), data)

        def _ail_handle_Jump(self, stmt):
            target = self._expr(stmt.target)

        def _ail_handle_Call(self, stmt):
            target = self._expr(stmt.target)

            new_args = None

            if stmt.args:
                new_args = [ ]
                for arg in stmt.args:
                    new_arg = self._expr(arg)
                    replacement = self.state.get_replacement(new_arg)
                    if replacement is not None:
                        new_args.append(replacement)
                    else:
                        new_args.append(arg)

            if new_args != stmt.args:
                new_call_stmt = Stmt.Call(stmt.idx, target, calling_convention=stmt.calling_convention,
                                          prototype=stmt.prototype, args=new_args, ret_expr=stmt.ret_expr,
                                          **stmt.tags)
                self.state.add_final_replacement(self._codeloc(),
                                                 stmt,
                                                 new_call_stmt,
                                                 )

        def _ail_handle_ConditionalJump(self, stmt):
            cond = self._expr(stmt.condition)
            true_target = self._expr(stmt.true_target)
            false_target = self._expr(stmt.false_target)

            if cond is stmt.condition and \
                    true_target is stmt.true_target and \
                    false_target is stmt.false_target:
                pass
            else:
                new_jump_stmt = Stmt.ConditionalJump(stmt.idx, cond, true_target, false_target, **stmt.tags)
                self.state.add_final_replacement(self._codeloc(),
                                                 stmt,
                                                 new_jump_stmt,
                                                 )

        #
        # AIL expression handlers
        #

        def _ail_handle_Tmp(self, expr):
            new_expr = self.state.get_replacement(expr)

            if new_expr is not None:
                l.debug("Add a final replacement: %s with %s", expr, new_expr)
                self.state.add_final_replacement(self._codeloc(), expr, new_expr)
                expr = new_expr

            return expr

        def _ail_handle_Register(self, expr):
            # Special handling for SP and BP
            if self._stack_pointer_tracker is not None:
                if expr.reg_offset == self.arch.sp_offset:
                    sb_offset = self._stack_pointer_tracker.offset_before(self.ins_addr, self.arch.sp_offset)
                    if sb_offset is not None:
                        new_expr = Expr.StackBaseOffset(None, self.arch.bits, sb_offset)
                        self.state.add_final_replacement(self._codeloc(), expr, new_expr)
                        return new_expr
                elif expr.reg_offset == self.arch.bp_offset:
                    sb_offset = self._stack_pointer_tracker.offset_before(self.ins_addr, self.arch.bp_offset)
                    if sb_offset is not None:
                        new_expr = Expr.StackBaseOffset(None, self.arch.bits, sb_offset)
                        self.state.add_final_replacement(self._codeloc(), expr, new_expr)
                        return new_expr

            new_expr = self.state.get_replacement(expr)
            if new_expr is not None:
                l.debug("Add a final replacement: %s with %s", expr, new_expr)
                self.state.add_final_replacement(self._codeloc(), expr, new_expr)
                expr = new_expr
            return expr

        def _ail_handle_Load(self, expr):
            addr = self._expr(expr.addr)

            if addr != expr.addr:
                return Expr.Load(expr.idx, addr, expr.size, expr.endness, **expr.tags)
            return expr

        def _ail_handle_Convert(self, expr):
            operand_expr = self._expr(expr.operand)

            if type(operand_expr) is Expr.Convert:
                if expr.from_bits == operand_expr.to_bits and expr.to_bits == operand_expr.from_bits:
                    # eliminate the redundant Convert
                    return operand_expr.operand
                else:
                    return Expr.Convert(expr.idx, operand_expr.from_bits, expr.to_bits, expr.is_signed, operand_expr.operand)
            elif type(operand_expr) is Expr.Const:
                # do the conversion right away
                value = operand_expr.value
                mask = (2 ** expr.to_bits) - 1
                value &= mask
                return Expr.Const(expr.idx, operand_expr.variable, value, expr.to_bits)

            converted = Expr.Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, operand_expr)
            return converted

        def _ail_handle_Const(self, expr):
            return expr

        def _ail_handle_DirtyExpression(self, expr):
            return expr

        def _ail_handle_CmpLE(self, expr):
            operand_0 = self._expr(expr.operands[0])
            operand_1 = self._expr(expr.operands[1])

            return Expr.BinaryOp(expr.idx, 'CmpLE', [ operand_0, operand_1 ])

        def _ail_handle_CmpEQ(self, expr):
            operand_0 = self._expr(expr.operands[0])
            operand_1 = self._expr(expr.operands[1])

            return Expr.BinaryOp(expr.idx, 'CmpEQ', [ operand_0, operand_1 ])

        def _ail_handle_Add(self, expr):
            operand_0 = self._expr(expr.operands[0])
            operand_1 = self._expr(expr.operands[1])

            if isinstance(operand_0, Expr.Const) and isinstance(operand_1, Expr.Const):
                return Expr.Const(expr.idx, None, operand_0.value + operand_1.value, expr.bits)
            elif isinstance(operand_0, Expr.BasePointerOffset) and isinstance(operand_1, Expr.Const):
                r = operand_0.copy()
                r.offset += operand_1.value
                return r
            return Expr.BinaryOp(expr.idx, 'Add', [operand_0 if operand_0 is not None else expr.operands[0],
                                                   operand_1 if operand_1 is not None else expr.operands[1]
                                                   ])

        def _ail_handle_Sub(self, expr):
            operand_0 = self._expr(expr.operands[0])
            operand_1 = self._expr(expr.operands[1])

            if isinstance(operand_0, Expr.Const) and isinstance(operand_1, Expr.Const):
                return Expr.Const(expr.idx, None, operand_0.value - operand_1.value, expr.bits)
            elif isinstance(operand_0, Expr.BasePointerOffset) and isinstance(operand_1, Expr.Const):
                r = operand_0.copy()
                r.offset -= operand_1.value
                return r
            return Expr.BinaryOp(expr.idx, 'Sub', [ operand_0 if operand_0 is not None else expr.operands[0],
                                                    operand_1 if operand_1 is not None else expr.operands[1]
                                                    ])

        def _ail_handle_StackBaseOffset(self, expr):
            return expr

        def _ail_handle_And(self, expr):
            operand_0 = self._expr(expr.operands[0])
            operand_1 = self._expr(expr.operands[1])

            # Special logic for SP alignment
            if type(operand_0) is Expr.StackBaseOffset and \
                    type(operand_1) is Expr.Const and is_alignment_mask(operand_1.value):
                return operand_0

            return Expr.BinaryOp(expr.idx, 'And', [ operand_0, operand_1 ])

        def _ail_handle_Xor(self, expr):
            operand_0 = self._expr(expr.operands[0])
            operand_1 = self._expr(expr.operands[1])

            return Expr.BinaryOp(expr.idx, 'Xor', [ operand_0, operand_1 ])

    return SimEnginePropagator


class Propagator(ForwardAnalysis, Analysis):
    def __init__(self, func=None, block=None, max_iterations=3, stack_pointer_tracker=None):
        """

        """

        if func is not None:
            # traversing a function
            graph_visitor = FunctionGraphVisitor(func)
        elif block is not None:
            # traversing a block
            graph_visitor = SingleNodeGraphVisitor(block)
        else:
            raise ValueError('HUH')

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=graph_visitor)

        self._max_iterations = max_iterations
        self._function = func
        self._block = block
        self._stack_pointer_tracker = stack_pointer_tracker

        self._node_iterations = defaultdict(int)
        self._states = { }

        self._engine_vex = get_engine(SimEngineLightVEX)(stack_pointer_tracker=self._stack_pointer_tracker)
        self._engine_ail = get_engine(SimEngineLightAIL)(stack_pointer_tracker=self._stack_pointer_tracker)

        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        return PropagatorState(self.project.arch)

    def _merge_states(self, node, *states):
        return states[0].merge(*states[1:])

    def _run_on_node(self, node, state):

        input_state = state

        if isinstance(node, Block):
            block = node
            block_key = node.addr
            engine = self._engine_ail
        else:
            block = self.project.factory.block(node.addr, node.size, opt_level=0)
            block_key = node.addr
            engine = self._engine_vex

        state = input_state.copy()

        engine.process(state, block=block)

        self._node_iterations[block_key] += 1

        self._states[block_key] = state

        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

register_analysis(Propagator, "AILPropagator")
