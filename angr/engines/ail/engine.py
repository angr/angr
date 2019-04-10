
from ..engine import SimEngine
from .nodes import init, NODE_HANDLERS
from ... import sim_options as o
from ...state_plugins.inspect import BP_AFTER, BP_BEFORE
from .statements import *
from .expressions import *

class SimEngineAIL(SimEngine):
    """
    Execution engine based on AIL.
    """

    def __init__(self, project=None):
        super().__init__(project)

        init()
        print(NODE_HANDLERS)
        self.node_handlers = NODE_HANDLERS
        self.stmt_handlers = STMT_CLASSES
        self.expr_handlers = EXPR_CLASSES

    def _check(self, state, *args, **kwargs):
        """
        Check whether the AIL symbolic execution engine is applicable for the current address or not.

        :param state:
        :param args:
        :param kwargs:
        :return:        True if it is applicable, False otherwise.
        """
        kb = kwargs.pop("kb", None)
        if kb is None:
            # KB must be available
            return False

        addr = state._ip
        if addr.symbolic:
            return False

        addr = state.solver.eval(addr)
        if self.lift(addr=addr, kb=kb) is None:
            return False

        return True

    def lift(self, addr=None, kb=None):
        """
        Get an AIL node at address `addr` from the given angr knowledge base.

        :param int addr:            The concrete address to lift at.
        :param KnowledgeBase kb:    The angr knowledge base.
        :return:                    The AIL node that starts at address `addr`.
        """

        node = kb.clinic.get_node(addr)

        return node

    def _process(self, state, successors, kb=None, **kwargs):
        """

        :param state:
        :param successors:
        :param kwargs:
        :return:
        """

        if state.ailexecstack.is_empty():
            # The execution stack is empty. Load a new node according to the address
            addr = state.solver.eval(state._ip)
            # get the node
            node = self.lift(addr=addr, kb=kb)
            # push the node on the stack
            state.ailexecstack.push(node)

        # execute the stack
        self._handle_stack(state, successors)

    def _handle_stack(self, state, successors):
        """

        :param state:
        :param successors:
        :param node:
        :return:
        """

        cont = False
        while cont is False:
            # get the next node based on the top element on the stack
            node = state.ailexecstack.pop()

            # Hook block node handler here for now
            if isinstance(node, ailment.Block):
                for stmt in node.statements:
                    self._handle_statement(state, successors, stmt)
                continue

            # handle the node
            cont = self.node_handlers[node.__class__](self, state, node)


    def _handle_statement(self, state, successors, stmt):
        # if type(stmt) == pyvex.IRStmt.IMark:
        #     # TODO how much of this could be moved into the imark handler
        #     ins_addr = stmt.addr + stmt.delta
        #     state.scratch.ins_addr = ins_addr

        #     # Raise an exception if we're suddenly in self-modifying code
        #     for subaddr in range(stmt.len):
        #         if subaddr + stmt.addr in state.scratch.dirty_addrs:
        #             raise SimReliftException(state)
        #     state._inspect('instruction', BP_AFTER)

        #     l.debug("IMark: %#x", stmt.addr)
        #     state.scratch.num_insns += 1
        #     state._inspect('instruction', BP_BEFORE, instruction=ins_addr)

        # process it!
        try:
            stmt_handler = self.stmt_handlers[stmt.__class__]
        except IndexError:
            l.error("Unsupported statement type %s", (type(stmt)))
            if o.BYPASS_UNSUPPORTED_IRSTMT not in state.options:
                raise UnsupportedIRStmtError("Unsupported statement type %s" % (type(stmt)))
            state.history.add_event('resilience', resilience_type='irstmt', stmt=type(stmt).__name__, message='unsupported IRStmt')
            return None
        else:
            exit_data = stmt_handler(self, state, stmt)

        # for the exits, put *not* taking the exit on the list of constraints so
        # that we can continue on. Otherwise, add the constraints
        if exit_data is not None:
            l.debug("%s adding conditional exit", self)

            target, guard, jumpkind = exit_data

            # Produce our successor state!
            # Let SimSuccessors.add_successor handle the nitty gritty details

            cont_state = None
            exit_state = None

            if o.COPY_STATES not in state.options:
                # very special logic to try to minimize copies
                # first, check if this branch is impossible
                if guard.is_false():
                    cont_state = state
                elif o.LAZY_SOLVES not in state.options and not state.solver.satisfiable(extra_constraints=(guard,)):
                    cont_state = state

                # then, check if it's impossible to continue from this branch
                elif guard.is_true():
                    exit_state = state
                elif o.LAZY_SOLVES not in state.options and not state.solver.satisfiable(extra_constraints=(claripy.Not(guard),)):
                    exit_state = state
                else:
                    exit_state = state.copy()
                    cont_state = state
            else:
                exit_state = state.copy()
                cont_state = state

            if exit_state is not None:
                successors.add_successor(exit_state, target, guard, jumpkind,
                                         exit_stmt_idx=state.scratch.stmt_idx, exit_ins_addr=state.scratch.ins_addr)

            if cont_state is None:
                return False

            # Do our bookkeeping on the continuing state
            cont_condition = claripy.Not(guard)
            cont_state.add_constraints(cont_condition)
            cont_state.scratch.guard = claripy.And(cont_state.scratch.guard, cont_condition)

        return True

    def _handle_expression(self, state, expr):
        try:
            handler = self.expr_handlers[expr.__class__]
            if handler is None:
                raise IndexError
        except IndexError:
            if o.BYPASS_UNSUPPORTED_IREXPR not in state.options:
                raise UnsupportedIRExprError("Unsupported expression type %s" % (type(expr)))
            else:
                handler = SimIRExpr_Unsupported

        state._inspect('expr', BP_BEFORE, expr=expr)
        result = handler(self, state, expr)

        if o.SIMPLIFY_EXPRS in state.options:
            result = state.solver.simplify(result)

        if state.solver.symbolic(result) and o.CONCRETIZE in state.options:
            concrete_value = state.solver.BVV(state.solver.eval(result), len(result))
            state.add_constraints(result == concrete_value)
            result = concrete_value

        state._inspect('expr', BP_AFTER, expr=expr, expr_result=result)
        return result
