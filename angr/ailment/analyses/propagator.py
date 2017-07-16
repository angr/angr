
import logging
from collections import defaultdict

import ailment

from angr.engines.light import SimEngineLightVEX, SimEngineLightAIL, SpOffset, RegisterOffset
from angr import Analysis, register_analysis
from angr.analyses.forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor


l = logging.getLogger('ailment.analyses.propagator')


class Atom(object):
    def __init__(self):
        pass

    def __repr__(self):
        raise NotImplementedError()


class Register(Atom):

    __slots__ = [ 'reg_offset', 'size' ]

    def __init__(self, reg_offset, size):
        super(Register, self).__init__()

        self.reg_offset = reg_offset
        self.size = size


class MemoryLocation(Atom):

    __slots__ = [ 'addr', 'size' ]

    def __init__(self, addr, size):
        super(MemoryLocation, self).__init__()

        self.addr = addr
        self.size = size


class PropagatorState(object):
    def __init__(self, arch, reaching_definitions=None):

        self.arch = arch
        self.reaching_definitions = reaching_definitions

        self._replacements = { }
        self._final_replacements = [ ]

    def __repr__(self):
        return "<PropagatorState>"

    def copy(self):
        rd = PropagatorState(
            self.arch,
            reaching_definitions=self.reaching_definitions,
        )

        rd._replacements = self._replacements.copy()
        rd._final_replacements = self._final_replacements[ :: ]

        return rd

    def merge(self, *others):

        state = self.copy()

        keys_to_remove = set()

        for o in others:
            for k, v in o._replacements.iteritems():
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

        for k, v in self._replacements.iteritems():
            if isinstance(v, ailment.Expression) and (v == atom or v.has_atom(atom)):
                keys_to_remove.add(k)

        for k in keys_to_remove:
            self._replacements.pop(k)

    def add_final_replacement(self, codeloc, old, new):
        self._final_replacements.append((codeloc, old, new))


def get_engine(base_engine):
    class SimEngineProp(base_engine):
        def __init__(self):
            super(SimEngineProp, self).__init__()

        def _process(self, state, successors, block=None):
            super(SimEngineProp, self)._process(state, successors, block=block)

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

        #
        # AIL statement handlers
        #

        def _ail_handle_Assignment(self, stmt):
            """

            :param ailment.Assignment stmt:
            :return:
            """

            src = self._expr(stmt.src)
            dst = stmt.dst

            if type(dst) is ailment.Tmp:
                new_src = self.state.get_replacement(src)
                if new_src is not None:
                    l.debug("%s = %s, replace %s with %s.", dst, src, src, new_src)
                    self.state.add_replacement(dst, new_src)
                else:
                    l.debug("Replacing %s with %s.", dst, src)
                    self.state.add_replacement(dst, src)

            elif type(dst) is ailment.Register:

                # remove previous replacements whose source contains this register
                self.state.filter_replacements(dst)

                new_src = self.state.get_replacement(src)
                if new_src is not None:
                    l.debug("Handle assignment: %s = %s, replace %s with %s.", dst, src, src, new_src)
                    self.state.add_replacement(dst, new_src)
                    src = new_src

                l.debug("New replacement: %s with %s", (dst, src))
                self.state.add_replacement(dst, src)
            else:
                l.warning('Unsupported type of Assignment dst %s.', type(dst).__name__)

        def _ail_handle_Store(self, stmt):
            _ = self._expr(stmt.addr)
            _ = self._expr(stmt.data)

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
            new_expr = self.state.get_replacement(expr)
            if new_expr is not None:
                l.debug("Add a final replacement: %s with %s", expr, new_expr)
                self.state.add_final_replacement(self._codeloc(), expr, new_expr)
                expr = new_expr
            return expr

        def _ail_handle_Load(self, expr):
            addr = self._expr(expr.addr)
            return expr

        def _ail_handle_Convert(self, expr):
            converted = self._expr(expr.operand)
            return converted

    return SimEngineProp


class Propagator(ForwardAnalysis, Analysis):
    def __init__(self, func=None, block=None, reaching_definitions=None, max_iterations=3):
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
        self._reaching_definitions = reaching_definitions

        self._node_iterations = defaultdict(int)
        self._states = { }

        self._engine_vex = get_engine(SimEngineLightVEX)()
        self._engine_ail = get_engine(SimEngineLightAIL)()

        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        return PropagatorState(self.project.arch, reaching_definitions=self._reaching_definitions)

    def _merge_states(self, node, *states):
        return states[0].merge(*states[1:])

    def _run_on_node(self, node, state):

        input_state = state

        if isinstance(node, ailment.Block):
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

register_analysis(Propagator, "Propagator")
