
import logging
from collections import defaultdict

import ailment

from ..engines.light import SimEngineLightVEX, SimEngineLightAIL, SpOffset, RegisterOffset
from .analysis import Analysis
from . import register_analysis
from .forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor


l = logging.getLogger('angr.analyses.reaching_definitions')


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


class ReachingDefinitions(object):
    def __init__(self, arch):

        # handy short-hands
        self.arch = arch

        self._register_definitions = defaultdict(set)
        self._memory_definitions = defaultdict(set)

        self._register_uses = defaultdict(set)
        self._memory_uses = defaultdict(set)

        self.registers = { }
        self.memory = { }

    def __repr__(self):
        return "<ReachingDefinitions, %d regdef, %d memdef>" % (len(self._register_definitions),
                                                                len(self._memory_definitions)
                                                                )

    def copy(self):
        rd = ReachingDefinitions(
            self.arch,
        )
        rd._register_definitions = self._register_definitions.copy()
        rd._memory_definitions = self._memory_definitions.copy()
        rd._register_uses = self._register_uses.copy()
        rd._memory_uses = self._memory_uses.copy()
        rd.registers = self.registers.copy()
        rd.memory = self.memory.copy()

        return rd

    def merge(self, *others):

        state = self.copy()

        for other in others:
            for k, v in other._register_definitions.iteritems():
                if k not in state._register_definitions:
                    state._register_definitions[k] = set(v)
                else:
                    state._register_definitions[k] |= v

            for k, v in other._memory_definitions.iteritems():
                if k not in state._memory_definitions:
                    state._memory_definitions[k] = set(v)
                else:
                    state._memory_definitions[k] |= v

            for k, v in other._register_uses.iteritems():
                if k not in state._register_uses:
                    state._register_uses[k] = set(v)
                else:
                    state._register_uses[k] |= v

            for k, v in other._memory_uses.iteritems():
                if k not in state._memory_uses:
                    state._memory_uses[k] = set(v)
                else:
                    state._memory_uses[k] |= v

        return state

    def add_definition(self, atom, code_loc):
        if type(atom) is Register:
            self._add_register_definition(atom, code_loc)
        elif type(atom) is MemoryLocation:
            self._add_memory_definition(atom, code_loc)

    def kill_definitions(self, atom):
        if type(atom) is Register:
            self._kill_register_definitions(atom)
        elif type(atom) is MemoryLocation:
            self._kill_memory_definitions(atom)

    def add_use(self, atom, code_loc):
        if type(atom) is Register:
            self._add_register_use(atom, code_loc)
        elif type(atom) is MemoryLocation:
            self._add_memory_use(atom, code_loc)

    #
    # Private methods
    #

    def _add_register_definition(self, atom, code_loc):

        # TODO: improve
        self._register_definitions[atom.reg_offset].add(code_loc)

    def _add_memory_definition(self, atom, code_loc):

        self._memory_definitions[atom.addr].add(code_loc)

    def _kill_register_definitions(self, atom):
        self._register_definitions.pop(atom.reg_offset, None)

    def _kill_memory_definitions(self, atom):
        self._memory_definitions.pop(atom.addr, None)

    def _add_register_use(self, atom, code_loc):

        # get all current definitions
        current_defs = self._register_definitions.get(atom.reg_offset, None)

        if current_defs:
            self._register_uses[(atom.reg_offset, code_loc)] |= current_defs

    def _add_memory_use(self, atom, code_loc):

        # get all current definitions
        current_defs = self._memory_definitions.get(atom.addr, None)

        if current_defs:
            self._memory_uses[(atom.addr, code_loc)] |= current_defs


def get_engine(base_engine):
    class SimEngineRD(base_engine):
        def __init__(self):
            super(SimEngineRD, self).__init__()

        def _process(self, state, successors, block=None):
            super(SimEngineRD, self)._process(state, successors, block=block)

        #
        # VEX statement handlers
        #

        def _handle_Put(self, stmt):
            reg_offset = stmt.offset
            size = stmt.data.result_size(self.tyenv) / 8
            reg = Register(reg_offset, size)

            self.state.kill_definitions(reg)
            self.state.add_definition(reg, self._codeloc())

            data = self._expr(stmt.data)

            self.state.registers[reg_offset] = data

        def _handle_Store(self, stmt):
            addr = stmt.addr
            size = stmt.data.result_size(self.tyenv) / 8
            memloc = MemoryLocation(addr, size)

            self.state.kill_definitions(memloc)
            self.state.add_definition(memloc, self._codeloc())

            data = self._expr(stmt.data)
            self.state.memory[addr] = data

        #
        # VEX expression handlers
        #

        def _handle_Get(self, expr):

            reg_offset = expr.offset
            size = expr.result_size(self.tyenv)

            if reg_offset == self.arch.sp_offset:
                return SpOffset(self.arch.bits, 0)
            elif reg_offset == self.arch.bp_offset:
                return SpOffset(self.arch.bits, 0, is_base=True)

            try:
                self.state.registers[reg_offset]
            except KeyError:
                return RegisterOffset(size * 8, reg_offset, 0)

        def _handle_Load(self, expr):

            addr = self._expr(expr.addr)

            return self.state.memory.get(addr, None)

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
                self.tmps[dst.tmp_idx] = src
            elif type(dst) is ailment.Register:

                reg = Register(dst.register_offset, dst.bits / 8)

                self.state.kill_definitions(reg)
                self.state.add_definition(reg, self._codeloc())

                self.state.registers[dst.register_offset] = src
            else:
                l.warning('Unsupported type of Assignment dst %s.', type(dst).__name__)

        def _ail_handle_Store(self, stmt):
            print stmt

        #
        # AIL expression handlers
        #

        def _ail_handle_Register(self, expr):

            reg_offset = expr.register_offset
            bits = expr.bits

            self.state.add_use(Register(reg_offset, bits / 8), self._codeloc())

            if reg_offset == self.arch.sp_offset:
                return SpOffset(bits, 0)
            elif reg_offset == self.arch.bp_offset:
                return SpOffset(bits, 0, is_base=True)

            try:
                return self.state.registers[reg_offset]
            except KeyError:
                return RegisterOffset(bits, reg_offset, 0)

    return SimEngineRD


class ReachingDefinitionAnalysis(ForwardAnalysis, Analysis):
    def __init__(self, func=None, block=None, max_iterations=3):
        """

        """

        if func is not None:
            # traversing a function
            graph_visitor = FunctionGraphVisitor(func)
        elif block is not None:
            # traversing a block
            graph_visitor = SingleNodeGraphVisitor(block)
        else:
            raise ValueError('Unsupported analysis target.')

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=graph_visitor)

        self._max_iterations = max_iterations
        self._function = func
        self._block = block

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
        return ReachingDefinitions(self.project.arch)

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

register_analysis(ReachingDefinitionAnalysis, "ReachingDefinitions")
