
import logging
from collections import defaultdict

import ailment

from ..knowledge.keyed_region import KeyedRegion
from ..engines.light import SimEngineLightVEX, SimEngineLightAIL, SpOffset, RegisterOffset
from .analysis import Analysis
from . import register_analysis
from .forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor


l = logging.getLogger('angr.analyses.reaching_definitions')

#
# Observation point types
#
OP_BEFORE = 0
OP_AFTER = 1


class Atom(object):
    def __init__(self):
        pass

    def __repr__(self):
        raise NotImplementedError()


class Tmp(Atom):

    __slots__ = [ 'tmp_idx' ]

    def __init__(self, tmp_idx):
        super(Tmp, self).__init__()
        self.tmp_idx = tmp_idx

    def __repr__(self):
        return "<Tmp %d>" % self.tmp_idx

    def __eq__(self, other):
        return type(other) is Tmp and \
                self.tmp_idx == other.tmp_idx

    def __hash__(self):
        return hash(('tmp', self.tmp_idx))


class Register(Atom):

    __slots__ = [ 'reg_offset', 'size' ]

    def __init__(self, reg_offset, size):
        super(Register, self).__init__()

        self.reg_offset = reg_offset
        self.size = size

    def __repr__(self):
        return "<Reg %d<%d>>" % (self.reg_offset, self.size)

    def __eq__(self, other):
        return type(other) is Register and \
                self.reg_offset == other.reg_offset and \
                self.size == other.size

    def __hash__(self):
        return hash(('reg', self.reg_offset, self.size))


class MemoryLocation(Atom):

    __slots__ = [ 'addr', 'size' ]

    def __init__(self, addr, size):
        super(MemoryLocation, self).__init__()

        self.addr = addr
        self.size = size

    def __eq__(self, other):
        return type(other) is MemoryLocation and \
                self.addr == other.addr and \
                self.size == other.size

    def __hash__(self):
        return hash(('mem', self.addr, self.size))


class Definition(object):
    def __init__(self, atom, codeloc):
        self.atom = atom
        self.codeloc = codeloc

    def __eq__(self, other):
        return self.atom == other.atom and self.codeloc == other.codeloc

    def __hash__(self):
        return hash((self.atom, self.codeloc))

    @property
    def offset(self):
        if type(self.atom) is MemoryLocation:
            return self.atom.addr
        elif type(self.atom) is Register:
            return self.atom.reg_offset
        else:
            raise ValueError('Unsupported operation offset on %s.' % type(self.atom))

    @property
    def size(self):
        if type(self.atom) is MemoryLocation:
            return self.atom.size
        elif type(self.atom) is Register:
            return self.atom.size
        else:
            raise ValueError('Unsupported operation size on %s.' % type(self.atom))


class Uses(object):
    def __init__(self):
        self._uses_by_definition = defaultdict(set)
        self._current_uses = KeyedRegion()

    def add_use(self, definition, codeloc):
        self._uses_by_definition[definition].add(codeloc)
        self._current_uses.set_object(definition.offset, definition, definition.size)

    def get_uses(self, definition):
        if not definition in self._uses_by_definition:
            return set()
        return self._uses_by_definition[definition]

    def get_current_uses(self, definition):
        # TODO: optimize it
        all_uses = set()

        offset = definition.offset
        for pos in xrange(definition.size):
            all_uses |= set(self._current_uses.get_objects_by_offset(offset + pos))

        return all_uses

    def copy(self):
        u = Uses()
        u._uses_by_definition = self._uses_by_definition.copy()
        u._current_uses = self._current_uses.copy()

        return u

    def merge(self, other):

        for k, v in other._uses_by_definition.iteritems():
            if k not in self._uses_by_definition:
                self._uses_by_definition[k] = v
            else:
                self._uses_by_definition[k] |= v

        self._current_uses.merge(other)


class ReachingDefinitions(object):
    def __init__(self, arch, track_tmps=False, analysis=None):

        self._track_tmps = track_tmps
        self.analysis = analysis

        # handy short-hands
        self.arch = arch

        self.register_definitions = defaultdict(set)
        self.memory_definitions = defaultdict(set)
        self.tmp_definitions = { }

        self.register_uses = Uses()
        self.memory_uses = Uses()
        self.tmp_uses = defaultdict(set)

        self._dead_virgin_definitions = set()  # definitions that are killed before used

        self.registers = { }
        self.memory = { }

    def __repr__(self):
        ctnt = "ReachingDefinitions, %d regdefs, %d memdefs" % (len(self.register_definitions),
                                                              len(self.memory_definitions),
                                                              )
        if self._track_tmps:
            ctnt += ", %d tmpdefs" % len(self.tmp_definitions)
        return "<%s>" % ctnt

    def copy(self):
        rd = ReachingDefinitions(
            self.arch,
            track_tmps=self._track_tmps,
            analysis=self.analysis,
        )
        rd.register_definitions = self.register_definitions.copy()
        rd.memory_definitions = self.memory_definitions.copy()
        rd.tmp_definitions = self.tmp_definitions.copy()
        rd.register_uses = self.register_uses.copy()
        rd.memory_uses = self.memory_uses.copy()
        rd.tmp_uses = self.tmp_uses.copy()
        rd._dead_virgin_definitions = self._dead_virgin_definitions.copy()
        rd.registers = self.registers.copy()
        rd.memory = self.memory.copy()

        return rd

    def merge(self, *others):

        state = self.copy()

        for other in others:
            for k, v in other.register_definitions.iteritems():
                if k not in state.register_definitions:
                    state.register_definitions[k] = set(v)
                else:
                    state.register_definitions[k] |= v

            for k, v in other.memory_definitions.iteritems():
                if k not in state.memory_definitions:
                    state.memory_definitions[k] = set(v)
                else:
                    state.memory_definitions[k] |= v

            state.register_uses.merge(other._register_uses)
            state.memory_uses.merge(other._memory_uses)

            state._dead_virgin_definitions |= other._unused_definitions

        return state

    def downsize(self):
        self.analysis = None

    def add_definition(self, atom, code_loc):
        if type(atom) is Register:
            self._add_register_definition(atom, code_loc)
        elif type(atom) is MemoryLocation:
            self._add_memory_definition(atom, code_loc)
        elif type(atom) is Tmp:
            self._add_tmp_definition(atom, code_loc)

    def kill_definitions(self, atom):
        if type(atom) is Register:
            self._kill_register_definitions(atom)
        elif type(atom) is MemoryLocation:
            self._kill_memory_definitions(atom)
        elif type(atom) is Tmp:
            # it should never happen
            assert False

    def add_use(self, atom, code_loc):
        if type(atom) is Register:
            self._add_register_use(atom, code_loc)
        elif type(atom) is MemoryLocation:
            self._add_memory_use(atom, code_loc)
        elif type(atom) is Tmp:
            self._add_tmp_use(atom, code_loc)

    #
    # Private methods
    #

    def _add_register_definition(self, atom, code_loc):

        # TODO: improve
        self.register_definitions[atom.reg_offset].add(Definition(atom, code_loc))

    def _add_memory_definition(self, atom, code_loc):

        self.memory_definitions[atom.addr].add(Definition(atom, code_loc))

    def _add_tmp_definition(self, atom, code_loc):
        self.tmp_definitions[atom.tmp_idx] = (atom, code_loc)

    def _kill_register_definitions(self, atom):

        defs = self.register_definitions.pop(atom.reg_offset, None)

        # check whether there is any use of this def
        if defs:
            uses = set()
            for def_ in defs:
                uses |= self.register_uses.get_current_uses(def_)

            if not uses:
                self._dead_virgin_definitions |= defs

    def _kill_memory_definitions(self, atom):
        self.memory_definitions.pop(atom.addr, None)

    def _add_register_use(self, atom, code_loc):

        # get all current definitions
        current_defs = self.register_definitions.get(atom.reg_offset, None)

        if current_defs:
            for current_def in current_defs:
                self.register_uses.add_use(current_def, code_loc)

    def _add_memory_use(self, atom, code_loc):

        # get all current definitions
        current_defs = self.memory_definitions.get(atom.addr, None)

        if current_defs:
            for current_def in current_defs:
                self.memory_uses.add_use(current_def, code_loc)

    def _add_tmp_use(self, atom, code_loc):

        current_def = self.tmp_definitions[atom.tmp_idx]

        self.tmp_uses[atom.tmp_idx].add((code_loc, current_def))


def get_engine(base_engine):
    class SimEngineRD(base_engine):
        def __init__(self):
            super(SimEngineRD, self).__init__()

        def _process(self, state, successors, block=None):
            super(SimEngineRD, self)._process(state, successors, block=block)

        #
        # VEX statement handlers
        #

        def _handle_Stmt(self, stmt):

            if self.state.analysis:
                self.state.analysis.observe(self.ins_addr, OP_BEFORE, self.state)

            super(SimEngineRD, self)._handle_Stmt(stmt)

            if self.state.analysis:
                self.state.analysis.observe(self.ins_addr, OP_AFTER, self.state)

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

        def _ail_handle_Stmt(self, stmt):

            if self.state.analysis:
                self.state.analysis.observe(self.ins_addr, OP_BEFORE, self.state)

            super(SimEngineRD, self)._ail_handle_Stmt(stmt)

            if self.state.analysis:
                self.state.analysis.observe(self.ins_addr, OP_AFTER, self.state)

        def _ail_handle_Assignment(self, stmt):
            """

            :param ailment.Assignment stmt:
            :return:
            """

            src = self._expr(stmt.src)
            dst = stmt.dst

            if type(dst) is ailment.Tmp:

                self.state.add_definition(Tmp(dst.tmp_idx), self._codeloc())

                self.tmps[dst.tmp_idx] = src
            elif type(dst) is ailment.Register:

                reg = Register(dst.reg_offset, dst.bits / 8)

                self.state.kill_definitions(reg)
                self.state.add_definition(reg, self._codeloc())

                self.state.registers[dst.reg_offset] = src
            else:
                l.warning('Unsupported type of Assignment dst %s.', type(dst).__name__)

        def _ail_handle_Store(self, stmt):
            data = self._expr(stmt.data)
            addr = self._expr(stmt.addr)

        def _ail_handle_Jump(self, stmt):
            target = self._expr(stmt.target)

        def _ail_handle_ConditionalJump(self, stmt):

            cond = self._expr(stmt.condition)
            true_target = self._expr(stmt.true_target)
            false_target = self._expr(stmt.false_target)

            ip = Register(self.arch.ip_offset, self.arch.bits / 8)
            self.state.kill_definitions(ip)

            # kill all cc_ops
            # TODO: make it architecture agnostic
            self.state.kill_definitions(Register(*self.arch.registers['cc_op']))
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep1']))
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep2']))
            self.state.kill_definitions(Register(*self.arch.registers['cc_ndep']))

        def _ail_handle_Call(self, stmt):
            target = self._expr(stmt.target)

            ip = Register(self.arch.ip_offset, self.arch.bits / 8)

            self.state.kill_definitions(ip)

            # kill all caller-saved registers
            if stmt.calling_convention is not None and stmt.calling_convention.CALLER_SAVED_REGS:
                for reg_name in stmt.calling_convention.CALLER_SAVED_REGS:
                    offset, size = self.arch.registers[reg_name]
                    reg = Register(offset, size)
                    self.state.kill_definitions(reg)

            # kill all cc_ops
            # TODO: make it architecture agnostic
            self.state.kill_definitions(Register(*self.arch.registers['cc_op']))
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep1']))
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep2']))
            self.state.kill_definitions(Register(*self.arch.registers['cc_ndep']))

        #
        # AIL expression handlers
        #

        def _ail_handle_Tmp(self, expr):

            if self.state._track_tmps:
                self.state.add_use(Tmp(expr.tmp_idx), self._codeloc())

            return super(SimEngineRD, self)._ail_handle_Tmp(expr)

        def _ail_handle_Register(self, expr):

            reg_offset = expr.reg_offset
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

        def _ail_handle_Load(self, expr):

            addr = self._expr(expr.addr)

    return SimEngineRD


class ReachingDefinitionAnalysis(ForwardAnalysis, Analysis):
    def __init__(self, func=None, block=None, max_iterations=3, track_tmps=False, observation_points=None):
        """

        :param angr.knowledge.Function func:    The function to run reaching definition analysis on.
        :param block:                           A single block to run reaching definition analysis on. You cannot
                                                specify both `func` and `block`.
        :param int max_iterations:              The maximum number of iterations before the analysis is terminated.
        :param bool track_tmps:                 Whether tmps are tracked or not.
        :param iterable observation_points:     A collection of tuples of (ins_addr, OP_TYPE) defining where reaching
                                                definitions should be copied and stored. OP_TYPE can be OP_BEFORE or
                                                OP_AFTER.
        """

        if func is not None:
            if block is not None:
                raise ValueError('You cannot specify both "func" and "block".')
            # traversing a function
            graph_visitor = FunctionGraphVisitor(func)
        elif block is not None:
            # traversing a block
            graph_visitor = SingleNodeGraphVisitor(block)
        else:
            raise ValueError('Unsupported analysis target.')

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=graph_visitor)

        self._track_tmps = track_tmps
        self._max_iterations = max_iterations
        self._function = func
        self._block = block
        self._observation_points = observation_points

        # sanity check
        if self._observation_points and any(not type(op) is tuple for op in self._observation_points):
            raise ValueError('"observation_points" must be tuples.')

        if not self._observation_points:
            l.warning('No observation point is specified. '
                      'You cannot get any analysis result from performing the analysis.'
                      )

        self._node_iterations = defaultdict(int)
        self._states = { }

        self._engine_vex = get_engine(SimEngineLightVEX)()
        self._engine_ail = get_engine(SimEngineLightAIL)()

        self.observed_results = { }

        self._analyze()

    @property
    def one_result(self):

        if not self.observed_results:
            raise ValueError('No result is available.')
        if len(self.observed_results) != 1:
            raise ValueError("More than one results are available.")

        return next(self.observed_results.itervalues())

    def observe(self, ins_addr, ob_type, state):
        if self._observation_points is not None \
                and (ins_addr, ob_type) in self._observation_points:
            self.observed_results[(ins_addr, ob_type)] = state.copy()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        return ReachingDefinitions(self.project.arch, track_tmps=self._track_tmps, analysis=self)

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

        # clear the tmp store
        state.tmp_uses.clear()
        state.tmp_definitions.clear()

        self._node_iterations[block_key] += 1

        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

register_analysis(ReachingDefinitionAnalysis, "ReachingDefinitions")
