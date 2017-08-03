import logging
from collections import defaultdict

import ailment
import pyvex
from ..engines.vex.irop import operations as vex_operations
from ..calling_conventions import DEFAULT_CC

from ..keyed_region import KeyedRegion
from ..engines.light import SimEngineLightVEX, SimEngineLightAIL, SpOffset, RegisterOffset
from .analysis import Analysis
from .forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor
from . import register_analysis

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

    @property
    def bits(self):
        return self.size * 8

    def __eq__(self, other):
        return type(other) is MemoryLocation and \
                self.addr == other.addr and \
                self.size == other.size

    def __hash__(self):
        return hash(('mem', self.addr, self.size))


class Parameter(Atom):
    __slots__ = ['value']

    def __init__(self, value):
        super(Parameter, self).__init__()

        self.value = value

    def __repr__(self):
        return "<Parameter %s>" % self.value


class Definition(object):
    def __init__(self, atom, codeloc, data=None):
        self.atom = atom
        self.codeloc = codeloc
        self.data = data

    def __eq__(self, other):
        return self.atom == other.atom and self.codeloc == other.codeloc and self.data == other.data

    def __repr__(self):
        return 'Definition 0x%x {Atom: %s, Codeloc: %s, Data: %s}' % (id(self), self.atom, self.codeloc, self.data)

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

        self._current_uses.merge(other._current_uses)


class DataSet(object):
    """
    This class represents a set of data.

    Addition and subtraction are performed on the cartesian product of the operands. Duplicate results are removed.
    data must always include a set.
    """

    def __init__(self, data):
        assert type(data) is set
        self.data = data

    def add(self, data):
        if type(data) == DataSet:
            self.data.update(data.data)
        else:
            self.data.add(data)

    def compact(self):
        if len(self.data) == 0:
            return None
        elif len(self.data) == 1:
            return next(iter(self.data))
        else:
            return self

    def __add__(self, other):
        res = set()
        if type(other) is DataSet:
            for d in self.data:
                for o in other.data:
                    if d is not None and o is not None:
                        res.add(d + o)
                    else:
                        res.add(None)
        else:
            if other is None:
                res.add(None)
            else:
                for d in self.data:
                    if d is not None:
                        res.add(d + other)
                    else:
                        res.add(None)

        return DataSet(res).compact()

    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        res = set()
        if type(other) is DataSet:
            for d in self.data:
                for o in other.data:
                    if d is not None and o is not None:
                        res.add(d - o)
                    else:
                        res.add(None)
        else:
            if other is None:
                res.add(None)
            else:
                for d in self.data:
                    if d is not None:
                        res.add(d - other)
                    else:
                        res.add(None)

        return DataSet(res).compact()

    def __rsub__(self, other):
        tmp = self - other
        if type(tmp) is DataSet:
            res = DataSet({-t for t in tmp.data if t is not None})
            if None in tmp.data:
                res.data.add(None)
        else:
            res = -tmp if tmp is not None else None
        return res

    def __eq__(self, other):
        if type(other) == DataSet:
            return self.data == other.data
        else:
            return False

    def __iter__(self):
        return iter(self.data)

    def __str__(self):
        return 'DataSet: ' + str(self.data)


class ReachingDefinitions(object):
    def __init__(self, arch, track_tmps=False, analysis=None, init_fct=False, cc=None, num_param=None):

        # handy short-hands
        self.arch = arch
        self._track_tmps = track_tmps
        self.analysis = analysis

        self.register_definitions = KeyedRegion()
        self.memory_definitions = KeyedRegion()

        if init_fct:
            stack_addr = 0x7fff0000

            # initialize stack
            sp = Register(arch.sp_offset, arch.bytes)
            sp_def = Definition(sp, None, stack_addr)
            self.register_definitions.set_object(sp_def.offset, sp_def, sp_def.size)

            # apply default CC if None is passed
            if cc is None:
                cc = DEFAULT_CC[arch.name]

            # initialize all registers if no number is passed
            if num_param is None:
                num_param = len(cc.ARG_REGS)

            # initialize register parameters
            for reg in cc.ARG_REGS:
                if num_param > 0:
                    r = Register(arch.registers[reg][0], arch.bytes)
                    r_def = Definition(r, None, Parameter(r))
                    self.register_definitions.set_object(r.reg_offset, r_def, r.size)
                    num_param -= 1
                else:
                    break

            # initialize stack parameters
            for offset in xrange(num_param):
                ml = MemoryLocation(stack_addr + arch.bytes * (offset + 1), arch.bytes)
                ml_def = Definition(ml, None, Parameter(SpOffset(arch.bits, arch.bytes * (offset + 1))))
                self.memory_definitions.set_object(ml.addr, ml_def, ml.size)

        self.register_uses = Uses()
        self.memory_uses = Uses()

        self._dead_virgin_definitions = set()  # definitions that are killed before used

    def __repr__(self):
        ctnt = "ReachingDefinitions, %d regdefs, %d memdefs" % (len(self.register_definitions),
                                                                len(self.memory_definitions))
        if self._track_tmps:
            ctnt += ", %d tmpdefs" % len(self.tmp_definitions)
        return "<%s>" % ctnt

    def copy(self):
        rd = ReachingDefinitions(
            self.arch,
            track_tmps=self._track_tmps,
            analysis=self.analysis,
            init_fct=False,
        )

        rd.register_definitions = self.register_definitions.copy()
        rd.memory_definitions = self.memory_definitions.copy()
        rd.register_uses = self.register_uses.copy()
        rd.memory_uses = self.memory_uses.copy()
        rd._dead_virgin_definitions = self._dead_virgin_definitions.copy()

        return rd

    def merge(self, *others):

        state = self.copy()

        for other in others:
            state.register_definitions.merge(other.register_definitions)
            state.memory_definitions.merge(other.memory_definitions)

            state.register_uses.merge(other.register_uses)
            state.memory_uses.merge(other.memory_uses)

            state._dead_virgin_definitions |= other._dead_virgin_definitions

        return state

    def downsize(self):
        self.analysis = None

    def kill_and_add_definition(self, atom, code_loc, data):
        if type(atom) is Register:
            self._kill_and_add_register_definition(atom, code_loc, data)
        elif type(atom) is MemoryLocation:
            self._kill_and_add_memory_definition(atom, code_loc, data)
        else:
            raise NotImplementedError()

    def add_use(self, atom, code_loc):
        if type(atom) is Register:
            self._add_register_use(atom, code_loc)
        elif type(atom) is MemoryLocation:
            self._add_memory_use(atom, code_loc)
        elif type(atom) is Tmp:
            raise NotImplementedError()

    #
    # Private methods
    #

    def _kill_and_add_register_definition(self, atom, code_loc, data):

        # FIXME: check correctness
        current_defs = self.register_definitions.get_objects_by_offset(atom.reg_offset)
        if current_defs:
            uses = set()
            for current_def in current_defs:
                uses |= self.register_uses.get_current_uses(current_def)
            if not uses:
                self._dead_virgin_definitions |= current_defs

        definition = Definition(atom, code_loc, data)
        # set_object() replaces kill (not implemented) and add (add) in one step
        self.register_definitions.set_object(atom.reg_offset, definition, atom.size)

    def _kill_and_add_memory_definition(self, atom, code_loc, data):
        definition = Definition(atom, code_loc, data)
        # set_object() replaces kill (not implemented) and add (add) in one step
        self.memory_definitions.set_object(atom.addr, definition, atom.size)

    def _add_register_use(self, atom, code_loc):

        # get all current definitions
        current_defs = self.register_definitions.get_objects_by_offset(atom.reg_offset)

        for current_def in current_defs:
            self.register_uses.add_use(current_def, code_loc)

    def _add_memory_use(self, atom, code_loc):

        # get all current definitions
        current_defs = self.memory_definitions.get_objects_by_offset(atom.addr)

        for current_def in current_defs:
            self.memory_uses.add_use(current_def, code_loc)

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

            # FIXME: observe() should only be called once per ins_addr
            if self.state.analysis:
                self.state.analysis.observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

            super(SimEngineRD, self)._handle_Stmt(stmt)

            # FIXME: see above
            if self.state.analysis:
                self.state.analysis.observe(self.ins_addr, stmt, self.block, self.state, OP_AFTER)

        # e.g. PUT(rsp) = t2, t2 might include multiple values
        def _handle_Put(self, stmt):
            reg_offset = stmt.offset
            size = stmt.data.result_size(self.tyenv) / 8
            reg = Register(reg_offset, size)
            data = self._expr(stmt.data)

            if (type(data) is DataSet and None in data) or (data is None):
                l.warning('data in register with offset %d undefined, ins_addr = 0x%x', reg_offset, self.ins_addr)

            self.state.kill_and_add_definition(reg, self._codeloc(), data)

        # e.g. STle(t6) = t21, t6 and/or t21 might include multiple values
        def _handle_Store(self, stmt):

            addr = self._expr(stmt.addr)
            size = stmt.data.result_size(self.tyenv) / 8
            data = self._expr(stmt.data)

            if type(addr) is not DataSet:
                addr = {addr}

            for a in addr:
                if a is not None:
                    if (type(data) is DataSet and None in data) or (data is None):
                        l.warning('memory at address 0x%08x undefined, ins_addr = 0x%x', a, self.ins_addr)

                    memloc = MemoryLocation(a, size)
                    # different addresses are not killed by a subsequent iteration, because kill only removes entries
                    # with same index and same size
                    self.state.kill_and_add_definition(memloc, self._codeloc(), data)
                else:
                    l.warning('memory address undefined, ins_addr = 0x%x', self.ins_addr)

        def _handle_Exit(self, stmt):
            pass

        #
        # VEX expression handlers
        #

        # e.g. t0 = GET:I64(rsp), rsp might be defined multiple times
        def _handle_Get(self, expr):

            reg_offset = expr.offset
            size = expr.result_size(self.tyenv)

            # FIXME: size, overlapping
            data = DataSet(set())
            current_defs = self.state.register_definitions.get_objects_by_offset(reg_offset)
            for current_def in current_defs:
                if current_def.data is not None:
                    # current_def.data can be a primitive type or a DataSet
                    data.add(current_def.data)
                    self.state.add_use
                else:
                    l.warning('data in register with offset %d undefined, ins_addr = 0x%x', reg_offset, self.ins_addr)
            data = data.compact()

            self.state.add_use(Register(reg_offset, size), self._codeloc())

            return data

        # e.g. t27 = LDle:I64(t9), t9 might include multiple values
        def _handle_Load(self, expr):

            addr = self._expr(expr.addr)
            size = expr.result_size(self.tyenv) / 8

            if type(addr) is not DataSet:
                addr = {addr}

            data = DataSet(set())
            for a in addr:
                if a is not None:
                    current_defs = self.state.memory_definitions.get_objects_by_offset(a)
                    for current_def in current_defs:
                        if current_def.data is not None:
                            data.add(current_def.data)
                        else:
                            l.warning('memory at address 0x%x undefined, ins_addr = 0x%x', a, self.ins_addr)
                    # FIXME: _add_memory_use() iterates over the same loop
                    self.state.add_use(MemoryLocation(a, size), self._codeloc())
                else:
                    l.warning('memory address undefined, ins_addr = 0x%x', self.ins_addr)

            data = data.compact()

            return data

        # FIXME: urgent
        def _handle_Unop(self, expr):
            res = None
            simop = vex_operations[expr.op]
            if simop._conversion:
                operand = self._expr(expr.args[0])

                if type(operand) is not DataSet:
                    operand = {operand}

                res = DataSet(set())
                for o in operand:
                    if o is None:
                        pass
                    elif isinstance(o, (int, long)):
                        size = simop._to_size
                        mask = 2 ** size - 1
                        o &= mask
                    else:
                        l.warning('Unsupported conversion type %s' % type(o).__name__)
                    res.add(o)

                res = res.compact()
            else:
                l.warning('Unsupported unary operation %s' % type(simop).__name__)

            return res

        #
        # AIL statement handlers
        #

        def _ail_handle_Stmt(self, stmt):

            if self.state.analysis:
                self.state.analysis.observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

            super(SimEngineRD, self)._ail_handle_Stmt(stmt)

            if self.state.analysis:
                self.state.analysis.observe(self.ins_addr, stmt, self.block, self.state, OP_AFTER)

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

            # if arguments exist, use them
            if stmt.args:
                for arg in stmt.args:
                    self._expr(arg)

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
            size = expr.size

            # TODO: Load from memory
            return MemoryLocation(addr, size)

        def _ail_handle_Convert(self, expr):
            return ailment.Expr.Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, self._expr(expr.operand))

        def _ail_handle_CmpEQ(self, expr):
            op0 = self._expr(expr.operands[0])
            op1 = self._expr(expr.operands[1])

            return ailment.Expr.BinaryOp(expr.idx, expr.op, [ op0, op1 ], **expr.tags)

        def _ail_handle_CmpLE(self, expr):
            op0 = self._expr(expr.operands[0])
            op1 = self._expr(expr.operands[1])

            return ailment.Expr.BinaryOp(expr.idx, expr.op, [ op0, op1 ], **expr.tags)

        def _ail_handle_Xor(self, expr):
            op0 = self._expr(expr.operands[0])
            op1 = self._expr(expr.operands[1])

            return ailment.Expr.BinaryOp(expr.idx, expr.op, [ op0, op1 ], **expr.tags)

        def _ail_handle_Const(self, expr):
            return expr

    return SimEngineRD


class ReachingDefinitionAnalysis(ForwardAnalysis, Analysis):
    def __init__(self, func=None, block=None, max_iterations=3, track_tmps=False, observation_points=None,
                 init_fct=False, cc=None, num_param=None):
        """

        :param angr.knowledge.Function func:    The function to run reaching definition analysis on.
        :param block:                           A single block to run reaching definition analysis on. You cannot
                                                specify both `func` and `block`.
        :param int max_iterations:              The maximum number of iterations before the analysis is terminated.
        :param bool track_tmps:                 Whether tmps are tracked or not.
        :param iterable observation_points:     A collection of tuples of (ins_addr, OP_TYPE) defining where reaching
                                                definitions should be copied and stored. OP_TYPE can be OP_BEFORE or
                                                OP_AFTER.
        :param bool init_fct:                   Whether stack and arguments are initialized or not
        :param SimCC cc:                        Calling convention of the function (DefaultCC of arch if not set)
        :param int num_param:                   Number of arguments that are passed to the function
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

        self._init_fct = init_fct
        self._cc = cc
        self._num_param = num_param

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

    def observe(self, ins_addr, stmt, block, state, ob_type):
        if self._observation_points is not None:
            if (ins_addr, ob_type) in self._observation_points:
                if ob_type == OP_BEFORE and type(stmt) is pyvex.IRStmt.IMark:
                    self.observed_results[(ins_addr, ob_type)] = state.copy()
                elif ob_type == OP_AFTER:
                    idx = block.vex.statements.index(stmt)
                    if idx == len(block.vex.statements) - 1 or type(
                            block.vex.statements[idx + 1]) is pyvex.IRStmt.IMark:
                        self.observed_results[(ins_addr, ob_type)] = state.copy()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        return ReachingDefinitions(self.project.arch, track_tmps=self._track_tmps, analysis=self,
                                   init_fct=self._init_fct, cc=self._cc, num_param=self._num_param)

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
        # state.tmp_uses.clear()
        # state.tmp_definitions.clear()

        self._node_iterations[block_key] += 1

        if self._node_iterations[block_key] < self._max_iterations:
            return True, state
        else:
            return False, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

register_analysis(ReachingDefinitionAnalysis, "ReachingDefinitions")
