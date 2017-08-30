import logging
import operator
import struct
from collections import defaultdict

import ailment
import pyvex

from . import register_analysis
from .analysis import Analysis
from .forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor
from ..calling_conventions import SimRegArg, SimStackArg
from ..engines.light import SimEngineLightVEX, SimEngineLightAIL, SpOffset, RegisterOffset
from ..engines.vex.irop import operations as vex_operations
from ..keyed_region import KeyedRegion

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
    __slots__ = ['tmp_idx']

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
    __slots__ = ['reg_offset', 'size']

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
    __slots__ = ['addr', 'size']

    def __init__(self, addr, size):
        super(MemoryLocation, self).__init__()

        self.addr = addr
        self.size = size

    def __repr__(self):
        return "<Mem 0x%x<%d>>" % (self.addr, self.size)

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
        if definition not in self._uses_by_definition:
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

    def __init__(self, data, bits):
        assert type(data) is set
        self.data = data
        self._bits = bits
        self._mask = (1 << bits) - 1

    @property
    def bits(self):
        return self._bits

    @property
    def mask(self):
        return self._mask

    def update(self, data):
        if type(data) is DataSet:
            if self.bits != data.bits:
                ValueError('Cannot operate on DataSets with different size.')
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

    def _un_op(self, op):
        res = set()

        for s in self:
            if s is None:
                res.add(None)
            else:
                try:
                    tmp = op(s)
                    if isinstance(tmp, (int, long)):
                        tmp &= self._mask
                    res.add(tmp)
                except TypeError as e:
                    l.warning(e)
                    res.add(None)

        return DataSet(res, self._bits).compact()

    def _bin_op(self, other, op):
        res = set()

        if type(other) is not DataSet:
            other = {other}
        else:
            if self._bits != other.bits:
                ValueError('Cannot operate on DataSets with different size.')

        for o in other:
            for s in self:
                if o is None or s is None:
                    res.add(None)
                else:
                    try:
                        tmp = op(s, o)
                        if isinstance(tmp, (int, long)):
                            tmp &= self._mask
                        res.add(tmp)
                    except TypeError as e:
                        l.warning(e)
                        res.add(None)

        return DataSet(res, self._bits).compact()

    def __add__(self, other):
        return self._bin_op(other, operator.add)

    def __radd__(self, other):
        return self._bin_op(other, operator.add)

    def __sub__(self, other):
        return self._bin_op(other, operator.sub)

    def __rsub__(self, other):
        tmp = self._bin_op(other, operator.sub)

        if tmp is None:
            return None
        else:
            try:
                return -tmp
            except TypeError as e:
                l.warning(e)
                return None

    def __and__(self, other):
        return self._bin_op(other, operator.and_)

    def __rand__(self, other):
        return self._bin_op(other, operator.and_)

    def __or__(self, other):
        return self._bin_op(other, operator.or_)

    def __ror__(self, other):
        return self._bin_op(other, operator.or_)

    def __neg__(self):
        return self._un_op(operator.neg)

    def __eq__(self, other):
        if type(other) == DataSet:
            return self.data == other.data and self._bits == other.bits and self._mask == other.mask
        else:
            return False

    def __iter__(self):
        return iter(self.data)

    def __str__(self):
        return 'DataSet<%d>: %s' % (self._bits, str(self.data))


class ReachingDefinitions(object):
    def __init__(self, arch, loader, track_tmps=False, analysis=None, init_func=False, cc=None, func_addr=None):

        # handy short-hands
        self.arch = arch
        self.loader = loader
        self._track_tmps = track_tmps
        self.analysis = analysis

        self.register_definitions = KeyedRegion()
        self.memory_definitions = KeyedRegion()

        if init_func:
            self._init_func(cc, func_addr)

        self.register_uses = Uses()
        self.memory_uses = Uses()

        self._dead_virgin_definitions = set()  # definitions that are killed before used

    def __repr__(self):
        ctnt = "ReachingDefinitions, %d regdefs, %d memdefs" % (len(self.register_definitions),
                                                                len(self.memory_definitions))
        if self._track_tmps:
            ctnt += ", %d tmpdefs" % len(self.tmp_definitions)
        return "<%s>" % ctnt

    def _init_func(self, cc, func_addr):
        # initialize stack pointer
        sp = Register(self.arch.sp_offset, self.arch.bytes)
        sp_def = Definition(sp, None, self.arch.initial_sp)
        self.register_definitions.set_object(sp_def.offset, sp_def, sp_def.size)

        if cc is not None:
            for arg in cc.args:
                # initialize register parameters
                if type(arg) is SimRegArg:
                    # FIXME: implement reg_offset handling in SimRegArg
                    reg_offset = self.arch.registers[arg.reg_name][0]
                    reg = Register(reg_offset, self.arch.bytes)
                    reg_def = Definition(reg, None, Parameter(reg))
                    self.register_definitions.set_object(reg.reg_offset, reg_def, reg.size)
                # initialize stack parameters
                elif type(arg) is SimStackArg:
                    ml = MemoryLocation(self.arch.initial_sp + arg.stack_offset, self.arch.bytes)
                    sp_offset = SpOffset(arg.size * 8, arg.stack_offset)
                    ml_def = Definition(ml, None, Parameter(sp_offset))
                    self.memory_definitions.set_object(ml.addr, ml_def, ml.size)
                else:
                    raise TypeError('Unsupported parameter type %s.' % type(arg).__name__)

        # architecture depended initialization
        if self.arch.name.lower().find('ppc64') > -1:
            rtoc_value = self.loader.main_object.ppc64_initial_rtoc
            if rtoc_value:
                offset, size = self.arch.registers['rtoc']
                rtoc = Register(offset, size)
                rtoc_def = Definition(rtoc, None, rtoc_value)
                self.register_definitions.set_object(rtoc.reg_offset, rtoc_def, rtoc.size)
        elif self.arch.name.lower().find('mips64') > -1:
            offset, size = self.arch.registers['t9']
            t9 = Register(offset, size)
            t9_def = Definition(t9, None, func_addr)
            self.register_definitions.set_object(t9.reg_offset, t9_def, t9.size)

    def copy(self):
        rd = ReachingDefinitions(
            self.arch,
            self.loader,
            track_tmps=self._track_tmps,
            analysis=self.analysis,
            init_func=False,
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
        def __init__(self, function_handler=None):
            super(SimEngineRD, self).__init__()
            self._function_handler = function_handler

        def process(self, state, *args, **kwargs):
            # we are using a completely different state. Therefore, we directly call our _process() method before
            # SimEngine becomes flexible enough.
            self._process(state, None, block=kwargs.pop('block', None))
            return self.state

        #
        # VEX statement handlers
        #

        def _handle_Stmt(self, stmt):

            if self.state.analysis:
                self.state.analysis.observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

            super(SimEngineRD, self)._handle_Stmt(stmt)

            if self.state.analysis:
                self.state.analysis.observe(self.ins_addr, stmt, self.block, self.state, OP_AFTER)

        # e.g. PUT(rsp) = t2, t2 might include multiple values
        def _handle_Put(self, stmt):
            reg_offset = stmt.offset
            size = stmt.data.result_size(self.tyenv) / 8
            reg = Register(reg_offset, size)
            data = self._expr(stmt.data)

            if (type(data) is DataSet and None in data) or (data is None):
                l.info('Data to write into register <%s> with offset %d undefined, ins_addr = 0x%x.',
                       self.arch.register_names[reg_offset], reg_offset, self.ins_addr)

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
                        l.info('Data to write at address 0x%x undefined, ins_addr = 0x%x.', a, self.ins_addr)

                    memloc = MemoryLocation(a, size)
                    # different addresses are not killed by a subsequent iteration, because kill only removes entries
                    # with same index and same size
                    self.state.kill_and_add_definition(memloc, self._codeloc(), data)
                else:
                    l.info('Memory address undefined, ins_addr = 0x%x.', self.ins_addr)

        def _handle_StoreG(self, stmt):
            guard = self._expr(stmt.guard)
            if guard is True:
                self._handle_Store(stmt)
            elif guard is False:
                pass
            else:
                l.info('Could not resolve guard %s for StoreG.', str(guard))

        # CAUTION: experimental
        def _handle_LoadG(self, stmt):
            guard = self._expr(stmt.guard)
            if guard is True:
                # FIXME: full conversion support
                if stmt.cvt.find('Ident') < 0:
                    l.warning('Unsupported conversion %s in LoadG.', stmt.cvt)
                load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)
                wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, load_expr)
                self._handle_WrTmp(wr_tmp_stmt)
            elif guard is False:
                wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, stmt.alt)
                self._handle_WrTmp(wr_tmp_stmt)
            else:
                if stmt.cvt.find('Ident') < 0:
                    l.warning('Unsupported conversion %s in LoadG.', stmt.cvt)
                load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)
                data = DataSet(set(), load_expr.result_size(self.tyenv))
                data.update(self._expr(load_expr))
                data.update(self._expr(stmt.alt))
                data = data.compact()
                self._handle_WrTmpData(stmt.dst, data)

        def _handle_Exit(self, stmt):
            pass

        def _handle_IMark(self, stmt):
            pass

        def _handle_AbiHint(self, stmt):
            pass

        #
        # VEX expression handlers
        #

        # e.g. t0 = GET:I64(rsp), rsp might be defined multiple times
        def _handle_Get(self, expr):

            reg_offset = expr.offset
            size = expr.result_size(self.tyenv)

            # FIXME: size, overlapping
            data = DataSet(set(), expr.result_size(self.tyenv))
            current_defs = self.state.register_definitions.get_objects_by_offset(reg_offset)
            for current_def in current_defs:
                if current_def.data is not None:
                    # current_def.data can be a primitive type or a DataSet
                    data.update(current_def.data)
                else:
                    l.info('Data in register <%s> with offset %d undefined, ins_addr = 0x%x.',
                           self.arch.register_names[reg_offset], reg_offset, self.ins_addr)
            data = data.compact()

            self.state.add_use(Register(reg_offset, size), self._codeloc())

            return data

        # e.g. t27 = LDle:I64(t9), t9 might include multiple values
        def _handle_Load(self, expr):
            addr = self._expr(expr.addr)
            size = expr.result_size(self.tyenv) / 8

            if type(addr) is not DataSet:
                addr = {addr}

            data = DataSet(set(), expr.result_size(self.tyenv))
            for a in addr:
                if a is not None:
                    current_defs = self.state.memory_definitions.get_objects_by_offset(a)
                    if current_defs:
                        for current_def in current_defs:
                            if current_def.data is not None:
                                data.update(current_def.data)
                            else:
                                l.info('Memory at address 0x%x undefined, ins_addr = 0x%x.', a, self.ins_addr)
                    else:
                        mem = self.state.loader.memory.read_bytes(a, size)
                        if mem:
                            if self.arch.memory_endness == 'Iend_LE':
                                fmt = "<"
                            else:
                                fmt = ">"

                            if size == 8:
                                fmt += "Q"
                            elif size == 4:
                                fmt += "I"

                            if size in [4, 8] and size == len(mem):
                                mem_str = ''.join(mem)
                                data.update(struct.unpack(fmt, mem_str)[0])

                    # FIXME: _add_memory_use() iterates over the same loop
                    self.state.add_use(MemoryLocation(a, size), self._codeloc())
                else:
                    l.info('Memory address undefined, ins_addr = 0x%x.', self.ins_addr)

            data = data.compact()

            return data

        # CAUTION: experimental
        def _handle_ITE(self, expr):
            cond = self._expr(expr.cond)

            if cond is True:
                return self._expr(expr.iftrue)
            elif cond is False:
                return self._expr(expr.iffalse)
            else:
                l.info('Could not resolve condition %s for ITE.', str(cond))
                res = DataSet(set(), expr.result_size(self.tyenv))
                res.update(self._expr(expr.iftrue))
                res.update(self._expr(expr.iffalse))
                return res.compact()

        def _handle_Conversion(self, expr):
            simop = vex_operations[expr.op]
            arg_0 = self._expr(expr.args[0])

            if type(arg_0) is not DataSet:
                arg_0 = {arg_0}

            bits = int(simop.op_attrs['to_size'])
            res = DataSet(set(), bits)
            # convert operand if possible otherwise keep it unchanged
            for a in arg_0:
                if a is None:
                    pass
                elif isinstance(a, (int, long)):
                    mask = 2 ** bits - 1
                    a &= mask
                elif type(a) is Parameter:
                    if type(a.value) is Register:
                        a.value.size = bits / 8
                    elif type(a.value) is SpOffset:
                        a.value.bits = bits
                    else:
                        l.warning('Unsupported type Parameter->%s for conversion.', type(a.value).__name__)
                else:
                    l.warning('Unsupported type %s for conversion.', type(a).__name__)
                res.update(a)

            res = res.compact()

            return res

        def _handle_Sar(self, expr):
            arg0, arg1 = expr.args
            expr_0 = self._expr(arg0)
            if expr_0 is None:
                return None
            expr_1 = self._expr(arg1)
            if expr_1 is None:
                return None

            if type(expr_0) is not DataSet:
                expr_0 = {expr_0}

            size = expr.result_size(self.tyenv)
            res = DataSet(set(), size)
            for e0 in expr_0:
                for e1 in expr_0:
                    try:
                        if e0 >> (size - 1) == 0:
                            head = 0
                        else:
                            head = ((1 << e1) - 1) << (size - e1)
                        res.update(head | (e0 >> e1))
                    except TypeError as e:
                        l.warning(e)
                        res.update(None)
            res = res.compact()

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
            return ailment.Expr.Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed,
                                        self._expr(expr.operand))

        def _ail_handle_CmpEQ(self, expr):
            op0 = self._expr(expr.operands[0])
            op1 = self._expr(expr.operands[1])

            return ailment.Expr.BinaryOp(expr.idx, expr.op, [op0, op1], **expr.tags)

        def _ail_handle_CmpLE(self, expr):
            op0 = self._expr(expr.operands[0])
            op1 = self._expr(expr.operands[1])

            return ailment.Expr.BinaryOp(expr.idx, expr.op, [op0, op1], **expr.tags)

        def _ail_handle_Xor(self, expr):
            op0 = self._expr(expr.operands[0])
            op1 = self._expr(expr.operands[1])

            return ailment.Expr.BinaryOp(expr.idx, expr.op, [op0, op1], **expr.tags)

        def _ail_handle_Const(self, expr):
            return expr

        #
        # User defined high level statement handlers
        #

        def _handle_function(self):
            ip = self.arch.ip_offset
            ip_defs = self.state.register_definitions.get_objects_by_offset(ip)
            if len(ip_defs) != 1:
                raise ValueError('Invalid definitions for IP')
            ip_addr = next(iter(ip_defs)).data
            if not isinstance(ip_addr, (int, long)):
                raise ValueError('Invalid type %s for IP' % type(ip_addr).__name__)

            is_intern = False
            ext_func_name = None
            if self.state.loader.main_object.contains_addr(ip_addr) is True:
                ext_func_name = self.state.loader.find_plt_stub_name(ip_addr)
                if ext_func_name is None:
                    is_intern = True
            else:
                symbol = self.state.loader.find_symbol(ip_addr)
                if symbol is not None:
                    ext_func_name = symbol.name

            if ext_func_name is not None:
                handler_name = 'handle_%s' % ext_func_name
                if hasattr(self._function_handler, handler_name):
                    getattr(self._function_handler, handler_name)(self.state, self._codeloc())
                else:
                    l.warning('Please implement the external function handler for %s() with your own logic.',
                              ext_func_name)
            elif is_intern is True:
                handler_name = 'handle_local_function'
                if hasattr(self._function_handler, handler_name):
                    is_updated, state = getattr(self._function_handler, handler_name)(self.state, ip_addr)
                    if is_updated is True:
                        self.state = state
                else:
                    l.warning('Please implement the local function handler with your own logic.')
            else:
                l.warning('Could not find function name for external function at address 0x%x.', ip_addr)

    return SimEngineRD


class ReachingDefinitionAnalysis(ForwardAnalysis, Analysis):
    def __init__(self, func=None, block=None, max_iterations=3, track_tmps=False, observation_points=None,
                 init_state=None, init_func=False, cc=None, function_handler=None):
        """

        :param angr.knowledge.Function func:    The function to run reaching definition analysis on.
        :param block:                           A single block to run reaching definition analysis on. You cannot
                                                specify both `func` and `block`.
        :param int max_iterations:              The maximum number of iterations before the analysis is terminated.
        :param bool track_tmps:                 Whether tmps are tracked or not.
        :param iterable observation_points:     A collection of tuples of (ins_addr, OP_TYPE) defining where reaching
                                                definitions should be copied and stored. OP_TYPE can be OP_BEFORE or
                                                OP_AFTER.
        :param ReachingDefinitions init_state:  An optional initialization state. The analysis creates and works on a
                                                copy.
        :param bool init_func:                  Whether stack and arguments are initialized or not.
        :param SimCC cc:                        Calling convention of the function.
        :param list function_handler:           Handler for functions, naming scheme: handle_<func_name>|local_function(
                                                <ReachingDefinitions>, <Codeloc>, <IP address>).
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
        self._init_state = init_state
        self._function_handler = function_handler

        if self._init_state is not None:
            self._init_state = self._init_state.copy()
            self._init_state.analysis = self

        # ignore initialization parameters if a block was passed
        if self._function is not None:
            self._init_func = init_func
            self._cc = cc
            self._func_addr = func.addr
        else:
            self._init_func = False
            self._cc = None
            self._func_addr = None

        # sanity check
        if self._observation_points and any(not type(op) is tuple for op in self._observation_points):
            raise ValueError('"observation_points" must be tuples.')

        if not self._observation_points:
            l.warning('No observation point is specified. '
                      'You cannot get any analysis result from performing the analysis.'
                      )

        self._node_iterations = defaultdict(int)
        self._states = {}

        self._engine_vex = get_engine(SimEngineLightVEX)(function_handler)
        self._engine_ail = get_engine(SimEngineLightAIL)(function_handler)

        self.observed_results = {}

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
                # OP_BEFORE: stmt has to be IMark
                if ob_type == OP_BEFORE and type(stmt) is pyvex.IRStmt.IMark:
                    self.observed_results[(ins_addr, ob_type)] = state.copy()
                # OP_AFTER: stmt has to be last stmt of block or next stmt has to be IMark
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
        if self._init_state is not None:
            return self._init_state
        else:
            return ReachingDefinitions(self.project.arch, self.project.loader, track_tmps=self._track_tmps,
                                       analysis=self, init_func=self._init_func, cc=self._cc, func_addr=self._func_addr)

    def _merge_states(self, node, *states):
        return states[0].merge(*states[1:])

    def _run_on_node(self, node, state):

        if isinstance(node, ailment.Block):
            block = node
            block_key = node.addr
            engine = self._engine_ail
        else:
            block = self.project.factory.block(node.addr, node.size, opt_level=0)
            block_key = node.addr
            engine = self._engine_vex

        state = state.copy()
        state = engine.process(state, block=block)

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
