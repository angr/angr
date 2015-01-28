#!/usr/bin/env python

import functools
import itertools
#import weakref

import struct

import logging
l = logging.getLogger("simuvex.s_state")

import ana

def arch_overrideable(f):
    @functools.wraps(f)
    def wrapped_f(self, *args, **kwargs):
        if hasattr(self.arch, f.__name__):
            arch_f = getattr(self.arch, f.__name__)
            return arch_f(self, *args, **kwargs)
        else:
            return f(self, *args, **kwargs)
    return wrapped_f

from .plugins import default_plugins

# This is a counter for the state-merging symbolic variables
merge_counter = itertools.count()

class SimState(ana.Storable): # pylint: disable=R0904
    '''The SimState represents the state of a program, including its memory, registers, and so forth.'''

    def __init__(self, temps=None, arch="AMD64", plugins=None, memory_backer=None, mode=None, options=None, add_options=None, remove_options=None):
        # the architecture is used for function simulations (autorets) and the bitness
        self.arch = Architectures[arch]() if isinstance(arch, str) else arch
        self.abiv = None

        # VEX temps are temporary variables local to an IRSB
        self.temps = temps if temps is not None else { }

        # the options
        if options is None:
            if mode is None:
                l.warning("SimState defaulting to symbolic mode.")
                mode = "symbolic"
            options = o.default_options[mode]

        options = set(options)
        if add_options is not None:
            options |= add_options
        if remove_options is not None:
            options -= remove_options
        self.options = options
        self.mode = mode

        # plugins
        self.plugins = { }
        if plugins is not None:
            for n,p in plugins.iteritems():
                self.register_plugin(n, p)

        if not self.has_plugin('memory'):
            if o.ABSTRACT_MEMORY in self.options:
                # We use SimAbstractMemory in static mode
                self['memory'] = SimAbstractMemory(memory_backer, memory_id="mem")
            else:
                self['memory'] = SimSymbolicMemory(memory_backer, memory_id="mem")
        if not self.has_plugin('registers'):
            self['registers'] = SimSymbolicMemory(memory_id="reg")

        # the native environment for native execution
        self.native_env = None

        # This is used in static mode as we don't have any constraints there
        self._satisfiable = True

        # states are big, so let's give them UUIDs for ANA right away to avoid
        # extra pickling
        self.make_uuid()

        # addresses and stuff of what we're currently processing
        self.bbl_addr = None
        self.stmt_idx = None
        self.sim_procedure = None

    def _ana_getstate(self):
        return ana.Storable._ana_getstate(self)

    def _ana_setstate(self, s):
        ana.Storable._ana_setstate(self, s)
        for p in self.plugins.values():
            p.set_state(self)

    # easier access to some properties

    @property
    def ip(self):
        '''
        Get the instruction pointer expression.
        :return: an expression
        '''
        return self.reg_expr('ip')

    @ip.setter
    def ip(self, val):
        self.store_reg('ip', val)

    # accessors for memory and registers and such
    @property
    def memory(self):
        return self.get_plugin('memory')

    @property
    def registers(self):
        return self.get_plugin('registers')

    @property
    def se(self):
        return self.get_plugin('solver_engine')

    @property
    def inspect(self):
        return self.get_plugin('inspector')

    @property
    def log(self):
        return self.get_plugin('log')

    @property
    def posix(self):
        return self.get_plugin('posix')

    @property
    def libc(self):
        return self.get_plugin('libc')

    @property
    def cgc(self):
        return self.get_plugin('cgc')


    def _inspect(self, *args, **kwargs):
        if self.has_plugin('inspector'):
            self.inspect.action(*args, **kwargs)

    #
    # Plugins
    #

    def has_plugin(self, name):
        return name in self.plugins

    def get_plugin(self, name):
        if name not in self.plugins:
            p = default_plugins[name]()
            self.register_plugin(name, p)
            return p
        return self.plugins[name]

    # ok, ok
    def __getitem__(self, name): return self.get_plugin(name)
    def __setitem__(self, name, plugin): return self.register_plugin(name, plugin)

    def register_plugin(self, name, plugin):
        #l.debug("Adding plugin %s of type %s", name, plugin.__class__.__name__)
        plugin.set_state(self)
        self.plugins[name] = plugin

    def release_plugin(self, name):
        if name in self.plugins:
            del self.plugins[name]

    #
    # Constraint pass-throughs
    #

    def simplify(self, *args): return self.se.simplify(*args)

    def add_constraints(self, *args):
        if len(args) > 0 and type(args[0]) in (list, tuple):
            raise Exception("Tuple or list passed to add_constraints!")

        if o.TRACK_CONSTRAINTS in self.options and len(args) > 0:
            if o.SIMPLIFY_CONSTRAINTS in self.options:
                constraints = [ self.simplify(a) for a in args ]
            else:
                constraints = args

            self._inspect('constraints', BP_BEFORE, added_constraints=constraints)
            self.se.add(*constraints)
            self._inspect('constraints', BP_AFTER)

        if o.ABSTRACT_SOLVER in self.options and len(args) > 0:
            for arg in args:
                if self.se.is_false(arg):
                    self._satisfiable = False
                    return
                if self.se.is_true(arg):
                    continue
                else:
                    # This is the IfProxy. Grab the constraints, and apply it to
                    # corresponding SI objects
                    if isinstance(arg.model, claripy.vsa.IfProxy):
                        side = True
                        if not self.se.is_true(arg.model.trueexpr):
                            side = False
                        original_expr, constrained_si = self.se.constraint_to_si(arg, side)
                        if original_expr is not None and constrained_si is not None:
                            # FIXME: We are using an expression to intersect a StridedInterval... Is it good?
                            new_expr = original_expr.intersection(constrained_si)
                            self.registers.replace_all(original_expr, new_expr)
                            for _, region in self.memory.regions.items():
                                region.memory.replace_all(original_expr, new_expr)

                            l.debug("SimState.add_constraints: Applied to final state.")
                    else:
                        l.warning('Unsupported constraint %s', arg)
        elif o.SYMBOLIC not in self.options and len(args) > 0:
            for arg in args:
                if self.se.is_false(arg):
                    self._satisfiable = False
                    return

    def BV(self, name, size, explicit_name=None):
        size = self.arch.bits if size is None else size

        self._inspect('symbolic_variable', BP_BEFORE, symbolic_name=name, symbolic_size=size)
        v = self.se.BitVec(name, size, explicit_name=explicit_name)
        self._inspect('symbolic_variable', BP_AFTER, symbolic_expr=v)
        return v

    def BVV(self, value, size=None):
        if type(value) is str:
            v = 0
            for c in value:
                v = v << 8
                v += ord(c)
            size = len(value)*8
            value = v
        size = self.arch.bits if size is None else size
        return self.se.BitVecVal(value, size)

    def StridedInterval(self, name=None, bits=0, stride=None, lower_bound=None, upper_bound=None, to_conv=None):
        return self.se.StridedInterval(name=name,
                                       bits=bits,
                                       stride=stride,
                                       lower_bound=lower_bound,
                                       upper_bound=upper_bound,
                                       to_conv=to_conv)

    def satisfiable(self, **kwargs):
        if o.ABSTRACT_SOLVER in self.options or o.SYMBOLIC not in self.options:
            extra_constraints = kwargs.pop('extra_constraints', ())
            for e in extra_constraints:
                if self.se.is_false(e):
                    return False

            return self._satisfiable
        else:
            return self.se.satisfiable(**kwargs)

    def downsize(self):
        if 'solver_engine' in self.plugins:
            self.se.downsize()

    #
    # Memory helpers
    #

    # Helper function for loading from symbolic memory and tracking constraints
    def _do_load(self, simmem, addr, length, condition=None, fallback=None):
        # do the load and track the constraints
        m,e = simmem.load(addr, length, condition=condition, fallback=fallback)
        self.add_constraints(*e)
        return m

    # Helper function for storing to symbolic memory and tracking constraints
    def _do_store(self, simmem, addr, content, size=None, condition=None, fallback=None):
        # do the store and track the constraints
        e = simmem.store(addr, content, size=size, condition=condition, fallback=fallback)
        self.add_constraints(*e)
        return e

    #
    # State branching operations
    #

    # Returns a dict that is a copy of all the state's plugins
    def copy_plugins(self):
        return { n: p.copy() for n,p in self.plugins.iteritems() }

    def copy(self):
        '''
        Returns a copy of the state.
        '''

        c_temps = dict(self.temps)
        c_arch = self.arch
        c_plugins = self.copy_plugins()
        state = SimState(temps=c_temps, arch=c_arch, plugins=c_plugins, options=self.options, mode=self.mode)
        state.abiv = self.abiv
        state.bbl_addr = self.bbl_addr
        state.sim_procedure = self.sim_procedure
        state.stmt_idx = self.stmt_idx
        return state

    def merge(self, *others):
        '''
        Merges this state with the other states. Returns the merging result, merged state, and the merge flag.
        :param others: the other states to merge
        :return: (merged state, merge flag, a bool indicating if any merging occured)
        '''
        # TODO: maybe make the length of this smaller? Maybe: math.ceil(math.log(len(others)+1, 2))
        merge_flag = self.se.BitVec("state_merge_%d" % merge_counter.next(), 16)
        merge_values = range(len(others)+1)

        if len(set(frozenset(o.plugins.keys()) for o in others)) != 1:
            raise SimMergeError("Unable to merge due to different sets of plugins.")
        if len(set(o.arch.name for o in others)) != 1:
            raise SimMergeError("Unable to merge due to different architectures.")

        merged = self.copy()
        merging_occured = False

        # plugins
        m_constraints = [ ]
        for p in self.plugins:
            plugin_state_merged, new_constraints = merged.plugins[p].merge([ _.plugins[p] for _ in others ], merge_flag, merge_values)
            if plugin_state_merged:
                l.debug('Merging occured in %s', p)
                if o.ABSTRACT_MEMORY not in self.options or p != 'registers':
                    merging_occured = True
            m_constraints += new_constraints
        merged.add_constraints(*m_constraints)

        return merged, merge_flag, merging_occured

    #############################################
    ### Accessors for tmps, registers, memory ###
    #############################################

    def tmp_expr(self, tmp, simplify=False):
        '''
        Returns the Claripy expression of a VEX temp value.

        @param tmp: the number of the tmp
        @param simplify: simplify the tmp before returning it
        @returns a Claripy expression of the tmp
        '''
        self._inspect('tmp_read', BP_BEFORE, tmp_read_num=tmp)
        v = self.temps[tmp]
        self._inspect('tmp_read', BP_AFTER, tmp_read_expr=v)
        return v if simplify is False else self.se.simplify(v)

    def store_tmp(self, tmp, content):
        '''
        Stores a Claripy expression in a VEX temp value.

        @param tmp: the number of the tmp
        @param content: a Claripy expression of the content
        '''
        self._inspect('tmp_write', BP_BEFORE, tmp_write_num=tmp, tmp_write_expr=content)

        if tmp not in self.temps:
            # Non-symbolic
            self.temps[tmp] = content
        else:
            # Symbolic
            self.add_constraints(self.temps[tmp] == content)

        self._inspect('tmp_write', BP_AFTER)

    def reg_expr(self, offset, length=None, endness=None, condition=None, fallback=None, simplify=False):
        '''
        Returns the Claripy expression of the content of a register.

        @param offset: the offset or name of the register
        @param length: the length to read. If ommitted, uses the architecture word size
        @param endness: the endianness (little or big) to read with. If ommitted,
                        uses the architecture default.
        @param condition: a condition, for a conditional read
        @param fallback: a fallback Claripy expression, if the Condition ends up being False
        @param simplify: simplify the tmp before returning it
        @returns a Claripy expression representing the read
        '''
        if length is None: length = self.arch.bits / 8
        self._inspect('reg_read', BP_BEFORE, reg_read_offset=offset, reg_read_length=length)

        if type(offset) is str:
            offset,length = self.arch.registers[offset]

        e = self._do_load(self.registers, offset, length, condition=condition, fallback=fallback)

        if endness is None: endness = self.arch.register_endness
        if endness == "Iend_LE": e = e.reversed

        self._inspect('reg_read', BP_AFTER, reg_read_expr=e)
        if simplify or o.SIMPLIFY_REGISTER_READS in self.options:
            e = self.se.simplify(e)
        return e

    def reg_concrete(self, *args, **kwargs):
        '''
        Returns the contents of a register but, if that register is symbolic,
        raises a SimValueError.
        '''
        e = self.reg_expr(*args, **kwargs)
        if self.se.symbolic(e):
            raise SimValueError("target of reg_concrete is symbolic!")
        return self.se.any_int(e)

    def store_reg(self, offset, content, length=None, endness=None, condition=None, fallback=None):
        '''
        Stores content to a register.

        @param offset: the offset or name of the register
        @param content: a Claripy expression to store
        @param length: an optional Claripy expression, representing how much of the content to
                       store. If ommitted, stores the whole thing.
        @param endness: store with the provided endness. If ommitted, uses the architecture default.
        @param condition: a condition, for a conditional store
        @param fallback: the value to store if the condition ends up False.
        '''
        if type(offset) is str:
            offset,length = self.arch.registers[offset]

        if type(content) in (int, long):
            if not length:
                l.warning("Length not provided to store_reg with integer content. Assuming bit-width of CPU.")
                length = self.arch.bits / 8
            content = self.se.BitVecVal(content, length * 8)

        if endness is None: endness = self.arch.register_endness
        if endness == "Iend_LE": content = content.reversed

        if o.SIMPLIFY_REGISTER_WRITES in self.options:
            l.debug("simplifying register write...")
            content = self.simplify(content)

        self._inspect('reg_write', BP_BEFORE, reg_write_offset=offset, reg_write_expr=content, reg_write_length=content.size()/8) # pylint: disable=maybe-no-member
        e = self._do_store(self.registers, offset, content, condition=condition, fallback=fallback)
        self._inspect('reg_write', BP_AFTER)

        return e

    def mem_expr(self, addr, length, endness=None, condition=None, fallback=None, simplify=False):
        '''
        Returns the Claripy expression of the content of memory.

        @param addr: a Claripy expression representing the address
        @param length: a Claripy expression representing the length of the read
        @param endness: the endianness (little or big) to read with. If ommitted,
                        does a big endian read.
        @param condition: a condition, for a conditional read
        @param fallback: a fallback Claripy expression, if the Condition ends up being False
        @param simplify: simplify the tmp before returning it
        @returns a Claripy expression representing the read
        '''
        if endness is None: endness = "Iend_BE"

        self._inspect('mem_read', BP_BEFORE, mem_read_address=addr, mem_read_length=length)

        e = self._do_load(self.memory, addr, length, condition=condition, fallback=fallback)
        if endness == "Iend_LE": e = e.reversed

        self._inspect('mem_read', BP_AFTER, mem_read_expr=e)
        if simplify or o.SIMPLIFY_MEMORY_READS in self.options:
            e = self.se.simplify(e)

        return e

    def mem_concrete(self, *args, **kwargs):
        '''
        Returns the contents of a memory but, if the contents are symbolic,
        raises a SimValueError.
        '''
        e = self.mem_expr(*args, **kwargs)
        if self.se.symbolic(e):
            raise SimValueError("target of mem_concrete is symbolic!")
        return self.se.any_int(e)

    def store_mem(self, addr, content, size=None, endness=None, condition=None, fallback=None):
        '''
        Stores content to memory.

        @param addr: a Claripy expression representing the address to store at
        @param content: a Claripy expression to store
        @param size: an optional Claripy expression, representing how much of the content to
                       store. If ommitted, stores the whole thing.
        @param endness: store with the provided endness. If ommitted, uses "Iend_BE" (big endian).
        @param condition: a condition, for a conditional store
        @param fallback: the value to store if the condition ends up False.
        '''
        if endness is None: endness = "Iend_BE"
        if endness == "Iend_LE": content = content.reversed

        if o.SIMPLIFY_MEMORY_WRITES in self.options:
            l.debug("simplifying memory write...")
            content = self.simplify(content)

        self._inspect('mem_write', BP_BEFORE, mem_write_address=addr, mem_write_expr=content, mem_write_length=self.se.BitVecVal(content.size()/8, self.arch.bits) if size is None else size) # pylint: disable=maybe-no-member
        e = self._do_store(self.memory, addr, content, size=size, condition=condition, fallback=fallback)
        self._inspect('mem_write', BP_AFTER)

        return e

    def make_string_table(self, strings, end_addr, align_start=0x10):
        '''
        Writes a string table into memory, ending at a given address.
        The table will have the form [pointers] [data], where the pointers are
        a null-terminated list of pointers into the data.

        The first argument, strings, should be a list where each item is either
        a string, an int, a tuple of ints, or None. If it is a string, the string will be written,
        verbatim and null-terminated, into the data table. If it is an int, that number
        of symbolic bytes will be written into the data table, followed by a null byte.
        If it is None, nothing will be written into the data table and a null pointer will
        be inserted into the pointer table. If it is a tuple of ints, those ints will be written
        verbatim into the list of pointers.

        end_addr is the lowest address guaranteed to be beyond the end of the whole table.
        In practice it will likely be several bytes beyond the end of the table, because
        the whole table will be shifted up until it satisfies alignment to the third
        argument, align_start.

        Returns the address of the start of the pointer table.
        '''
        pointers = []
        data = []
        for string in strings:
            if type(string) is str:
                pointers.append(len(data))
                data += list(string)
                data.append('\0')
            elif type(string) in (int, long):
                pointers.append(len(data))
                sr = self.se.Unconstrained('sym_string_%d' % string, string * 8)
                for i in xrange(string):
                    data.append(sr[8*i:8*i+7])
                data.append('\0')
            elif type(string) in (list, tuple):
                for c in string:
                    pointers.append((c,))
            elif string is None:
                pointers.append(None)
            else:
                raise ValueError("Unknown data type in string table")
        pointers.append(None)

        pointers_len = len(pointers) * self.arch.bytes
        table_start = end_addr - len(data) - pointers_len
        table_start -= table_start % align_start
        data_start = table_start + pointers_len

        for i, c in enumerate(pointers):
            if c is None:
                v = self.BVV(0, self.arch.bits)
            elif type(c) is tuple:
                v = self.BVV(c[0], self.arch.bits)
            else:
                v = self.BVV(c + data_start, self.arch.bits)
            self.store_mem(table_start + i*self.arch.bytes, v, endness=self.arch.memory_endness)

        for i, c in enumerate(data):
            if type(c) is str:
                self.store_mem(data_start + i, self.BVV(ord(c), 8))
            else:
                self.store_mem(data_start + i, c)
        return table_start

    ###############################
    ### Stack operation helpers ###
    ###############################

    @arch_overrideable
    def sp_expr(self):
        '''
        Returns a Claripy expression representing the current value of the stack pointer.
        Equivalent to: state.reg_expr('sp')
        '''
        return self.reg_expr(self.arch.sp_offset)

    @arch_overrideable
    def stack_push(self, thing):
        '''
        Push 'thing' to the stack, writing the thing to memory and adjusting the stack pointer.
        '''
        # increment sp
        sp = self.reg_expr(self.arch.sp_offset) + self.arch.stack_change
        self.store_reg(self.arch.sp_offset, sp)
        return self.store_mem(sp, thing, endness=self.arch.memory_endness)

    @arch_overrideable
    def stack_pop(self):
        '''
        Pops from the stack and returns the popped thing. The length will be
        the architecture word size.
        '''
        sp = self.reg_expr(self.arch.sp_offset)
        self.store_reg(self.arch.sp_offset, sp - self.arch.stack_change)
        return self.mem_expr(sp, self.arch.bits / 8, endness=self.arch.memory_endness)

    @arch_overrideable
    def stack_read(self, offset, length, bp=False):
        '''
        Reads length bytes, at an offset into the stack.

        @param offset: the offset from the stack pointer
        @param length: the number of bytes to read
        @param bp: if True, offset from the BP instead of the SP. Default: False
        '''
        if bp:
            sp = self.reg_expr(self.arch.bp_offset)
        else:
            sp = self.reg_expr(self.arch.sp_offset)

        return self.mem_expr(sp+offset, length, endness=self.arch.memory_endness)

    ###############################
    ### Other helpful functions ###
    ###############################

    def make_concrete(self, expr):
        '''
        Concretizes an expression and updates the state with a constraint
        making it that value. Returns a BitVecVal of the concrete value.
        '''
        if type(expr) in (int, long):
            raise ValueError("expr should not be an int or a long in make_concrete()")

        if not self.se.symbolic(expr):
            return expr

        v = self.se.any_expr(expr)
        self.add_constraints(expr == v)
        return v

    def make_concrete_int(self, expr):
        if type(expr) in (int, long):
            return expr
        return self.se.any_int(self.make_concrete(expr))

    # This handles the preparation of concrete function launches from abstract functions.
    @arch_overrideable
    def prepare_callsite(self, retval, args, convention='wtf'):
        #TODO
        pass

    def _dbg_print_stack(self, depth=None, sp=None):
        '''
        Only used for debugging purposes.
        Return the current stack info in formatted string. If depth is None, the
        current stack frame (from sp to bp) will be printed out.
        '''
        var_size = self.arch.bits / 8
        sp_sim = self.reg_expr(self.arch.sp_offset)
        bp_sim = self.reg_expr(self.arch.bp_offset)
        if self.se.symbolic(sp_sim) and sp is None:
            result = "SP is SYMBOLIC"
        elif self.se.symbolic(bp_sim) and depth is None:
            result = "BP is SYMBOLIC"
        else:
            sp_value = sp if sp is not None else self.se.any_int(sp_sim)
            if self.se.symbolic(bp_sim):
                result = "SP = 0x%08x, BP is symbolic\n" % (sp_value)
                bp_value = None
            else:
                bp_value = self.se.any_int(bp_sim)
                result = "SP = 0x%08x, BP = 0x%08x\n" % (sp_value, bp_value)
            if depth is None:
                # bp_value cannot be None here
                depth = (bp_value - sp_value) / var_size + 1 # Print one more value
            pointer_value = sp_value
            for i in range(depth):
                stack_value = self.stack_read(i * var_size, var_size, bp=False)

                if self.se.symbolic(stack_value):
                    concretized_value = "SYMBOLIC - %s" % repr(stack_value)
                else:
                    if len(self.se.any_n_int(stack_value, 2)) == 2:
                        concretized_value = repr(stack_value)
                    else:
                        concretized_value = "0x%08x" % self.se.any_int(stack_value)

                if pointer_value == sp_value:
                    line = "(sp)% 16x | %s" % (pointer_value, concretized_value)
                elif pointer_value == bp_value:
                    line = "(bp)% 16x | %s" % (pointer_value, concretized_value)
                else:
                    line = "% 20x | %s" % (pointer_value, concretized_value)

                pointer_value += var_size
                result += line + "\n"
        return result

    #
    # Other helper methods
    #

    def set_mode(self, mode):
        self.mode = mode
        self.options = set(o.default_options[mode])

    #
    # Concretization
    #

    #def is_native(self):
    #   if self.native_env is None and o.NATIVE_EXECUTION not in self.options:
    #       l.debug("Not native, all good.")
    #       return False
    #   elif self.native_env is not None and o.NATIVE_EXECUTION in self.options:
    #       l.debug("Native, all good.")
    #       return True
    #   elif self.native_env is None and o.NATIVE_EXECUTION in self.options:
    #       l.debug("Switching to native.")
    #       self.native_env = self.to_native()
    #       return True
    #   elif self.native_env is not None and o.NATIVE_EXECUTION not in self.options:
    #       l.debug("Switching from native.")
    #       self.from_native(self.native_env)
    #       self.native_env = None
    #       return False

    #def set_native(self, n):
    #   if n:
    #       self.options.add(o.NATIVE_EXECUTION)
    #   else:
    #       self.options.remove(o.NATIVE_EXECUTION)
    #   return self.is_native()

    #def to_native(self):
    #   l.debug("Creating native environment.")
    #   m = self.memory.concrete_parts()
    #   r = self.registers.concrete_parts()
    #   size = max(1024*3 * 10, max([0] + m.keys()) + 1024**3)
    #   l.debug("Concrete memory size: %d", size)
    #   return vexecutor.VexEnvironment(self.arch.vex_arch, size, m, r)

    #def from_native(self, e):
    #   for k,v in e.memory.changed_items():
    #       l.debug("Memory: setting 0x%x to 0x%x", k, v)
    #       self.store_mem(k, se.BitVecVal(v, 8))
    #   for k,v in e.registers.changed_items():
    #       l.debug("Memory: setting 0x%x to 0x%x", k, v)
    #       self.store_reg(k, se.BitVecVal(v, 8))

from .plugins.symbolic_memory import SimSymbolicMemory
from .plugins.abstract_memory import SimAbstractMemory
from .s_arch import Architectures
from .s_errors import SimMergeError, SimValueError, SimMemoryError
from .plugins.inspect import BP_AFTER, BP_BEFORE
import simuvex.s_options as o
import claripy
