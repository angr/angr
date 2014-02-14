#!/usr/bin/env python

import copy
import itertools

import symexec
import s_memory
import s_arch
import functools
from .s_value import SimValue
from .s_helpers import flip_bytes
from s_exception import SimMergeError

import logging
l = logging.getLogger("s_state")

def arch_overrideable(f):
    @functools.wraps(f)
    def wrapped_f(self, *args, **kwargs):
        if hasattr(self.arch, f.__name__):
            arch_f = getattr(self.arch, f.__name__)
            return arch_f(self, *args, **kwargs)
        else:
            return f(self, *args, **kwargs)
    return wrapped_f

default_plugins = { }

# This is a base class for SimState plugins. A SimState plugin will be copied along with the state when the state is branched. They
# are intended to be used for things such as tracking open files, tracking heap details, and providing storage and persistence for SimProcedures.
class SimStatePlugin(object):
    __slots__ = [ 'state' ]

    def __init__(self):
        self.state = None

    # Sets a new state (for example, if it the state has been branched)
    def set_state(self, state):
        self.state = state

    # Should return a copy of the state plugin.
    def copy(self):
        raise Exception("copy() not implement for %s", self.__class__.__name__)

    # Should merge the state plugin with the provided other.
    #
    #    other - the other state plugin
    #    merge_flag - a symbolic expression for the merge flag
    #    flag_us_value - the value to compare against to check if our content should be used or the other's content. Example:
    #
    #        self.symbolic_content = symexec.If(merge_flag == flag_us_value, self.symbolic_content, other.symbolic_content)
    def merge(self, other, merge_flag, flag_us_value): # pylint: disable=W0613
        raise Exception("merge() not implement for %s", self.__class__.__name__)

    @staticmethod
    def register_default(name, cls):
        if name in default_plugins:
            raise Exception("%s is already set as the default for %s" % (default_plugins[name], name))
        default_plugins[name] = cls

# This is a counter for the state-merging symbolic variables
merge_counter = itertools.count()

class SimState(object): # pylint: disable=R0904
    '''The SimState represents the state of a program, including its memory, registers, and so forth.'''

    __slots__ = [ 'arch', 'temps', 'memory', 'registers', 'old_constraints', 'new_constraints', 'branch_constraints', 'plugins', 'track_constraints', '_solver' ]

    def __init__(self, temps=None, registers=None, memory=None, arch="AMD64", plugins=None, memory_backer=None, track_constraints=None):
        # the architecture is used for function simulations (autorets) and the bitness
        self.arch = s_arch.Architectures[arch] if isinstance(arch, str) else arch

        # VEX temps are temporary variables local to an IRSB
        self.temps = temps if temps is not None else { }

        # VEX treats both memory and registers as memory regions
        if memory:
            self.memory = memory
        else:
            if memory_backer is None: memory_backer = { }
            vectorized_memory = s_memory.Vectorizer(memory_backer)
            self.memory = s_memory.SimMemory(vectorized_memory, memory_id="mem", bits=self.arch.bits)

        if registers:
            self.registers = registers
        else:
            self.registers = s_memory.SimMemory({ }, memory_id="reg", bits=self.arch.bits)

        # let's keep track of the old and new constraints
        self.old_constraints = [ ]
        self.new_constraints = [ ]
        self.branch_constraints = [ ]

        # plugins
        self.plugins = { }
        if plugins is not None:
            for n,p in plugins.iteritems():
                self.register_plugin(n, p)

        self.track_constraints = track_constraints if track_constraints is not None else True
        self._solver = None

    @property
    def solver(self):
        if self._solver is not None:
            return self._solver

        ca = self.constraints_after()
        if len(ca) == 0 and not self.track_constraints:
            return symexec.empty_solver
        else:
            # here's our solver!
            l.debug("Creating solver for %s", self)
            self._solver = symexec.Solver()
            self._solver.add(*ca)
            return self._solver

    def get_plugin(self, name):
        if name not in self.plugins:
            p = default_plugins[name]()
            self.register_plugin(name, p)
            return p
        return self.plugins[name]

    # ok, ok
    def __getitem__(self, name): return self.get_plugin(name)

    def register_plugin(self, name, plugin):
        l.debug("Adding plugin %s of type %s", name, plugin.__class__.__name__)
        plugin.set_state(self)
        self.plugins[name] = plugin

    def simplify(self):
        if len(self.old_constraints) > 0:
            self.old_constraints = [ symexec.simplify_expression(symexec.And(*self.old_constraints)) ]

        if len(self.new_constraints) > 0:
            self.new_constraints = [ symexec.simplify_expression(symexec.And(*self.new_constraints)) ]

        if len(self.branch_constraints) > 0:
            self.branch_constraints = [ symexec.simplify_expression(symexec.And(*self.branch_constraints)) ]

    def constraints_after(self):
        return self.old_constraints + self.new_constraints + self.branch_constraints

    def constraints_before(self):
        return copy.copy(self.old_constraints)

    def constraints_avoid(self):
        # if there are no branch constraints, we can't avoid
        if len(self.branch_constraints) == 0:
            return self.old_constraints + self.new_constraints + [ symexec.BitVecVal(1, 1) == 0 ]
        else:
            return self.old_constraints + self.new_constraints + [ symexec.Not(symexec.And(*self.branch_constraints)) ]

    def add_old_constraints(self, *args):
        if self.track_constraints:
            self.old_constraints.extend(args)
            self.solver.add(*args)

    def add_constraints(self, *args):
        if self.track_constraints:
            self.new_constraints.extend(args)
            self.solver.add(*args)

    def add_branch_constraints(self, *args):
        if self.track_constraints:
            self.branch_constraints.extend(args)
            self.solver.add(*args)

    def clear_constraints(self):
        self.old_constraints = [ ]
        self.new_constraints = [ ]
        self.branch_constraints = [ ]

    # Helper function for loading from symbolic memory and tracking constraints
    def simmem_expression(self, simmem, addr, length, when=None):
        if type(addr) not in (int, long) and not isinstance(addr, SimValue):
            # it's an expression
            addr = self.expr_value(addr, when=when)

        # do the load and track the constraints
        m,e = simmem.load(addr, length)
        self.add_constraints(*e)
        return m

    # Helper function for storing to symbolic memory and tracking constraints
    def store_simmem_expression(self, simmem, addr, content, when=None):
        if type(addr) not in (int, long) and not isinstance(addr, SimValue):
            # it's an expression
            addr = self.expr_value(addr, when=when)

        # do the store and track the constraints
        e = simmem.store(addr, content)
        self.add_constraints(*e)
        return e

    ####################################
    ### State progression operations ###
    ####################################

    # Applies new constraints to the state so that a branch is avoided.
    def inplace_avoid(self):
        self._solver = None
        self.old_constraints = self.constraints_avoid()
        self.new_constraints = [ ]
        self.branch_constraints = [ ]

    # Applies new constraints to the state so that a branch (if any) is taken
    def inplace_after(self):
        self.old_constraints = self.constraints_after()
        self.new_constraints = [ ]
        self.branch_constraints = [ ]

    ##################################
    ### State branching operations ###
    ##################################

    # Returns a dict that is a copy of all the state's plugins
    def copy_plugins(self):
        return { n: p.copy() for n,p in self.plugins.iteritems() }

    # Copies a state without its constraints
    def copy_unconstrained(self):
        c_temps = copy.copy(self.temps)
        c_mem = self.memory.copy()
        c_registers = self.registers.copy()
        c_arch = self.arch
        c_plugins = self.copy_plugins()
        c_track = self.track_constraints
        return SimState(temps=c_temps, registers=c_registers, memory=c_mem, arch=c_arch, plugins=c_plugins, track_constraints=c_track)

    # Copies a state so that a branch (if any) is taken
    def copy_after(self):
        c = self.copy_unconstrained()
        c.add_old_constraints(*self.constraints_after())
        return c

    # Creates a copy of the state, discarding added constraints
    def copy_before(self):
        c = self.copy_unconstrained()
        c.add_old_constraints(*self.constraints_before())
        return c

    # Copies a state so that a branch is avoided
    def copy_avoid(self):
        c = self.copy_unconstrained()
        c.add_old_constraints(*self.constraints_avoid())
        return c

    # Copies the state, with all the new and branch constraints un-applied but present
    def copy_exact(self):
        c = self.copy_before()
        c.add_constraints(*self.new_constraints)
        c.add_branch_constraints(*self.branch_constraints)
        return c

    # Merges this state with the other state. Discards temps by default.
    def merge(self, other, keep_temps = False):
        merge_flag = symexec.BitVec("state_merge_%d" % merge_counter.next(), 1)
        merge_us_value = 1

        if self.plugins.keys() != other.plugins.keys():
            raise SimMergeError("Unable to merge due to different sets of plugins.")
        if self.arch != other.arch:
            raise SimMergeError("Unable to merge due to different architectures.")

        # memory and registers
        constraints = self.memory.merge(other.memory, merge_flag, merge_us_value)
        self.add_constraints(*constraints)
        constraints = self.registers.merge(other.registers, merge_flag, merge_us_value)
        self.add_constraints(*constraints)

        # temps
        if keep_temps:
            raise SimMergeError("Please implement temp merging or bug Yan.")

        # old constraints
        our_o = symexec.And(*self.old_constraints) if len(self.old_constraints) > 0 else True
        their_o = symexec.And(*other.old_constraints) if len(other.old_constraints) > 0 else True
        self.old_constraints = [ symexec.If(merge_flag == merge_us_value, our_o, their_o) ]

        # new constraints
        our_n = symexec.And(*self.new_constraints) if len(self.new_constraints) > 0 else True
        their_n = symexec.And(*other.new_constraints) if len(other.new_constraints) > 0 else True
        self.new_constraints = [ symexec.If(merge_flag == merge_us_value, our_n, their_n) ]

        # branch constraints
        our_b = symexec.And(*self.branch_constraints) if len(self.branch_constraints) > 0 else True
        their_b = symexec.And(*other.branch_constraints) if len(other.branch_constraints) > 0 else True
        self.branch_constraints = [ symexec.If(merge_flag == merge_us_value, our_b, their_b) ]

        # plugins
        for p in self.plugins:
            self.plugins[p].merge(other.plugins[p], merge_flag, merge_us_value)

    #############################################
    ### Accessors for tmps, registers, memory ###
    #############################################

    # Returns the BitVector expression of a VEX temp value
    def tmp_expr(self, tmp):
        return self.temps[tmp]

    # Returns the SimValue representing a VEX temp value
    def tmp_value(self, tmp, when=None):
        return self.expr_value(self.tmp_expr(tmp), when=when)

    # Stores a BitVector expression in a VEX temp value
    def store_tmp(self, tmp, content):
        if tmp not in self.temps:
            # Non-symbolic
            self.temps[tmp] = content
        else:
            # Symbolic
            self.add_constraints(self.temps[tmp] == content)

    # Returns the BitVector expression of the content of a register
    def reg_expr(self, offset, length=None, when=None):
        if length is None: length = self.arch.bits / 8
        return self.simmem_expression(self.registers, offset, length, when)

    # Returns the SimValue representing the content of a register
    def reg_value(self, offset, length=None, when=None):
        return self.expr_value(self.reg_expr(offset, length, when), when=when)

    # Returns a concretized value of the content in a register
    def reg_concrete(self, *args, **kwargs):
        return symexec.utils.concretize_constant(self.reg_expr(*args, **kwargs))

    # Stores a bitvector expression in a register
    def store_reg(self, offset, content, length=None, when=None):
        if type(content) in (int, long):
            if not length:
                l.warning("Length not provided to store_reg with integer content. Assuming bit-width of CPU.")
                length = self.arch.bits / 8
            content = symexec.BitVecVal(content, length * 8)
        return self.store_simmem_expression(self.registers, offset, content, when)

    # Returns the BitVector expression of the content of memory at an address
    def mem_expr(self, addr, length, when=None, endness="Iend_BE"):
        e = self.simmem_expression(self.memory, addr, length, when)
        if endness == "Iend_LE":
            e = flip_bytes(e)
        return e

    # Returns a concretized value of the content at a memory address
    def mem_concrete(self, *args, **kwargs):
        return symexec.utils.concretize_constant(self.mem_expr(*args, **kwargs))

    # Returns the SimValue representing the content of memory at an address
    def mem_value(self, addr, length, when=None, endness="Iend_BE"):
        return self.expr_value(self.mem_expr(addr, length, when, endness), when=when)

    # Stores a bitvector expression at an address in memory
    def store_mem(self, addr, content, when=None, endness="Iend_BE"):
        if endness == "Iend_LE":
            content = flip_bytes(content)
        return self.store_simmem_expression(self.memory, addr, content, when)

    ###############################
    ### Stack operation helpers ###
    ###############################

    # Push to the stack, writing the thing to memory and adjusting the stack pointer.
    @arch_overrideable
    def stack_push(self, thing):
        # increment sp
        sp = self.reg_expr(self.arch.sp_offset) + 4
        self.store_reg(self.arch.sp_offset, sp)

        return self.store_mem(sp, thing)

    # Pop from the stack, adjusting the stack pointer and returning the popped thing.
    @arch_overrideable
    def stack_pop(self):
        sp = self.reg_expr(self.arch.sp_offset)
        self.store_reg(self.arch.sp_offset, sp - self.arch.bits / 8)

        return self.mem_expr(sp, self.arch.bits / 8)

    # Returns a SimValue, popped from the stack
    @arch_overrideable
    def stack_pop_value(self):
        return self.expr_value(self.stack_pop())

    # Read some number of bytes from the stack at the provided offset.
    @arch_overrideable
    def stack_read(self, offset, length, bp=False):
        if bp:
            sp = self.reg_expr(self.arch.bp_offset)
        else:
            sp = self.reg_expr(self.arch.sp_offset)

        return self.mem_expr(sp+offset, length)

    # Returns a SimVal, representing the bytes on the stack at the provided offset.
    @arch_overrideable
    def stack_read_value(self, offset, length, bp=False):
        return self.expr_value(self.stack_read(offset, length, bp))

    ###############################
    ### Other helpful functions ###
    ###############################

    # Returns a SimValue of the expression, with the specified constraint set
    def expr_value(self, expr, extra_constraints=list(), when=None):
        if when is None:
            return SimValue(expr, state = self, constraints = extra_constraints)
        elif when == "after":
            return SimValue(expr, constraints = self.constraints_after() + extra_constraints)
        elif when == "before":
            return SimValue(expr, constraints = self.constraints_before() + extra_constraints)
        elif when == "avoid":
            return SimValue(expr, constraints = self.constraints_avoid() + extra_constraints)

    # Concretizes an expression and updates the state with a constraint making it that value. Returns a BitVecVal of the concrete value.
    def make_concrete(self, expr, when=None):
        return symexec.BitVecVal(self.make_concrete_int(expr, when=when), expr.size())

    # Concretizes an expression and updates the state with a constraint making it that value. Returns an int of the concrete value.
    def make_concrete_int(self, expr, when=None):
        if type(expr) in (int, long):
            return expr

        v_int = self.expr_value(expr, when=when).any()
        self.add_constraints(expr == v_int)
        return v_int

    # This handles the preparation of concrete function launches from abstract functions.
    @arch_overrideable
    def prepare_callsite(self, retval, args, convention='wtf'):
        #TODO
        pass

    def satisfiable(self):
    	return self.solver.check() == symexec.sat
