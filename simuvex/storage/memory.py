#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.plugins.memory")

import claripy
from ..plugins.plugin import SimStatePlugin

class AddressWrapper(object):
    """
    AddressWrapper is used in SimAbstractMemory, which provides extra meta information for an address (or a ValueSet
    object) that is normalized from an integer/BVV/StridedInterval.
    """

    def __init__(self, region, address, is_on_stack, function_address):
        """
        Constructor for the class AddressWrapper.

        :param region: Name of the memory regions it belongs to
        :param address: An address (not a ValueSet object)
        :param is_on_stack: Whether this address is on a stack region or not
        :param function_address: Related function address (if any)
        """

        self.region = region
        self.address = address
        self.is_on_stack = is_on_stack
        self.function_address = function_address

    def __hash__(self):
        return hash((self.region, self.address))

    def __eq__(self, other):
        return self.region == other.region and self.address == other.address

    def __repr__(self):
        return "<%s> %s" % (self.region, hex(self.address))

    def to_valueset(self, state):
        """
        Convert to a ValueSet instance

        :param state: A state
        :return: The converted ValueSet instance
        """
        return state.se.VS(bits=state.arch.bits, region=self.region, val=self.address)

class MemoryStoreRequest(object):
    '''
    A MemoryStoreRequest is used internally by SimMemory to track memory request data.
    '''

    def __init__(self, addr, data=None, size=None, condition=None, endness=None):
        self.addr = addr
        self.data = data
        self.size = size
        self.condition = condition
        self.endness = endness

        # was this store done?
        self.completed = False

        # stuff that's determined during handling
        self.actual_addresses = None
        self.constraints = [ ]

        self.fallback_values = None
        self.symbolic_sized_values = None
        self.conditional_values = None
        self.simplified_values = None
        self.stored_values = None

class SimMemory(SimStatePlugin):
    def __init__(self, endness=None, abstract_backer=None):
        SimStatePlugin.__init__(self)
        self.id = None
        self.endness = "Iend_BE" if endness is None else endness

        # Whether this memory is internally used inside SimAbstractMemory
        self._abstract_backer = abstract_backer

    @property
    def category(self):
        """
        Return the category of this SimMemory instance. It can be one of the three following categories: reg, mem,
        and file.
        """

        if self.id in ('reg', 'mem'):
            return self.id

        elif self._abstract_backer:
            return 'mem'

        elif self.id.startswith('file'):
            return 'file'

        else:
            raise SimMemoryError('Unknown SimMemory category for memory_id "%s"' % self.id)

    def _resolve_location_name(self, name):
        if self.category == 'reg':
            return self.state.arch.registers[name]
        elif name[0] == '*':
            return self.state.registers.load(name[1:]), None
        else:
            raise SimMemoryError("Trying to address memory with a register name.")

    def _convert_to_ast(self, data_e, size_e=None):
        """
        Make an AST out of concrete @data_e
        """
        if type(data_e) is str:
            # Convert the string into a BitVecVal, *regardless of endness*
            bits = len(data_e) * 8
            data_e = self.state.BVV(data_e, bits)
        elif type(data_e) in (int, long):
            data_e = self.state.se.BVV(data_e, size_e*8 if size_e is not None
                                       else self.state.arch.bits)
        else:
            data_e = data_e.to_bv()

        return data_e

    def store(self, addr, data, size=None, condition=None, add_constraints=None, endness=None, action=None):
        '''
        Stores content into memory.

        @param addr: a claripy expression representing the address to store at
        @param data: the data to store (claripy expression or something convertable to a
                    claripy expression)
        @param size: a claripy expression representing the size of the data to store
        @param condition: (optional) a claripy expression representing a condition
                          if the store is conditional
        @param add_constraints: add constraints resulting from the merge (default: True)
        @param endness: The endianness for the data
        @param action: a SimActionData to fill out with the final written value and constraints
        '''
        addr_e = _raw_ast(addr)
        data_e = _raw_ast(data)
        size_e = _raw_ast(size)
        condition_e = _raw_ast(condition)
        add_constraints = True if add_constraints is None else add_constraints

        if isinstance(addr, str):
            named_addr, named_size = self._resolve_location_name(addr)
            addr = named_addr
            addr_e = addr
            if size is None:
                size = named_size
                size_e = size

        # store everything as a BV
        data_e = self._convert_to_ast(data_e, size_e if isinstance(size_e, (int, long)) else None)

        if type(size_e) in (int, long):
            size_e = self.state.se.BVV(size_e, self.state.arch.bits)

        if self.category == 'reg': self.state._inspect('reg_write', BP_BEFORE, reg_write_offset=addr_e, reg_write_length=size_e, reg_write_expr=data_e)
        if self.category == 'mem': self.state._inspect('mem_write', BP_BEFORE, mem_write_address=addr_e, mem_write_length=size_e, mem_write_expr=data_e)

        request = MemoryStoreRequest(addr_e, data=data_e, size=size_e, condition=condition_e, endness=endness)
        self._store(request)

        if self.category == 'reg': self.state._inspect('reg_write', BP_AFTER)
        if self.category == 'mem': self.state._inspect('mem_write', BP_AFTER)

        if add_constraints and len(request.constraints) > 0:
            self.state.add_constraints(*request.constraints)

        if request.completed and o.AUTO_REFS in self.state.options and action is None and not self._abstract_backer:
            ref_size = size if size is not None else (data_e.size() / 8)
            region_type = self.category
            if region_type == 'file':
                # Special handling for files to keep compatibility
                # We may use some refactoring later
                region_type = self.id
            action = SimActionData(self.state, region_type, 'write', addr=addr, data=data, size=ref_size, condition=condition)
            self.state.log.add_action(action)

        if request.completed and action is not None:
            action.actual_addrs = request.actual_addresses
            action.actual_value = action._make_object(request.stored_values[0]) # TODO
            if len(request.constraints) > 0:
                action.added_constraints = action._make_object(self.state.se.And(*request.constraints))
            else:
                action.added_constraints = action._make_object(self.state.se.true)

    def _store(self, request):
        raise NotImplementedError()

    def store_cases(self, addr, contents, conditions, fallback=None, add_constraints=None, endness=None, action=None):
        '''
        Stores content into memory, conditional by case.

        @param addr: a claripy expression representing the address to store at
        @param contents: a list of bitvectors, not necessarily of the same size. Use
                         None to denote an empty write
        @param conditions: a list of conditions. Must be equal in length to contents
        @param fallback: (optional) a claripy expression representing what the write
                         should resolve to if all conditions evaluate to false (default:
                         whatever was there before)
        @param add_constraints: add constraints resulting from the merge (default: True)
        @param endness: the endianness for contents as well as fallback
        @param action: a SimActionData to fill out with the final written value and constraints
        '''

        if fallback is None and all(c is None for c in contents):
            l.debug("Avoiding an empty write.")
            return

        addr_e = _raw_ast(addr)
        contents_e = _raw_ast(contents)
        conditions_e = _raw_ast(conditions)
        fallback_e = _raw_ast(fallback)

        max_bits = max(c.length for c in contents_e if isinstance(c, claripy.ast.Bits)) if fallback is None else fallback.length

        # if fallback is not provided by user, load it from memory
        # remember to specify the endianness!
        fallback_e = self.load(addr, max_bits/8, add_constraints=add_constraints, endness=endness) if fallback_e is None else fallback_e

        req = self._store_cases(addr_e, contents_e, conditions_e, fallback_e, endness=endness)
        if add_constraints:
            self.state.add_constraints(*req.constraints)

        if req.completed and o.AUTO_REFS in self.state.options and action is None:
            region_type = self.category
            if region_type == 'file':
                # Special handling for files to keep compatibility
                # We may use some refactoring later
                region_type = self.id
            action = SimActionData(self.state, region_type, 'write', addr=addr, data=req.stored_values[-1], size=max_bits/8, condition=self.state.se.Or(*conditions), fallback=fallback)
            self.state.log.add_action(action)

        if req.completed and action is not None:
            action.actual_addrs = req.actual_addresses
            action.actual_value = action._make_object(req.stored_values[-1])
            action.added_constraints = action._make_object(self.state.se.And(*req.constraints) if len(req.constraints) > 0 else self.state.se.true)

    def _store_cases(self, addr, contents, conditions, fallback, endness=None):
        extended_contents = [ ]
        for c in contents:
            if c is None:
                c = fallback
            else:
                need_bits = fallback.length - c.length
                if need_bits > 0:
                    c = c.concat(fallback[need_bits-1:0])
            extended_contents.append(c)

        case_constraints = { }
        for c,g in zip(extended_contents, conditions):
            if c not in case_constraints:
                case_constraints[c] = [ ]
            case_constraints[c].append(g)

        unique_contents = [ ]
        unique_constraints = [ ]
        for c,g in case_constraints.items():
            unique_contents.append(c)
            unique_constraints.append(self.state.se.Or(*g))

        if len(unique_contents) == 1 and unique_contents[0] is fallback:
            req = MemoryStoreRequest(addr, data=fallback, endness=endness)
            return self._store(req)
        else:
            simplified_contents = [ ]
            simplified_constraints = [ ]
            for c,g in zip(unique_contents, unique_constraints):
                simplified_contents.append(self.state.se.simplify(c))
                simplified_constraints.append(self.state.se.simplify(g))
            cases = zip(simplified_constraints, simplified_contents)
            #cases = zip(unique_constraints, unique_contents)

            ite = self.state.se.simplify(self.state.se.ite_cases(cases, fallback))
            req = MemoryStoreRequest(addr, data=ite, endness=endness)
            return self._store(req)

    def load(self, addr, size=None, condition=None, fallback=None, add_constraints=None, action=None, endness=None):
        '''
        Loads size bytes from dst.

            @param dst: the address to load from
            @param size: the size (in bytes) of the load
            @param condition: a claripy expression representing a condition for a conditional load
            @param fallback: a fallback value if the condition ends up being False
            @param add_constraints: add constraints resulting from the merge (default: True)
            @param action: a SimActionData to fill out with the constraints
            @param endness: the endness to load with

        There are a few possible return values. If no condition or fallback are passed in,
        then the return is the bytes at the address, in the form of a claripy expression.
        For example:

            <A BVV(0x41, 32)>

        On the other hand, if a condition and fallback are provided, the value is conditional:

            <A If(condition, BVV(0x41, 32), fallback)>
        '''
        add_constraints = True if add_constraints is None else add_constraints

        addr_e = _raw_ast(addr)
        size_e = _raw_ast(size)
        condition_e = _raw_ast(condition)
        fallback_e = _raw_ast(fallback)

        if isinstance(addr, str):
            named_addr, named_size = self._resolve_location_name(addr)
            addr = named_addr
            addr_e = addr
            if size is None:
                size = named_size
                size_e = size

        if size is None:
            size = self.state.arch.bits / 8
            size_e = size

        if self.category == 'reg': self.state._inspect('reg_read', BP_BEFORE, reg_read_offset=addr_e, reg_read_length=size_e)
        if self.category == 'mem': self.state._inspect('mem_read', BP_BEFORE, mem_read_address=addr_e, mem_read_length=size_e)

        a,r,c = self._load(addr_e, size_e, condition=condition_e, fallback=fallback_e)
        if add_constraints:
            self.state.add_constraints(*c)

        if (self.category == 'mem' and o.SIMPLIFY_MEMORY_READS in self.state.options) or \
           (self.category == 'reg' and o.SIMPLIFY_REGISTER_READS in self.state.options):
            l.debug("simplifying %s read...", self.category)
            r = self.state.simplify(r)

        if not self._abstract_backer and \
                o.UNINITIALIZED_ACCESS_AWARENESS in self.state.options and \
                self.state.uninitialized_access_handler is not None and \
                (r.op == 'Reverse' or r.op == 'I') and \
                hasattr(r.model, 'uninitialized') and \
                r.model.uninitialized:
            normalized_addresses = self.normalize_address(addr)
            if len(normalized_addresses) > 0 and type(normalized_addresses[0]) is AddressWrapper:
                normalized_addresses = [ (aw.region, aw.address) for aw in normalized_addresses ]
            self.state.uninitialized_access_handler(self.category, normalized_addresses, size, r, self.state.scratch.bbl_addr, self.state.scratch.stmt_idx)

        # the endness
        endness = self.endness if endness is None else endness
        if endness == "Iend_LE":
            r = r.reversed

        if self.category == 'mem': self.state._inspect('mem_read', BP_AFTER, mem_read_expr=r)
        if self.category == 'reg': self.state._inspect('reg_read', BP_AFTER, reg_read_expr=r)

        if o.AST_DEPS in self.state.options and self.category == 'reg':
            r = SimActionObject(r, reg_deps=frozenset((addr,)))

        if o.AUTO_REFS in self.state.options and action is None:
            ref_size = size if size is not None else (r.size() / 8)
            region_type = self.category
            if region_type == 'file':
                # Special handling for files to keep compatibility
                # We may use some refactoring later
                region_type = self.id
            action = SimActionData(self.state, region_type, 'read', addr=addr, data=r, size=ref_size, condition=condition, fallback=fallback)
            self.state.log.add_action(action)

        if action is not None:
            action.actual_addrs = a
            action.added_constraints = action._make_object(self.state.se.And(*c) if len(c) > 0 else self.state.se.true)

        return r

    def normalize_address(self, addr, is_write=False): #pylint:disable=no-self-use,unused-argument
        '''
        Normalizes the address for use in static analysis (with the abstract memory
        model). In non-abstract mode, simply returns the address in a single-element
        list.
        '''
        return [ addr ]

    def _load(self, addr, size, condition=None, fallback=None):
        raise NotImplementedError()

    def find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None):
        '''
        Returns the address of bytes equal to 'what', starting from 'start'. Note that,
        if you don't specify a default value, this search could cause the state to go
        unsat if no possible matching byte exists.

            @param start: the start address
            @param what: what to search for
            @param max_search: search at most this many bytes
            @param max_symbolic_bytes: search through at most this many symbolic bytes
            @param default: the default value, if what you're looking for wasn't found

            @returns an expression representing the address of the matching byte
        '''
        addr = _raw_ast(addr)
        what = _raw_ast(what)
        default = _raw_ast(default)

        r,c,m = self._find(addr, what, max_search=max_search, max_symbolic_bytes=max_symbolic_bytes, default=default)
        if o.AST_DEPS in self.state.options and self.category == 'reg':
            r = SimActionObject(r, reg_deps=frozenset((addr,)))

        return r,c,m

    def _find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None):
        raise NotImplementedError()

    def copy_contents(self, dst, src, size, condition=None, src_memory=None, dst_memory=None):
        '''
        Copies data within a memory.

        @param dst: claripy expression representing the address of the destination
        @param src: claripy expression representing the address of the source
        @param src_memory: (optional) copy data from this SimMemory instead of self
        @param src_memory: (optional) copy data to this SimMemory instead of self
        @param size: claripy expression representing the size of the copy
        @param condition: claripy expression representing a condition, if the write should
                          be conditional. If this is determined to be false, the size of
                          the copy will be 0
        '''
        dst = _raw_ast(dst)
        src = _raw_ast(src)
        size = _raw_ast(size)
        condition = _raw_ast(condition)

        return self._copy_contents(dst, src, size, condition=condition, src_memory=src_memory, dst_memory=dst_memory)

    def _copy_contents(self, dst, src, size, condition=None, src_memory=None, dst_memory=None):
        raise NotImplementedError()

from .. import s_options as o
from ..s_action import SimActionData
from ..s_action_object import SimActionObject, _raw_ast
from ..s_errors import SimMemoryError
from ..plugins.inspect import BP_BEFORE, BP_AFTER
