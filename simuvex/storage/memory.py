#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.plugins.memory")

import claripy
from ..plugins.plugin import SimStatePlugin

class SimMemory(SimStatePlugin):
    def __init__(self, endness=None, abstract_backer=None):
        SimStatePlugin.__init__(self)
        self.id = None
        self._endness = "Iend_BE" if endness is None else endness

        # Whether this memory is internally used inside SimAbstractMemory
        self._abstract_backer = abstract_backer

    def store(self, addr, data, size=None, condition=None, fallback=None, add_constraints=None, endness=None, action=None):
        '''
        Stores content into memory.

        @param addr: a claripy expression representing the address to store at
        @param data: the data to store (claripy expression or something convertable to a
                    claripy expression)
        @param size: a claripy expression representing the size of the data to store
        @param condition: (optional) a claripy expression representing a condition
                          if the store is conditional
        @param fallback: (optional) a claripy expression representing what the write
                         should resolve to if the condition evaluates to false (default:
                         whatever was there before)
        @param add_constraints: add constraints resulting from the merge (default: True)
        @param action: a SimActionData to fill out with the final written value and constraints
        '''
        add_constraints = True if add_constraints is None else add_constraints

        addr_e = _raw_ast(addr)
        data_e = _raw_ast(data)
        size_e = _raw_ast(size)
        condition_e = _raw_ast(condition)
        fallback_e = _raw_ast(fallback)

        # TODO: first, simplify stuff
        if (
                    (self.id == 'mem' and o.SIMPLIFY_MEMORY_WRITES in self.state.options) or
                    (self.id == 'reg' and o.SIMPLIFY_REGISTER_WRITES in self.state.options)
        ):
            l.debug("simplifying %s write...", self.id)
            data_e = self.state.simplify(data_e)

        # store everything as a BV
        if type(data_e) is str:
            # Convert the string into a BitVecVal, *regardless of endness*
            bits = len(data_e) * 8
            data_e = self.state.BVV(data_e, bits)
        else:
            data_e = data_e.to_bv()

        # the endness
        endness = self._endness if endness is None else endness
        if endness == "Iend_LE":
            data_e = data_e.reversed

        if o.AUTO_REFS in self.state.options and action is None:
            ref_size = size if size is not None else (data_e.size() / 8)
            action = SimActionData(self.state, self.id, 'write', addr=addr, data=data, size=ref_size, condition=condition, fallback=fallback)
            self.state.log.add_action(action)

        a,r,c = self._store(addr_e, data_e, size=size_e, condition=condition_e, fallback=fallback_e)
        if add_constraints:
            self.state.add_constraints(*c)

        if action is not None:
            action.actual_addrs = a
            action.actual_value = action._make_object(r)
            action.added_constraints = action._make_object(self.state.se.And(*c) if len(c) > 0 else self.state.se.true)

    def _store(self, addr, data, size=None, condition=None, fallback=None):
        raise NotImplementedError()

    def store_cases(self, addr, contents, conditions, fallback=None, add_constraints=None, action=None):
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
        fallback_e = self.load(addr, max_bits/8, add_constraints=add_constraints) if fallback_e is None else fallback_e

        a,r,c = self._store_cases(addr_e, contents_e, conditions_e, fallback_e)
        if add_constraints:
            self.state.add_constraints(*c)

        if o.AUTO_REFS in self.state.options and action is None:
            action = SimActionData(self.state, self.id, 'write', addr=addr, data=r, size=max_bits/8, condition=self.state.se.Or(*conditions), fallback=fallback)
            self.state.log.add_action(action)

        if action is not None:
            action.actual_addrs = a
            action.actual_value = action._make_object(r)
            action.added_constraints = action._make_object(self.state.se.And(*c) if len(c) > 0 else self.state.se.true)

    def _store_cases(self, addr, contents, conditions, fallback):
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
            return self._store(addr, fallback)
        else:
            simplified_contents = [ ]
            simplified_constraints = [ ]
            for c,g in zip(unique_contents, unique_constraints):
                simplified_contents.append(self.state.se.simplify(c))
                simplified_constraints.append(self.state.se.simplify(g))
            cases = zip(simplified_constraints, simplified_contents)
            #cases = zip(unique_constraints, unique_contents)

            ite = self.state.se.simplify(self.state.se.ite_cases(cases, fallback))
            return self._store(addr, ite)

    def load(self, addr, size, condition=None, fallback=None, add_constraints=None, action=None):
        '''
        Loads size bytes from dst.

            @param dst: the address to load from
            @param size: the size (in bytes) of the load
            @param condition: a claripy expression representing a condition for a conditional load
            @param fallback: a fallback value if the condition ends up being False
            @param add_constraints: add constraints resulting from the merge (default: True)
            @param action: a SimActionData to fill out with the constraints

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

        a,r,c = self._load(addr_e, size_e, condition=condition_e, fallback=fallback_e)
        if add_constraints:
            self.state.add_constraints(*c)

        if not self._abstract_backer and \
                self.id != 'reg' and \
                o.UNINITIALIZED_ACCESS_AWARENESS in self.state.options and \
                self.state.uninitialized_access_handler is not None and \
                (r.op == 'Reverse' or r.op == 'I') and \
                hasattr(r.model, 'uninitialized') and \
                r.model.uninitialized:
            converted_addrs = [ (a[0], a[1]) if not isinstance(a, (tuple, list)) else a for a in self.state.memory.normalize_address(addr) ]
            self.state.uninitialized_access_handler(self.id, converted_addrs, size, r, self.state.scratch.bbl_addr, self.state.scratch.stmt_idx)

        if o.AST_DEPS in self.state.options and self.id == 'reg':
            r = SimActionObject(r, reg_deps=frozenset((addr,)))

        if o.AUTO_REFS in self.state.options and action is None:
            ref_size = size if size is not None else (r.size() / 8)
            action = SimActionData(self.state, self.id, 'read', addr=addr, data=r, size=ref_size, condition=condition, fallback=fallback)
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

    def find(self, addr, what, max_search=100, max_symbolic_bytes=None, default=None):
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
        if o.AST_DEPS in self.state.options and self.id == 'reg':
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
