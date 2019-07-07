import angr
import logging
import claripy
import pdb
import sys
import os
import pyvex
import traceback
import bisect
import cffi
import resource
import pdb
import time
import itertools
import sortedcontainers
import operator
import functools

from ..storage.memory import SimMemory, DUMMY_SYMBOLIC_READ_VALUE
from ..misc.ux import once
from .history import SimStateHistory
from .sim_action_object import SimActionObject
from .plugin import SimStatePlugin
from . import paged_memory
from .pitree import pitree
from .utils import get_obj_byte, get_unconstrained_bytes, resolve_size_range

log = logging.getLogger('memsight')
log.setLevel(logging.DEBUG)

class MemoryItem(object):
    __slots__ = ('addr', '_obj', 't', 'guard')

    def __init__(self, addr, obj, t, guard):
        self.addr = addr
        self._obj = obj
        self.t = t
        self.guard = guard

    @property
    def obj(self):
        if type(self._obj) in (list,):
            self._obj = get_obj_byte(self._obj[0], self._obj[1])
        return self._obj

    def __repr__(self):
        return "[" + str(self.addr) + ", " + str(self.obj) + ", " + str(self.t) + ", " + str(self.guard) + "]"

    # noinspection PyProtectedMember
    def _compare_obj(self, other):

        if id(self._obj) == id(other._obj):
            return True

        if type(self._obj) in (list,) and type(other._obj) in (list,) \
                and id(self._obj[0]) == id(other._obj[0]) \
                and self._obj[1] == self._obj[1]:
            return True

        if type(self._obj) in (list,):
            if type(self._obj[0]) not in (claripy.ast.bv.BV,):
                return False
        elif type(self._obj) not in (claripy.ast.bv.BV,):
            return False

        if type(other._obj) in (list,):
            if type(other._obj[0]) not in (claripy.ast.bv.BV,):
                return False
        elif type(other._obj) not in (claripy.ast.bv.BV,):
            return False

        a = self.obj
        b = other.obj
        if a.op == 'BVV' and b.op == 'BVV':
            return a.args[0] == b.args[0]

        return False

    def __eq__(self, other):

        if id(self) == id(other):
            return True

        if (other is None
            or self.t != other.t
            # or (type(self.addr) in (int, long) and type(other.addr) in (int, long) and self.addr != other.addr)
            or (type(self.obj) == int and type(other.obj) == int and self.obj != other.obj)
            or id(self.guard) != id(other.guard)  # conservative
            or not self._compare_obj(other)):
            return False

        return True

    def copy(self):
        return MemoryItem(self.addr, self.obj, self.t, self.guard)


class MappedRegion(object):
    PROT_READ = 1
    PROT_WRITE = 2
    PROT_EXEC = 4

    def __init__(self, addr, length, permissions):
        self.addr = addr
        self.length = length
        self.permissions = permissions

    def __repr__(self):
        rwx_s = "r" if self.is_readable() else ''
        rwx_s += "w" if self.is_writable() else ''
        rwx_s += "x" if self.is_executable() else ''
        return "(" + str(hex(self.addr)) + ", " + str(hex(self.addr + self.length)) + ") [" + rwx_s + "]"

    def is_readable(self):
        return self.permissions.args[0] & MappedRegion.PROT_READ

    def is_writable(self):
        return self.permissions.args[0] & MappedRegion.PROT_WRITE

    def is_executable(self):
        return self.permissions.args[0] & MappedRegion.PROT_EXEC


class FullySymbolicMemory(SimMemory):
    def __init__(self, memory_backer=None,
                 permissions_backer=None,
                 arch=None,
                 endness=None,
                 concrete_memory=None,
                 symbolic_memory=None,
                 stack_range=None,
                 mapped_regions=[],
                 timestamp=0,
                 initializable=None,
                 initialized=False,
                 timestamp_implicit=0):

        SimMemory.__init__(self,
                           endness=endness,
                           abstract_backer=False,
                           stack_region_map=None,
                           generic_region_map=None
                           )

        self._memory_backer = memory_backer
        # assert not permissions_backer[0]
        self._permissions_backer = permissions_backer
        self.id = "mem"
        self._arch = arch
        self._endness = "Iend_BE" if endness is None else endness

        self._initial_timestamps = [timestamp, timestamp_implicit]

        self._concrete_memory = paged_memory.PagedMemory(self) if concrete_memory is None else concrete_memory
        self._symbolic_memory = pitree.pitree() if symbolic_memory is None else symbolic_memory

        # stack range
        self._stack_range = stack_range

        # mapped regions
        self._mapped_regions = mapped_regions

        self._initializable = initializable if initializable is not None else sortedcontainers.SortedList(
            key=operator.itemgetter(0))
        self._initialized = initialized

        # required by CGC deallocate()
        self._page_size = self._concrete_memory.PAGE_SIZE

    @property
    def timestamp(self):
        assert self.state is not None
        self.init_timestamps()
        return self.state.history.timestamps[0]

    @timestamp.setter
    def timestamp(self, value):
        assert self.state is not None
        self.init_timestamps()
        self.state.history.timestamps[0] = value

    @property
    def implicit_timestamp(self):
        assert self.state is not None
        self.init_timestamps()
        return self.state.history.timestamps[1]

    @implicit_timestamp.setter
    def implicit_timestamp(self, value):
        assert self.state is not None
        self.init_timestamps()
        self.state.history.timestamps[1] = value

    def init_timestamps(self):
        assert self.state is not None
        if self._initial_timestamps is not None:
            self.state.history.timestamps = self._initial_timestamps
            self._initial_timestamps = None

    @property
    def _pages(self):
        # required by CGC deallocate()
        # this is not correct
        return self._concrete_memory._pages

    def _init_memory(self):

        if self._initialized:
            return

        # init mapped regions
        if self._permissions_backer is not None:
            for start, end in self._permissions_backer[1]:
                perms = self._permissions_backer[1][(start, end)]
                self.map_region(start, end - start, perms)

        # init memory
        if self._memory_backer is not None:

            for addr, data in self._memory_backer.backers():

                obj = claripy.BVV(bytes(data))

                size = len(obj) // self.state.arch.byte_width
                data_offset = 0
                page_index = int(addr / self._page_size)
                page_offset = addr % self._page_size

                while size > 0:
                    max_bytes_in_page = page_index * 0x1000 + 0x1000 - addr
                    mo = [page_index, obj, data_offset, page_offset, min([size, self._page_size, max_bytes_in_page])]
                    self._initializable.add(mo)
                    page_index += 1
                    size -= self._page_size - page_offset
                    data_offset += self._page_size - page_offset
                    page_offset = 0

        self._initialized = True

    def set_state(self, state):
        super(FullySymbolicMemory, self).set_state(state)
        self._init_memory()

        # FIXME: conscious decision to not support this option. BVS.uc_alloc_depth does not carry across Concat().
        # It's non-trivial to rewrite _load() to not have to Concat(), even for common case
        if options.UNDER_CONSTRAINED_SYMEXEC in self.state.options:
            raise NotImplementedError

    def _load_init_data(self, addr, size):
        page_index = int(addr / self._page_size)
        page_end = int((addr + size) / self._page_size)

        to_remove = []
        for k in range(self._initializable.bisect_key_left(page_index), self._initializable.bisect_key_right(page_end)):
            # [page_index, data, data_offset, page_offset, min(size, page_size)]
            page_index, data, data_offset, page_offset, page_size = self._initializable[k]
            page = self._concrete_memory._pages[page_index] if page_index in self._concrete_memory._pages else None
            for j in range(page_size):
                if page is not None and page_offset + j in page:
                    continue
                e = (page_index * 0x1000) + page_offset + j
                # MemoryItem lazily slices [data, idx] for perf
                v = [data, data_offset + j]
                self._concrete_memory[e] = MemoryItem(e, v, 0, None)
            to_remove.append(self._initializable[k])

        for e in to_remove:
            self._initializable.remove(e)

    def build_ite(self, addr, cases, v, obj):

        assert len(cases) > 0

        if len(cases) == 1:
            cond = addr == cases[0].addr
        else:
            cond = self.state.solver.And(addr >= cases[0].addr, addr <= cases[-1].addr)

        cond = claripy.And(cond, cases[0].guard) if cases[0].guard is not None else cond

        return self.state.solver.If(cond, v, obj)

    def _fill_missing(self, addr, min_addr, max_addr, inspect=True, events=True):
        if once('mem_fill_warning'):
            log.warning("The program is accessing memory or registers with an unspecified value. "
                        "This could indicate unwanted behavior.")
            log.warning("angr will cope with this by generating an unconstrained symbolic variable and "
                        "continuing.  You can resolve this by:")
            log.warning("1) setting a value to the initial state")
            log.warning("2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, "
                        "to make unknown regions hold null")
            log.warning("3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, "
                        "to suppress these messages.")
        refplace_int = self.state.solver.eval(self.state._ip)
        if self.state.project:
            refplace_str = self.state.project.loader.describe_addr(refplace_int)
        else:
            refplace_str = "unknown"
        log.warning("Filling memory with 1 unconstrained bytes referenced from %#x (%s)",
                    refplace_int, refplace_str)

        obj = get_unconstrained_bytes(
                self.category,
                self.state,
                "%s_%x" % (self.id, min_addr),
                self.state.arch.byte_width,
                inspect=inspect,
                events=events
                )
        self.implicit_timestamp -= 1
        self._symbolic_memory.add(min_addr, max_addr + 1,
                                    MemoryItem(addr, obj, self.implicit_timestamp, None))
        if events:
            self.state.history.add_event('uninitialized', memory_id=self.id, addr=addr, size=1)
        return obj

    def _load(self, addr, size, condition=None, fallback=None, inspect=True, events=True, ret_on_segv=False):
        if self.state.solver.symbolic(size):
            log.warning("Concretizing symbolic length. Much sad; think about implementing.")

        # for now, we always load the maximum size
        _,max_size = resolve_size_range(self, size)
        if self.state.solver.symbolic(size):
            self.state.add_constraints(size == max_size, action=True)

        # convert size to an int
        size = self.state.solver.eval(size)

        if max_size == 0:
            self.state.history.add_event('memory_limit', message="0-length read")

        # concrete address
        if not self.state.solver.symbolic(addr):
            addr = self.state.solver.eval(addr)
            min_addr = addr
            max_addr = addr

        # symbolic addr
        else:
            min_addr = self.state.solver.min_int(addr)
            max_addr = self.state.solver.max_int(addr)
            if min_addr == max_addr:
                addr = min_addr

        # check permissions
        self.check_sigsegv_and_refine(addr, min_addr, max_addr, False)

        # check if binary data should be loaded into address space
        self._load_init_data(min_addr, (max_addr - min_addr) + size)

        read_value = None
        for k in range(size):
            P = self._concrete_memory.find(min_addr + k, max_addr + k, True)

            P += [x.data for x in self._symbolic_memory.search(min_addr + k, max_addr + k + 1)]
            P = sorted(P, key=lambda x: (x.t, (x.addr if type(x.addr) == int else 0)))

            if min_addr == max_addr and len(P) == 1 and type(P[0].addr) == int and P[0].guard is None:
                # concrete load, with only one possible memory object, so don't
                # emit an ITE
                obj = P[0].obj
            else:
                # emit an ITE for all possible memory objects
                # XXX: Checks whether an uninit read could possibly occur. It's slower but greatly reduces log spam
                extra_constraints = [
                    claripy.Not(
                        claripy.And(
                            addr + k == x.addr,
                            x.guard if x.guard is not None else claripy.BoolV(True)
                        )
                    ) for x in P
                ]
                if self.state.solver.satisfiable(extra_constraints=extra_constraints):
                    obj = self._fill_missing(addr+k, min_addr+k, max_addr+k, inspect=inspect, events=events)
                else:
                    obj = self.state.solver.BVV(DUMMY_SYMBOLIC_READ_VALUE, self.state.arch.byte_width)
                obj = self.build_merged_ite(addr + k, P, obj)
            read_value = self.state.solver.Concat(read_value, obj) if read_value is not None else obj

        if condition is not None:
            read_value = self.state.solver.If(condition, read_value, fallback)

        addrs = [ addr ] # TODO
        load_constraint = [ ] # TODO
        return addrs, read_value, load_constraint

    def build_merged_ite(self, addr, P, obj):

        #op_start_time = time.time()
        #print "Elapsed time: " + str(time.time() - op_start_time)

        N = len(P)
        merged_p = []
        for i in range(N):

            p = P[i]
            v = p.obj

            is_good_candidate = type(p.addr) == int and p.guard is None
            mergeable = False

            if len(merged_p) > 0 and is_good_candidate \
                    and p.addr == merged_p[-1].addr + 1:

                prev_v = merged_p[-1].obj
                if v.op == 'BVV':

                    # both constant and equal
                    if prev_v.op == 'BVV' and v.args[0] == prev_v.args[0]:
                        mergeable = True

                # same symbolic object
                elif v is prev_v:
                    mergeable = True

            if not mergeable:

                if len(merged_p) > 0:
                    obj = self.build_ite(addr, merged_p, merged_p[-1].obj, obj)
                    merged_p = []

                if is_good_candidate:
                    merged_p.append(p)
                else:
                    obj = self.build_ite(addr, [p], v, obj)

            else:
                merged_p.append(p)

        if len(merged_p) > 0:
            obj = self.build_ite(addr, merged_p, merged_p[-1].obj, obj)

        return obj

    def _store_one_byte(self, obj, addr, k, min_addr, max_addr, condition):
        if min_addr == max_addr:
            assert addr == min_addr
            P = self._concrete_memory[addr + k]
            if P is None or condition is None:
                self._concrete_memory[addr + k] = MemoryItem(addr + k, obj, self.timestamp,
                                                             condition)
            else:
                item = MemoryItem(addr + k, obj, self.timestamp, condition)
                if type(P) in (list,):
                    P = [item] + P
                else:
                    P = [item, P]
                self._concrete_memory[addr + k] = P
        else:
            # TODO: as in the paper, we should scan all memory objects that
            # overlap with ours, and remove any which are equivalent
            self._symbolic_memory.add(min_addr + k, max_addr + k + 1,
                                      MemoryItem(addr + k, obj, self.timestamp, condition))

    def _store_concrete_size(self, size, condition, data, addr, min_addr, max_addr):
        # fastpath
        # size is not symbolic so we don't have to chop data; MemoryItem lazily slices [data, k]
        if condition is not None:
            prev = self.load(addr, size)
        for k in range(size):
            self._store_one_byte([data, k], addr, k, min_addr, max_addr, condition)
        if condition is None:
            return [ data ]
        else:
            return [ self.state.solver.If(condition, data, prev) ]

    def _store_symbolic_size(self, size, condition, data, addr, min_addr, max_addr, min_size, max_size):
        # slowpath
        # size is symbolic and we need to data.chop() (slow)
        initial_condition = condition
        if initial_condition is None:
            initial_condition = claripy.BoolV(True)
        stored_values = [ ]
        original_value = self.load(addr, size=max_size)
        for k, a, b in zip(
            range(max_size),
            data.chop(self.state.arch.byte_width),
            original_value.chop(self.state.arch.byte_width)
        ):
            condition = claripy.BoolV(True)
            if k + 1 >= min_size:
                condition = self.state.solver.UGT(size, k)
            self._store_one_byte(a, addr, k, min_addr, max_addr, claripy.And(condition, initial_condition))
            stored_values.append(self.state.solver.If(condition, a, b))
        stored_value = claripy.Concat(*stored_values)
        return [ self.state.solver.If(initial_condition, stored_value, original_value) ]

    def _store(self, req):
        req._adjust_condition(self.state)

        size = req.size
        if size is None:
            size = req.data.length//self.state.arch.byte_width

        # store with conditional size
        conditional_size = None
        if self.state.solver.symbolic(size):
            conditional_size = [ self.state.solver.min_int(size), self.state.solver.max_int(size) ]
            self.state.solver.add(self.state.solver.ULE(size, conditional_size[1]))

        # simplify
        data = req.data
        if options.SIMPLIFY_MEMORY_WRITES in self.state.options:
            data = self.state.solver.simplify(data)

        # fix endness
        endness = self._endness if req.endness is None else req.endness
        if endness == "Iend_LE":
            data = data.reversed

        # concrete address
        if not self.state.solver.symbolic(req.addr):
            addr = self.state.solver.eval(req.addr)
            min_addr = addr
            max_addr = addr

        # symbolic addr
        else:
            min_addr = self.state.solver.min_int(req.addr)
            max_addr = self.state.solver.max_int(req.addr)
            if min_addr == max_addr:
                addr = min_addr
            else:
                addr = req.addr

        # check permissions
        self.check_sigsegv_and_refine(addr, min_addr, max_addr, True)

        # perform the store
        self.timestamp += 1
        if conditional_size is None:
            size = self.state.solver.eval(size)
            req.stored_values = self._store_concrete_size(size, req.condition, data, addr, min_addr, max_addr)
        else:
            req.stored_values = self._store_symbolic_size(size, req.condition, data, addr, min_addr, max_addr,
                                                          conditional_size[0], conditional_size[1])

        req.completed = True
        req.actual_addrs = [ addr ] # TODO
        return req

    @SimMemory.memo
    def copy(self, _):

        s = FullySymbolicMemory(memory_backer=self._memory_backer,
                                permissions_backer=self._permissions_backer,
                                arch=self._arch,
                                endness=self._endness,
                                concrete_memory=self._concrete_memory,  # we do it properly below...
                                symbolic_memory=self._symbolic_memory.copy(),
                                stack_range=self._stack_range,
                                mapped_regions=self._mapped_regions[:],
                                timestamp=self.timestamp,
                                initializable=self._initializable.copy(),
                                initialized=self._initialized,
                                timestamp_implicit=self.implicit_timestamp)

        s._concrete_memory = self._concrete_memory.copy(s)

        return s

    @property
    def mem(self):
        # In angr, this returns a reference to the (internal) paged memory
        # We do not have (yet) a paged memory. We instead return self
        # that exposes a _preapproved_stack attribute
        # (similarly as done by a paged memory)
        return self

    @property
    def _preapproved_stack(self):
        return self._stack_range

    @_preapproved_stack.setter
    def _preapproved_stack(self, value):
        if self._stack_range is not None:
            for k in range(len(self._mapped_regions)):
                region = self._mapped_regions[k]
                if region.addr == self._stack_range.start:
                    del self._mapped_regions[k]
                    break

        self._stack_range = value
        self.map_region(value.start, value.end - value.start, MappedRegion.PROT_READ | MappedRegion.PROT_WRITE)

    def map_region(self, addr, length, permissions):

        if hasattr(self.state, 'state_couner'):
            self.state.state_counter.log.append("[" + hex(self.state.regs.ip.args[0]) + "] " + "Map Region")

        if self.state.solver.symbolic(addr) or self.state.solver.symbolic(length):
            assert False

        # make if concrete
        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.solver.max_int(addr)

        # make perms a bitvector to easily check them
        if isinstance(permissions, int):
            permissions = claripy.BVV(permissions, 3)

        # keep track of this region
        self._mapped_regions.append(MappedRegion(addr, length, permissions))

        # sort mapped regions
        self._mapped_regions = sorted(self._mapped_regions, key=lambda x: x.addr)

    def unmap_region(self, addr, length):

        if self.state.solver.symbolic(addr):
            raise SimMemoryError("cannot unmap region with a symbolic address")

        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.solver.max_int(addr)

        self.timestamp += 1
        for a in range(addr, addr + length):
            self._concrete_memory[a] = MemoryItem(a, 0x0, self.timestamp, None)

        # remove from mapped regions
        for k in range(len(self._mapped_regions)):
            region = self._mapped_regions[k]
            if region.addr == addr:
                assert region.length == length
                del self._mapped_regions[k]
                break

        return

    def permissions(self, addr):
        # return permissions of the addr's region

        if self.state.solver.symbolic(addr):
            assert False

        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.solver.eval(addr)

        for region in self._mapped_regions:
            if addr >= region.addr and addr <= region.addr + region.length:
                return region.permissions

        # Unmapped region: angr treats it as RW region
        raise angr.errors.SimMemoryError("page does not exist at given address")

    def check_sigsegv_and_refine(self, addr, min_addr, max_addr, write_access):

        if angr.options.STRICT_PAGE_ACCESS not in self.state.options:
            return

        # (min_addr, max_addr) is our range addr

        access_type = "write" if write_access else "read"

        if len(self._mapped_regions) == 0:
            raise angr.errors.SimSegfaultError(min_addr, "Invalid " + access_type + " access: [" + str(
                hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

        last_covered_addr = min_addr - 1
        for region in self._mapped_regions:

            # region is after our range addr
            if max_addr < region.addr:
                break

            # region is before our range addr
            if last_covered_addr + 1 > region.addr + region.length:
                continue

            # there is one addr in our range that could be not covered by any region
            if last_covered_addr + 1 < region.addr:

                # check with the solver: is there a solution for addr?
                if self.state.solver.satisfiable(
                        extra_constraints=(addr >= last_covered_addr + 1, addr < region.addr,)):
                    raise angr.errors.SimSegfaultError(last_covered_addr + 1,
                                                        "Invalid " + access_type + " access: [" + str(
                                                            hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

            # last_covered_addr + 1 is inside this region
            # let's check for permissions

            upper_addr = min(region.addr + region.length, max_addr)
            if access_type == 'write':
                if not region.is_writable() and self.state.solver.satisfiable(
                        extra_constraints=(addr >= last_covered_addr + 1, addr <= upper_addr,)):
                    raise angr.errors.SimSegfaultError(last_covered_addr + 1,
                                                        "Invalid " + access_type + " access: [" + str(
                                                            hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

            elif access_type == 'read':
                if not region.is_readable() and self.state.solver.satisfiable(
                        extra_constraints=(addr >= last_covered_addr + 1, addr <= upper_addr,)):
                    raise angr.errors.SimSegfaultError(last_covered_addr + 1,
                                                        "Invalid " + access_type + " access: [" + str(
                                                            hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

            if max_addr > region.addr + region.length:
                last_covered_addr = region.addr + region.length
            else:
                last_covered_addr = max_addr

        # last region could not cover up to max_addr
        if last_covered_addr < max_addr:
            # we do not need to check with the solver since max_addr is already a valid solution for addr
            raise angr.errors.SimSegfaultError(last_covered_addr + 1, "Invalid " + access_type + " access: [" + str(
                hex(min_addr)) + ", " + str(hex(max_addr)) + "]")


    def merge(self, others, merge_conditions, common_ancestor=None):

        assert common_ancestor is not None
        if type(common_ancestor) in (SimStateHistory,):
            ancestor_timestamp = common_ancestor.timestamps[0]
            ancestor_implicit_timestamp = common_ancestor.timestamps[1]
        else:
            ancestor_timestamp = common_ancestor.state.history.timestamps[0]
            ancestor_implicit_timestamp = common_ancestor.state.history.timestamps[1]

        # self.state.state_counter.log.append("[" + hex(self.state.regs.ip.args[0]) + "] " + "Merge")

        assert len(merge_conditions) == 1 + len(others)
        assert len(others) == 1  # ToDo: add support for merging of multiple memories

        count = self._merge_concrete_memory(others[0], merge_conditions)
        count += self._merge_symbolic_memory(others[0], merge_conditions, ancestor_timestamp, ancestor_implicit_timestamp)

        self.timestamp = max(self.timestamp, others[0].timestamp) + 1
        self.implicit_timestamp = min(self.implicit_timestamp, others[0].implicit_timestamp)

        return count

    def _merge_concrete_memory(self, other, merge_conditions):

        assert self._stack_range == other._stack_range
        keys = lambda s: set(map(s.key, s))

        missing_self = keys(self._initializable) - keys(other._initializable)
        for index in missing_self:
            self._load_init_data(index * 0x1000, 1)

        assert len(keys(self._initializable) - keys(other._initializable)) == 0

        missing_other = keys(other._initializable) - keys(self._initializable)
        for index in missing_other:
            other._load_init_data(index * 0x1000, 1)

        assert len(keys(other._initializable) - keys(self._initializable)) == 0

        count = 0

        # basic idea:
        # get all in-use addresses among both memories
        # for each address:
        #   - if it is in use in all memories and it has the same byte content then do nothing
        #   - otherwise map the address to an ite with all the possible contents + a bottom case

        page_indexes = set(self._concrete_memory._pages.keys())
        page_indexes |= set(other._concrete_memory._pages.keys())

        # assert len(page_indexes) == 0

        for page_index in page_indexes:

            # print "merging next page..."

            page_self = self._concrete_memory._pages[
                page_index] if page_index in self._concrete_memory._pages else None
            page_other = other._concrete_memory._pages[
                page_index] if page_index in other._concrete_memory._pages else None

            # shared page? if yes, do no touch it
            if id(page_self) == id(page_other):
                continue

            offsets = set(page_self.keys()) if page_self is not None else set()
            offsets |= set(page_other.keys()) if page_other is not None else set()

            for offset in offsets:

                v_self = page_self[offset] if page_self is not None and offset in page_self else None
                v_other = page_other[offset] if page_other is not None and offset in page_other else None

                if type(v_self) not in (list,) and type(v_other) not in (list,):

                    if v_self is not None and v_other is not None:
                        assert v_self.addr == v_other.addr
                        pass

                    same_value = v_self == v_other
                else:
                    if type(v_self) != type(v_other):
                        same_value = False
                    elif len(v_self) != len(v_other):
                        same_value = False
                    else:
                        same_value = True
                        for k in range(len(v_self)):  # we only get equality when items are in the same order

                            sub_v_self = v_self[k]
                            sub_v_other = v_other[k]

                            assert type(sub_v_self) not in (list,)
                            assert type(sub_v_other) not in (list,)
                            assert sub_v_self.addr == sub_v_other.addr

                            if sub_v_self != sub_v_other:
                                same_value = False
                                break

                # self has an initialized value that is missing in other
                # we can keep as it is.
                if v_other is None and v_self is not None and type(v_self) is not (
                        list,) and v_self.t == 0 and v_self.guard is None:
                    same_value = True

                # Symmetric case. We need to insert in self.
                if v_self is None and v_other is not None and type(v_other) is not (
                        list,) and v_other.t == 0 and v_other.guard is None:
                    self._concrete_memory[page_index * 0x1000 + offset] = v_other
                    same_value = True

                if not same_value:
                    count += 1
                    merged_value = self._copy_symbolic_items_and_apply_guard(v_self, merge_conditions[0]) \
                                    + self._copy_symbolic_items_and_apply_guard(v_other, merge_conditions[1])
                    assert len(merged_value) > 0
                    self._concrete_memory[page_index * 0x1000 + offset] = merged_value if len(merged_value) > 1 else \
                        merged_value[0]

        return count

    def _copy_symbolic_items_and_apply_guard(self, L, guard):
        if L is None:
            return []
        if type(L) not in (list,):
            L = [L]
        LL = []
        for l in L:
            l = l.copy()
            l.guard = claripy.And(l.guard, guard) if l.guard is not None else guard
            LL.append(l)
        return LL

    def _merge_symbolic_memory(self, other, merge_conditions, ancestor_timestamp, ancestor_timestamp_implicit):
        # assert self.timestamp_implicit == 0
        # assert other.timestamp_implicit == 0
        # assert common_ancestor.timestamp_implicit == 0

        count = 0

        P = self._symbolic_memory.search(0, sys.maxsize)
        for p in P:
            # assert p.data.t >= 0
            if (p.data.t > 0 and p.data.t >= ancestor_timestamp) or (
                            p.data.t < 0 and p.data.t <= ancestor_timestamp_implicit):
                guard = claripy.And(p.data.guard, merge_conditions[0]) if p.data.guard is not None else \
                    merge_conditions[0]
                i = MemoryItem(p.data.addr, p.data.obj, p.data.t, guard)
                self._symbolic_memory.update_item(p, i)
                count += 1

        P = other._symbolic_memory.search(0, sys.maxsize)
        for p in P:
            # assert p.data.t >= 0
            if (p.data.t > 0 and p.data.t >= ancestor_timestamp) or (
                            p.data.t < 0 and p.data.t <= ancestor_timestamp_implicit):
                guard = claripy.And(p.data.guard, merge_conditions[1]) if p.data.guard is not None else \
                    merge_conditions[1]
                i = MemoryItem(p.data.addr, p.data.obj, p.data.t, guard)
                self._symbolic_memory.add(p.begin, p.end, i)
                count += 1

        return count

    def __contains__(self, addr):

        if isinstance(addr, int):
            addr = addr
        elif self.state.solver.symbolic(addr):
            log.warning("Currently unable to do SimMemory.__contains__ on symbolic variables.")
            return False
        else:
            addr = self.state.solver.eval(addr)

        # concrete address
        if type(addr) == int:
            min_addr = addr
            max_addr = addr

        # symbolic addr
        else:
            min_addr = self.state.solver.min_int(addr)
            max_addr = self.state.solver.max_int(addr)
            if min_addr == max_addr:
                addr = min_addr

        # check permissions
        self.check_sigsegv_and_refine(addr, min_addr, max_addr, False)

        # check if binary data should be loaded into address space
        self._load_init_data(min_addr, (max_addr - min_addr) + 1)

        P = self._concrete_memory.find(min_addr, max_addr, True)

        P += [x.data for x in self._symbolic_memory.search(min_addr, max_addr + 1)]
        P = sorted(P, key=lambda x: (x.t, (x.addr if type(x.addr) == int else 0)))

        return len(P) > 0

from angr.sim_state import SimState
SimState.register_default('fully_symbolic_memory', FullySymbolicMemory)

from .. import sim_options as options
from ..errors import SimMemoryError, SimMemoryLimitError
