import itertools
import logging
import math
import re
import string
from typing import List
from collections import defaultdict, OrderedDict

from sortedcontainers import SortedDict

import claripy
import cle
import pyvex
from cle.address_translator import AT
from archinfo.arch_soot import SootAddressDescriptor
from archinfo.arch_arm import is_arm_arch, get_real_address_if_arm

from ...knowledge_plugins.cfg import CFGNode, MemoryDataSort, MemoryData, IndirectJump
from ...knowledge_plugins.xrefs import XRef, XRefType
from ...misc.ux import deprecated
from ... import sim_options as o
from ...errors import (AngrCFGError, AngrSkipJobNotice, AngrUnsupportedSyscallError, SimEngineError, SimMemoryError,
                       SimTranslationError, SimValueError, SimOperationError, SimError, SimIRSBNoDecodeError,
                       )
from ...utils.constants import DEFAULT_STATEMENT
from ..forward_analysis import ForwardAnalysis
from .cfg_arch_options import CFGArchOptions
from .cfg_base import CFGBase
from .segment_list import SegmentList


VEX_IRSB_MAX_SIZE = 400


l = logging.getLogger(name=__name__)


class FunctionReturn:
    """
    FunctionReturn describes a function call in a specific location and its return location. Hashable and equatable
    """

    __slots__ = ('callee_func_addr', 'caller_func_addr', 'call_site_addr', 'return_to', )

    def __init__(self, callee_func_addr, caller_func_addr, call_site_addr, return_to):
        self.callee_func_addr = callee_func_addr
        self.caller_func_addr = caller_func_addr
        self.call_site_addr = call_site_addr
        self.return_to = return_to

    def __eq__(self, other):
        """
        Comparison

        :param FunctionReturn other: The other object
        :return: True if equal, False otherwise
        """
        return self.callee_func_addr == other.callee_func_addr and \
                self.caller_func_addr == other.caller_func_addr and \
                self.call_site_addr == other.call_site_addr and \
                self.return_to == other.return_to

    def __hash__(self):
        return hash((self.callee_func_addr, self.caller_func_addr, self.call_site_addr, self.return_to))


class PendingJobs:
    """
    A collection of pending jobs during CFG recovery.
    """
    def __init__(self, functions, deregister_job_callback):
        self._jobs = OrderedDict()  # A mapping between function addresses and lists of pending jobs
        self._functions = functions
        self._deregister_job_callback = deregister_job_callback

        self._returning_functions = set()
        self._updated_functions = set()  # Addresses of functions whose returning status have changed between two
                                         # consecutive calls to cleanup().
        self._job_count = 0

    def __len__(self):
        return self._job_count

    def __bool__(self):
        return self._job_count > 0
    __nonzero__ = __bool__

    def _pop_job(self, func_addr):

        jobs = self._jobs[func_addr]
        j = jobs.pop(-1)
        if not jobs:
            del self._jobs[func_addr]
        self._job_count -= 1
        return j

    def add_job(self, job):
        func_addr = job.returning_source
        if func_addr not in self._jobs:
            self._jobs[func_addr] = [ ]
        self._jobs[func_addr].append(job)
        self._job_count += 1

    def pop_job(self, returning=True):
        """
        Pop a job from the pending jobs list.

        When returning == True, we prioritize the jobs whose functions are known to be returning (function.returning is
        True). As an optimization, we are sorting the pending jobs list according to job.function.returning.

        :param bool returning: Only pop a pending job if the corresponding function returns.
        :return: A pending job if we can find one, or None if we cannot find any that satisfies the requirement.
        :rtype: angr.analyses.cfg.cfg_fast.CFGJob
        """

        if not self:
            return None

        if not returning:
            return self._pop_job(next(reversed(self._jobs.keys())))

        # Prioritize returning functions
        for func_addr in reversed(self._jobs.keys()):
            if func_addr not in self._returning_functions:
                continue
            return self._pop_job(func_addr)

        return None

    def cleanup(self):
        """
        Remove those pending exits if:
        a) they are the return exits of non-returning SimProcedures
        b) they are the return exits of non-returning syscalls
        b) they are the return exits of non-returning functions

        :return: None
        """

        pending_exits_to_remove = defaultdict(list)

        for func_addr in self._updated_functions:
            if func_addr not in self._jobs:
                continue
            jobs = self._jobs[func_addr]
            for i, pe in enumerate(jobs):
                if pe.returning_source is None:
                    # The original call failed. This pending exit must be followed.
                    continue

                func = self._functions.function(pe.returning_source)
                if func is None:
                    # Why does it happen?
                    l.warning("An expected function at %s is not found. Please report it to Fish.",
                              pe.returning_source if pe.returning_source is not None else 'None')
                    continue

                if func.returning is False:
                    # Oops, it's not returning
                    # Remove this pending exit
                    pending_exits_to_remove[pe.returning_source].append(i)

        for func_addr, indices in pending_exits_to_remove.items():
            jobs = self._jobs[func_addr]
            for index in reversed(indices):
                job = jobs[index]
                self._deregister_job_callback(job.func_addr, job)
                del jobs[index]
                self._job_count -= 1
            if not jobs:
                del self._jobs[func_addr]

        self.clear_updated_functions()

    def add_returning_function(self, func_addr):
        """
        Mark a function as returning.

        :param int func_addr: Address of the function that returns.
        :return:              None
        """

        self._returning_functions.add(func_addr)
        self._updated_functions.add(func_addr)

    def add_nonreturning_function(self, func_addr):
        """
        Mark a function as not returning.

        :param int func_addr:   Address of the function that does not return.
        :return:                None
        """

        self._updated_functions.add(func_addr)

    def clear_updated_functions(self):
        """
        Clear the updated_functions set.

        :return:    None
        """

        self._updated_functions.clear()

#
# Descriptors of edges in individual function graphs
#


class FunctionEdge:
    __slots__ = ('src_func_addr', 'stmt_idx', 'ins_addr',)

    def apply(self, cfg):
        raise NotImplementedError()


class FunctionTransitionEdge(FunctionEdge):

    __slots__ = ('src_node', 'dst_addr', 'src_func_addr', 'to_outside', 'dst_func_addr', 'is_exception', )

    def __init__(self, src_node, dst_addr, src_func_addr, to_outside=False, dst_func_addr=None, stmt_idx=None,
                 ins_addr=None, is_exception=False):
        self.src_node = src_node
        self.dst_addr = dst_addr
        self.src_func_addr = src_func_addr
        self.to_outside = to_outside
        self.dst_func_addr = dst_func_addr
        self.stmt_idx = stmt_idx
        self.ins_addr = ins_addr
        self.is_exception = is_exception

    def apply(self, cfg):
        to_outside = self.to_outside
        if not to_outside:
            # is it jumping to outside? Maybe we are seeing more functions now.
            dst_node = cfg.model.get_any_node(self.dst_addr, force_fastpath=True)
            if dst_node is not None and dst_node.function_address != self.src_func_addr:
                to_outside = True
        return cfg._function_add_transition_edge(
            self.dst_addr,
            self.src_node,
            self.src_func_addr,
            to_outside=to_outside,
            dst_func_addr=self.dst_func_addr,
            stmt_idx=self.stmt_idx,
            ins_addr=self.ins_addr,
            is_exception=self.is_exception,
        )


class FunctionCallEdge(FunctionEdge):

    __slots__ = ('src_node', 'dst_addr', 'ret_addr', 'syscall')

    def __init__(self, src_node, dst_addr, ret_addr, src_func_addr, syscall=False, stmt_idx=None, ins_addr=None):
        self.src_node = src_node
        self.dst_addr = dst_addr
        self.ret_addr = ret_addr
        self.src_func_addr = src_func_addr
        self.syscall = syscall
        self.stmt_idx = stmt_idx
        self.ins_addr = ins_addr

    def apply(self, cfg):
        return cfg._function_add_call_edge(
            self.dst_addr,
            self.src_node,
            self.src_func_addr,
            syscall=self.syscall,
            stmt_idx=self.stmt_idx,
            ins_addr=self.ins_addr,
        )


class FunctionFakeRetEdge(FunctionEdge):

    __slots__ = ('src_node', 'dst_addr', 'confirmed')

    def __init__(self, src_node, dst_addr, src_func_addr, confirmed=None):
        self.src_node = src_node
        self.dst_addr = dst_addr
        self.src_func_addr = src_func_addr
        self.confirmed = confirmed

    def apply(self, cfg):
        return cfg._function_add_fakeret_edge(
            self.dst_addr,
            self.src_node,
            self.src_func_addr,
            confirmed=self.confirmed,
        )


class FunctionReturnEdge(FunctionEdge):

    __slots__ = ('ret_from_addr', 'ret_to_addr', 'dst_func_addr')

    def __init__(self, ret_from_addr, ret_to_addr, dst_func_addr):
        self.ret_from_addr = ret_from_addr
        self.ret_to_addr = ret_to_addr
        self.dst_func_addr = dst_func_addr

    def apply(self, cfg):
        return cfg._function_add_return_edge(
            self.ret_from_addr,
            self.ret_to_addr,
            self.dst_func_addr
        )


#
# CFGJob
#


class CFGJob:
    """
    Defines a job to work on during the CFG recovery
    """

    __slots__ = ('addr', 'func_addr', 'jumpkind', 'ret_target', 'last_addr', 'src_node', 'src_ins_addr', 'src_stmt_idx',
                 'returning_source', 'syscall', '_func_edges', 'job_type')

    JOB_TYPE_NORMAL = "Normal"
    JOB_TYPE_FUNCTION_PROLOGUE = "Function-prologue"
    JOB_TYPE_COMPLETE_SCANNING = "Complete-scanning"

    def __init__(self, addr, func_addr, jumpkind, ret_target=None, last_addr=None, src_node=None, src_ins_addr=None,
                 src_stmt_idx=None, returning_source=None, syscall=False, func_edges=None, job_type=JOB_TYPE_NORMAL):
        self.addr = addr
        self.func_addr = func_addr
        self.jumpkind = jumpkind
        self.ret_target = ret_target
        self.last_addr = last_addr
        self.src_node = src_node
        self.src_ins_addr = src_ins_addr
        self.src_stmt_idx = src_stmt_idx
        self.returning_source = returning_source
        self.syscall = syscall
        self.job_type = job_type

        self._func_edges = func_edges

    def add_function_edge(self, edge):

        if self._func_edges is None:
            self._func_edges = [ ]
        self._func_edges.append(edge)

    def apply_function_edges(self, cfg, clear=False):
        if not self._func_edges:
            return
        for edge in self._func_edges:
            edge.apply(cfg)
        if clear:
            self._func_edges = None

    def __repr__(self):
        if isinstance(self.addr, SootAddressDescriptor):
            return "<CFGJob {}>".format(self.addr)
        else:
            return "<CFGJob%s %#08x @ func %#08x>" % (" syscall" if self.syscall else "", self.addr, self.func_addr)

    def __eq__(self, other):
        return self.addr == other.addr and \
                self.func_addr == other.func_addr and \
                self.jumpkind == other.jumpkind and \
                self.ret_target == other.ret_target and \
                self.last_addr == other.last_addr and \
                self.src_node == other.src_node and \
                self.src_stmt_idx == other.src_stmt_idx and \
                self.src_ins_addr == other.src_ins_addr and \
                self.returning_source == other.returning_source and \
                self.syscall == other.syscall

    def __hash__(self):
        return hash((self.addr, self.func_addr, self.jumpkind, self.ret_target, self.last_addr, self.src_node,
                     self.src_stmt_idx, self.src_ins_addr, self.returning_source, self.syscall)
                    )


class CFGFast(ForwardAnalysis, CFGBase):    # pylint: disable=abstract-method
    """
    We find functions inside the given binary, and build a control-flow graph in very fast manners: instead of
    simulating program executions, keeping track of states, and performing expensive data-flow analysis, CFGFast will
    only perform light-weight analyses combined with some heuristics, and with some strong assumptions.

    In order to identify as many functions as possible, and as accurate as possible, the following operation sequence
    is followed:

    # Active scanning

        - If the binary has "function symbols" (TODO: this term is not accurate enough), they are starting points of
          the code scanning
        - If the binary does not have any "function symbol", we will first perform a function prologue scanning on the
          entire binary, and start from those places that look like function beginnings
        - Otherwise, the binary's entry point will be the starting point for scanning

    # Passive scanning

        - After all active scans are done, we will go through the whole image and scan all code pieces

    Due to the nature of those techniques that are used here, a base address is often not required to use this analysis
    routine. However, with a correct base address, CFG recovery will almost always yield a much better result. A custom
    analysis, called GirlScout, is specifically made to recover the base address of a binary blob. After the base
    address is determined, you may want to reload the binary with the new base address by creating a new Project object,
    and then re-recover the CFG.
    """

    # TODO: Move arch_options to CFGBase, and add those logic to CFGEmulated as well.

    PRINTABLES = string.printable.replace("\x0b", "").replace("\x0c", "").encode()
    SPECIAL_THUNKS = {
        'AMD64': {
            bytes.fromhex('E807000000F3900FAEE8EBF9488D642408C3'): ('ret',),
            bytes.fromhex('E807000000F3900FAEE8EBF948890424C3'): ('jmp', 'rax'),
        }
    }

    tag = "CFGFast"

    def __init__(self,
                 binary=None,
                 objects=None,
                 regions=None,
                 pickle_intermediate_results=False,
                 symbols=True,
                 function_prologues=True,
                 resolve_indirect_jumps=True,
                 force_segment=False,
                 force_complete_scan=True,
                 indirect_jump_target_limit=100000,
                 data_references=False,
                 cross_references=False,
                 normalize=False,
                 start_at_entry=True,
                 function_starts=None,
                 extra_memory_regions=None,
                 data_type_guessing_handlers=None,
                 arch_options=None,
                 indirect_jump_resolvers=None,
                 base_state=None,
                 exclude_sparse_regions=True,
                 skip_specific_regions=True,
                 heuristic_plt_resolving=None,
                 detect_tail_calls=False,
                 low_priority=False,
                 cfb=None,
                 model=None,
                 use_patches=False,
                 elf_eh_frame=True,
                 exceptions=True,
                 start=None,  # deprecated
                 end=None,  # deprecated
                 collect_data_references=None, # deprecated
                 extra_cross_references=None, # deprecated
                 **extra_arch_options
                 ):
        """
        :param binary:                  The binary to recover CFG on. By default the main binary is used.
        :param objects:                 A list of objects to recover the CFG on. By default it will recover the CFG of
                                        all loaded objects.
        :param iterable regions:        A list of tuples in the form of (start address, end address) describing memory
                                        regions that the CFG should cover.
        :param bool pickle_intermediate_results: If we want to store the intermediate results or not.
        :param bool symbols:            Get function beginnings from symbols in the binary.
        :param bool function_prologues: Scan the binary for function prologues, and use those positions as function
                                        beginnings
        :param bool resolve_indirect_jumps: Try to resolve indirect jumps. This is necessary to resolve jump targets
                                            from jump tables, etc.
        :param bool force_segment:      Force CFGFast to rely on binary segments instead of sections.
        :param bool force_complete_scan:    Perform a complete scan on the binary and maximize the number of identified
                                            code blocks.
        :param bool data_references:    Enables the collection of references to data used by individual instructions.
                                        This does not collect 'cross-references', particularly those that involve
                                        multiple instructions.  For that, see `cross_references`
        :param bool cross_references:   Whether CFGFast should collect "cross-references" from the entire program or
                                        not. This will populate the knowledge base with references to and from each
                                        recognizable address constant found in the code. Note that, because this
                                        performs constant propagation on the entire program, it may be much slower and
                                        consume more memory.
                                        This option implies `data_references=True`.
        :param bool normalize:          Normalize the CFG as well as all function graphs after CFG recovery.
        :param bool start_at_entry:     Begin CFG recovery at the entry point of this project. Setting it to False
                                        prevents CFGFast from viewing the entry point as one of the starting points of
                                        code scanning.
        :param list function_starts:    A list of extra function starting points. CFGFast will try to resume scanning
                                        from each address in the list.
        :param list extra_memory_regions: A list of 2-tuple (start-address, end-address) that shows extra memory
                                          regions. Integers falling inside will be considered as pointers.
        :param list indirect_jump_resolvers: A custom list of indirect jump resolvers. If this list is None or empty,
                                             default indirect jump resolvers specific to this architecture and binary
                                             types will be loaded.
        :param base_state:              A state to use as a backer for all memory loads
        :param bool detect_tail_calls:  Enable aggressive tail-call optimization detection.
        :param bool elf_eh_frame:       Retrieve function starts (and maybe sizes later) from the .eh_frame of ELF
                                        binaries.
        :param int start:               (Deprecated) The beginning address of CFG recovery.
        :param int end:                 (Deprecated) The end address of CFG recovery.
        :param CFGArchOptions arch_options: Architecture-specific options.
        :param dict extra_arch_options: Any key-value pair in kwargs will be seen as an arch-specific option and will
                                        be used to set the option value in self._arch_options.

        Extra parameters that angr.Analysis takes:

        :param progress_callback:       Specify a callback function to get the progress during CFG recovery.
        :param bool show_progressbar:   Should CFGFast show a progressbar during CFG recovery or not.
        :return: None
        """

        ForwardAnalysis.__init__(self, allow_merging=False)
        CFGBase.__init__(
            self,
            'fast',
            0,
            normalize=normalize,
            binary=binary,
            force_segment=force_segment,
            base_state=base_state,
            resolve_indirect_jumps=resolve_indirect_jumps,
            indirect_jump_resolvers=indirect_jump_resolvers,
            indirect_jump_target_limit=indirect_jump_target_limit,
            detect_tail_calls=detect_tail_calls,
            low_priority=low_priority,
            model=model,
        )

        # necessary warnings
        regions_not_specified = regions is None and binary is None and not objects
        if self.project.loader._auto_load_libs is True and end is None and len(self.project.loader.all_objects) > 3 \
                and regions_not_specified:
            l.warning('"auto_load_libs" is enabled. With libraries loaded in project, CFGFast will cover libraries, '
                      'which may take significantly more time than expected. You may reload the binary with '
                      '"auto_load_libs" disabled, or specify "regions" to limit the scope of CFG recovery.'
                      )

        if collect_data_references is not None:
            l.warning('"collect_data_references" is deprecated and will be removed soon. Please use '
                      '"data_references" instead')
            data_references = collect_data_references
        if extra_cross_references is not None:
            l.warning('"extra_cross_references" is deprecated and will be removed soon. Please use '
                      '"cross_references" instead')
            cross_references = extra_cross_references

        if start is not None or end is not None:
            l.warning('"start" and "end" are deprecated and will be removed soon. Please use "regions" to specify one '
                      'or more memory regions instead.'
                      )
            if regions is None:
                regions = [ (start, end) ]
            else:
                l.warning('"regions", "start", and "end" are all specified. Ignoring "start" and "end".')

        if binary is not None and not objects:
            objects = [ binary ]
        regions = regions if regions is not None else self._executable_memory_regions(objects=objects,
                                                                                      force_segment=force_segment
                                                                                      )

        if exclude_sparse_regions:
            new_regions = [ ]
            for start_, end_ in regions:
                if not self._is_region_extremely_sparse(start_, end_, base_state=base_state):
                    new_regions.append((start_, end_))
            regions = new_regions
        if skip_specific_regions:
            if base_state is not None:
                l.warning("You specified both base_state and skip_specific_regions. They may conflict with each other.")
            new_regions = [ ]
            for start_, end_ in regions:
                if not self._should_skip_region(start_):
                    new_regions.append((start_, end_))
            regions = new_regions
        if not regions and self.project.arch.name != 'Soot':
            raise AngrCFGError("Regions are empty or all regions are skipped. You may want to manually specify regions.")
        # sort the regions
        regions = sorted(regions, key=lambda x: x[0])
        self._regions_size = sum((b - a) for a, b in regions)
        # initial self._regions as a sorted dict
        self._regions = SortedDict(regions)

        self._pickle_intermediate_results = pickle_intermediate_results

        self._use_symbols = symbols
        self._use_function_prologues = function_prologues
        self._force_complete_scan = force_complete_scan
        self._use_elf_eh_frame = elf_eh_frame
        self._use_exceptions = exceptions

        if heuristic_plt_resolving is None:
            # If unspecified, we only enable heuristic PLT resolving when there is at least one binary loaded with the
            # ELF backend
            self._heuristic_plt_resolving = len(self.project.loader.all_elf_objects) > 0
        else:
            self._heuristic_plt_resolving = heuristic_plt_resolving

        self._start_at_entry = start_at_entry
        self._extra_function_starts = function_starts

        self._extra_memory_regions = extra_memory_regions

        self._cross_references = cross_references
        # You need data refs to get cross refs
        self._collect_data_ref = data_references or self._cross_references

        self._use_patches = use_patches

        self._arch_options = arch_options if arch_options is not None else CFGArchOptions(
                self.project.arch, **extra_arch_options)

        self._data_type_guessing_handlers = [ ] if data_type_guessing_handlers is None else data_type_guessing_handlers

        self._cfb = cfb

        l.debug("CFG recovery covers %d regions:", len(self._regions))
        for start_addr in self._regions:
            l.debug("... %#x - %#x", start_addr, self._regions[start_addr])

        # mapping to all known thunks
        self._known_thunks = {}

        self._initial_state = None
        self._next_addr = None

        # Create the segment list
        self._seg_list = SegmentList()

        self._read_addr_to_run = defaultdict(list)
        self._write_addr_to_run = defaultdict(list)

        self._function_prologue_addrs = None
        self._remaining_function_prologue_addrs = None

        # exception handling
        self._exception_handling_by_endaddr = SortedDict()

        #
        # Variables used during analysis
        #
        self._pending_jobs = None
        self._traced_addresses = None
        self._function_returns = None
        self._function_exits = None

        # A mapping between address and the actual data in memory
        # self._memory_data = { }
        # A mapping between address of the instruction that's referencing the memory data and the memory data itself
        # self.insn_addr_to_memory_data = { }
        # self._graph = None

        # Start working!
        self._analyze()

    def __getstate__(self):
        d = dict(self.__dict__)
        d['_progress_callback'] = None
        return d

    def __setstate__(self, d):
        self.__dict__.update(d)

    #
    # Utils
    #

    @staticmethod
    def _calc_entropy(data, size=None):
        """
        Calculate the entropy of a piece of data

        :param data: The target data to calculate entropy on
        :param size: Size of the data, Optional.
        :return: A float
        """

        if not data:
            return 0
        entropy = 0
        if size is None:
            size = len(data)

        data = bytes(pyvex.ffi.buffer(data, size))
        for x in range(0, 256):
            p_x = float(data.count(x)) / size
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    #
    # Properties
    #

    @property
    def graph(self):
        return self._model.graph

    @property
    def _insn_addr_to_memory_data(self):
        l.warning('_insn_addr_to_memory_data has been made public and is deprecated. Please fix your code accordingly.')
        return self._model.insn_addr_to_memory_data

    @property
    def _memory_data(self):
        return self._model.memory_data

    @property
    def memory_data(self):
        return self._model.memory_data

    @property
    def jump_tables(self):
        return self._model.jump_tables

    @property
    def insn_addr_to_memory_data(self):
        return self._model.insn_addr_to_memory_data

    #
    # Private methods
    #

    # Methods for determining scanning scope

    def _inside_regions(self, address):
        """
        Check if the address is inside any existing region.

        :param int address: Address to check.
        :return:            True if the address is within one of the memory regions, False otherwise.
        :rtype:             bool
        """

        try:
            start_addr = next(self._regions.irange(maximum=address, reverse=True))
        except StopIteration:
            return False
        else:
            return address < self._regions[start_addr]

    def _get_min_addr(self):
        """
        Get the minimum address out of all regions. We assume self._regions is sorted.

        :return: The minimum address.
        :rtype:  int
        """

        if not self._regions:
            if self.project.arch.name != "Soot":
                l.error("self._regions is empty or not properly set.")
            return None

        return next(self._regions.irange())

    def _next_address_in_regions(self, address):
        """
        Return the next immediate address that is inside any of the regions.

        :param int address: The address to start scanning.
        :return:            The next address that is inside one of the memory regions.
        :rtype:             int
        """

        if self._inside_regions(address):
            return address

        try:
            return next(self._regions.irange(minimum=address, reverse=False))
        except StopIteration:
            return None

    # Methods for scanning the entire image

    def _next_unscanned_addr(self, alignment=None):
        """
        Find the next address that we haven't processed

        :param alignment: Assures the address returns must be aligned by this number
        :return: An address to process next, or None if all addresses have been processed
        """

        # TODO: Take care of those functions that are already generated
        if self._next_addr is None:
            self._next_addr = self._get_min_addr()
            curr_addr = self._next_addr
        else:
            curr_addr = self._next_addr + 1

        if not self._inside_regions(curr_addr):
            curr_addr = self._next_address_in_regions(curr_addr)

        if curr_addr is None:
            l.debug("All addresses within memory regions have been scanned.")
            return None

        if self._seg_list.has_blocks:
            curr_addr = self._seg_list.next_free_pos(curr_addr)

        if alignment is not None:
            if curr_addr % alignment > 0:
                curr_addr = curr_addr - (curr_addr % alignment) + alignment

        # Make sure curr_addr exists in binary
        accepted = False
        for start, end in self._regions.items():
            if start <= curr_addr < end:
                # accept
                accepted = True
                break
            if curr_addr < start:
                # accept, but we are skipping the gap
                accepted = True
                curr_addr = start
                break

        if not accepted:
            # No memory available!
            return None

        self._next_addr = curr_addr
        if self._inside_regions(curr_addr):
            l.debug("Returning a new recon address: %#x", curr_addr)
            return curr_addr

        l.debug("%#x is beyond the ending point. Returning None.", curr_addr)
        return None

    def _load_a_byte_as_int(self, addr):
        if self._base_state is not None:
            try:
                val = self._base_state.mem_concrete(addr, 1, inspect=False, disable_actions=True)
            except SimValueError:
                # Not concretizable
                l.debug("Address %#x is not concretizable!", addr)
                return None
        else:
            val = self._fast_memory_load_byte(addr)
            if val is None:
                return None
        return val

    def _scan_for_printable_strings(self, start_addr):
        addr = start_addr
        sz = []
        is_sz = True

        # Get data until we meet a null-byte
        while self._inside_regions(addr):
            l.debug("Searching address %x", addr)
            val = self._load_a_byte_as_int(addr)
            if val is None:
                break
            if val == 0:
                if len(sz) < 4:
                    is_sz = False
                break
            if val not in self.PRINTABLES:
                is_sz = False
                break
            sz.append(val)
            addr += 1

        if sz and is_sz:
            l.debug("Got a string of %d chars: [%s]", len(sz), bytes(sz).decode())
            string_length = len(sz) + 1
            return string_length

        # no string is found
        return 0

    def _scan_for_repeating_bytes(self, start_addr, repeating_byte, threshold=2):
        """
        Scan from a given address and determine the occurrences of a given byte.

        :param int start_addr:      The address in memory to start scanning.
        :param int repeating_byte:  The repeating byte to scan for.
        :param int threshold:  The minimum occurrences.
        :return:                    The occurrences of a given byte.
        :rtype:                     int
        """

        addr = start_addr

        repeating_length = 0

        while self._inside_regions(addr):
            val = self._load_a_byte_as_int(addr)
            if val is None:
                break
            if val == repeating_byte:
                repeating_length += 1
            else:
                break
            addr += 1

        if repeating_length >= threshold:
            return repeating_length
        else:
            return 0

    def _next_code_addr_core(self):
        """
        Call _next_unscanned_addr() first to get the next address that is not scanned. Then check if data locates at
        that address seems to be code or not. If not, we'll continue to for the next un-scanned address.
        """

        next_addr = self._next_unscanned_addr()
        if next_addr is None:
            return None

        start_addr = next_addr

        while True:
            string_length = self._scan_for_printable_strings(start_addr)
            if string_length:
                self._seg_list.occupy(start_addr, string_length, "string")
                start_addr += string_length

            if self.project.arch.name in ('X86', 'AMD64'):
                cc_length = self._scan_for_repeating_bytes(start_addr, 0xcc, threshold=1)
                if cc_length:
                    self._seg_list.occupy(start_addr, cc_length, "alignment")
                    start_addr += cc_length
            else:
                cc_length = 0

            zeros_length = self._scan_for_repeating_bytes(start_addr, 0x00)
            if zeros_length:
                self._seg_list.occupy(start_addr, zeros_length, "alignment")
                start_addr += zeros_length

            if string_length == 0 and cc_length == 0 and zeros_length == 0:
                # umm now it's probably code
                break

        instr_alignment = self._initial_state.arch.instruction_alignment
        if start_addr % instr_alignment > 0:
            # occupy those few bytes
            self._seg_list.occupy(start_addr, instr_alignment - (start_addr % instr_alignment), 'alignment')
            start_addr = start_addr - start_addr % instr_alignment + \
                         instr_alignment

        return start_addr

    def _next_code_addr(self):

        while True:
            addr = self._next_code_addr_core()
            if addr is None:
                return None

            # if the new address is already occupied
            if not self._seg_list.is_occupied(addr):
                return addr

    # Overriden methods from ForwardAnalysis

    def _job_key(self, job):
        return job.addr

    def _pre_analysis(self):

        # Call _initialize_cfg() before self.functions is used.
        self._initialize_cfg()

        # Scan for __x86_return_thunk and friends
        self._known_thunks = self._find_thunks()

        # Initialize variables used during analysis
        self._pending_jobs = PendingJobs(self.functions, self._deregister_analysis_job)
        self._traced_addresses = set()
        self._function_returns = defaultdict(set)

        # Sadly, not all calls to functions are explicitly made by call
        # instruction - they could be a jmp or b, or something else. So we
        # should record all exits from a single function, and then add
        # necessary calling edges in our call map during the post-processing
        # phase.
        self._function_exits = defaultdict(set)

        # Create an initial state. Store it to self so we can use it globally.
        self._initial_state = self.project.factory.blank_state(mode="fastpath")
        initial_options = self._initial_state.options - {o.TRACK_CONSTRAINTS} - o.refs
        initial_options |= {o.SUPER_FASTPATH, o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS, o.SYMBOL_FILL_UNCONSTRAINED_MEMORY}
        # initial_options.remove(o.COW_STATES)
        self._initial_state.options = initial_options

        # Process known exception handlings
        if self._use_exceptions:
            self._preprocess_exception_handlings()

        starting_points = set()

        # clear all existing functions
        self.kb.functions.clear()

        if self._use_symbols:
            starting_points |= self._function_addresses_from_symbols

        if self._use_elf_eh_frame:
            starting_points |= self._function_addresses_from_eh_frame

        if self._extra_function_starts:
            starting_points |= set(self._extra_function_starts)

        # Sort it
        starting_points = sorted(list(starting_points), reverse=True)

        if self._start_at_entry and self.project.entry is not None and self._inside_regions(self.project.entry) and \
                self.project.entry not in starting_points:
            # make sure self.project.entry is inserted
            starting_points = [ self.project.entry ] + starting_points

        # Create jobs for all starting points
        for sp in starting_points:
            job = CFGJob(sp, sp, 'Ijk_Boring')
            self._insert_job(job)
            # register the job to function `sp`
            self._register_analysis_job(sp, job)

        self._updated_nonreturning_functions = set()

        if self._use_function_prologues and self.project.concrete_target is None:
            self._function_prologue_addrs = sorted(self._func_addrs_from_prologues())
            # make a copy of those prologue addresses, so that we can pop from the list
            self._remaining_function_prologue_addrs = self._function_prologue_addrs[::]

            # make function_prologue_addrs a set for faster lookups
            self._function_prologue_addrs = set(self._function_prologue_addrs)

    def _pre_job_handling(self, job):  # pylint:disable=arguments-differ
        """
        Some pre job-processing tasks, like update progress bar.

        :param CFGJob job: The CFGJob instance.
        :return: None
        """

        if self._low_priority:
            self._release_gil(len(self._nodes), 20, 0.0001)

        # a new entry is picked. Deregister it
        self._deregister_analysis_job(job.func_addr, job)

        if not self._inside_regions(job.addr):
            obj = self.project.loader.find_object_containing(job.addr)
            if obj is not None and isinstance(obj, self._cle_pseudo_objects):
                pass
            else:
                # it's outside permitted regions. skip.
                raise AngrSkipJobNotice()

        # Do not calculate progress if the user doesn't care about the progress at all
        if self._show_progressbar or self._progress_callback:
            max_percentage_stage_1 = 50.0
            percentage = self._seg_list.occupied_size * max_percentage_stage_1 / self._regions_size
            if percentage > max_percentage_stage_1:
                percentage = max_percentage_stage_1

            self._update_progress(percentage, cfg=self)

    def _intra_analysis(self):
        pass

    def _get_successors(self, job):  # pylint:disable=arguments-differ

        # current_function_addr = job.func_addr
        # addr = job.addr

        # if current_function_addr != -1:
        #    l.debug("Tracing new exit %#x in function %#x", addr, current_function_addr)
        # else:
        #    l.debug("Tracing new exit %#x", addr)

        jobs = self._scan_block(job)

        # l.debug("... got %d jobs: %s", len(jobs), jobs)

        for job_ in jobs:  # type: CFGJob
            # register those jobs
            self._register_analysis_job(job_.func_addr, job_)

        return jobs

    def _handle_successor(self, job, successor, successors):
        return [ successor ]

    def _merge_jobs(self, *jobs):
        pass

    def _widen_jobs(self, *jobs):
        pass

    def _post_process_successors(self, irsb, successors):

        if is_arm_arch(self.project.arch):
            if irsb.addr % 2 == 1:
                # we are in thumb mode. filter successors
                successors = self._arm_thumb_filter_jump_successors(irsb,
                                                                    successors,
                                                                    lambda tpl: tpl[1],
                                                                    lambda tpl: tpl[0],
                                                                    lambda tpl: tpl[3],
                                                                    )

        return successors

    def _post_job_handling(self, job, new_jobs, successors):
        pass

    def _job_queue_empty(self):

        if self._pending_jobs:
            # fastpath
            # look for a job that comes from a function that must return
            # if we can find one, just use it
            job = self._pop_pending_job(returning=True)
            if job is not None:
                self._insert_job(job)
                return

            self._clean_pending_exits()

        # did we finish analyzing any function?
        # fill in self._completed_functions
        self._make_completed_functions()

        # analyze function features, most importantly, whether each function returns or not
        self._analyze_all_function_features()

        # Clear _changed_functions set
        self._updated_nonreturning_functions = set()

        if self._pending_jobs:
            self._clean_pending_exits()

            job = self._pop_pending_job(returning=True)
            if job is not None:
                self._insert_job(job)
                return

        # Try to see if there is any indirect jump left to be resolved
        # it's possible that certain indirect jumps must be resolved before the returning status of a function can be
        # determined. e.g., in AArch64
        # __stubs:00000001000064B0 ___stack_chk_fail
        # __stubs:00000001000064B0                 NOP
        # __stubs:00000001000064B4                 LDR             X16, =__imp____stack_chk_fail
        # __stubs:00000001000064B8                 BR              X16
        #
        # we need to rely on indirect jump resolving to identify this call to stack_chk_fail before knowing that
        # function 0x100006480 does not return. Hence, we resolve indirect jumps before popping undecided pending jobs.
        if self._resolve_indirect_jumps and self._indirect_jumps_to_resolve:
            self._process_unresolved_indirect_jumps()

            if self._job_info_queue:
                return

        if self._pending_jobs:
            job = self._pop_pending_job(returning=False)
            if job is not None:
                self._insert_job(job)
                return

        if self._use_function_prologues and self._remaining_function_prologue_addrs:
            while self._remaining_function_prologue_addrs:
                prolog_addr = self._remaining_function_prologue_addrs[0]
                self._remaining_function_prologue_addrs = self._remaining_function_prologue_addrs[1:]
                if self._seg_list.is_occupied(prolog_addr):
                    continue

                job = CFGJob(prolog_addr, prolog_addr, 'Ijk_Boring')
                self._insert_job(job)
                self._register_analysis_job(prolog_addr, job)
                return

        if self._force_complete_scan:
            addr = self._next_code_addr()
            if addr is None:
                l.debug("Force-scan jumping failed")
            else:
                l.debug("Force-scanning to %#x", addr)

            if addr is not None:
                # if this is ARM and addr % 4 != 0, it has to be THUMB
                if is_arm_arch(self.project.arch):
                    if addr % 2 == 0 and addr % 4 != 0:
                        addr |= 1
                    else:
                        # load 8 bytes and test with THUMB-mode prologues
                        bytes_prefix = self._fast_memory_load_bytes(addr, 8)
                        if any(re.match(prolog, bytes_prefix) for prolog in self.project.arch.thumb_prologs):
                            addr |= 1
                job = CFGJob(addr, addr, "Ijk_Boring", last_addr=None, job_type=CFGJob.JOB_TYPE_COMPLETE_SCANNING)
                self._insert_job(job)
                self._register_analysis_job(addr, job)

    def _post_analysis(self):

        self._make_completed_functions()

        if self._normalize:
            # Normalize the control flow graph first before rediscovering all functions
            self.normalize()

        if self.project.arch.name in ('X86', 'AMD64', 'MIPS32'):
            self._remove_redundant_overlapping_blocks()

        self._updated_nonreturning_functions = set()
        # Revisit all edges and rebuild all functions to correctly handle returning/non-returning functions.
        self.make_functions()

        self._analyze_all_function_features(all_funcs_completed=True)

        # Scan all functions, and make sure all fake ret edges are either confirmed or removed
        for f in self.functions.values():
            all_edges = f.transition_graph.edges(data=True)

            callsites_to_functions = defaultdict(list) # callsites to functions mapping

            for src, dst, data in all_edges:
                if 'type' in data:
                    if data['type'] == 'call':
                        callsites_to_functions[src.addr].append(dst.addr)

            edges_to_remove = [ ]
            for src, dst, data in all_edges:
                if 'type' in data:
                    if data['type'] == 'fake_return' and 'confirmed' not in data:

                        # Get all possible functions being called here
                        target_funcs = [ self.functions.function(addr=func_addr)
                                         for func_addr in callsites_to_functions[src.addr]
                                         ]
                        if target_funcs and all(t is not None and t.returning is False for t in target_funcs):
                            # Remove this edge
                            edges_to_remove.append((src, dst))
                        else:
                            # Mark this edge as confirmed
                            f._confirm_fakeret(src, dst)

            for edge in edges_to_remove:
                f.transition_graph.remove_edge(*edge)

            # Clear the cache
            f._local_transition_graph = None

        # Scan all functions, and make sure .returning for all functions are either True or False
        for f in self.functions.values():
            if f.returning is None:
                f.returning = len(f.endpoints) > 0  # pylint:disable=len-as-condition

        # Finally, mark endpoints of every single function
        for function in self.kb.functions.values():
            function.mark_nonreturning_calls_endpoints()

        # optional: remove functions that must be alignments
        self.mark_function_alignments()

        # make return edges
        self._make_return_edges()

        if self.project.arch.name != 'Soot':
            if self.project.loader.main_object.sections:
                # this binary has sections
                # make sure we have data entries assigned at the beginning of each data section
                for sec in self.project.loader.main_object.sections:
                    if sec.memsize > 0 and not sec.is_executable and sec.is_readable:
                        for seg in self.project.loader.main_object.segments:
                            if seg.vaddr <= sec.vaddr < seg.vaddr + seg.memsize:
                                break
                        else:
                            continue

                        if sec.vaddr not in self.model.memory_data:
                            self.model.memory_data[sec.vaddr] = MemoryData(sec.vaddr, 0, MemoryDataSort.Unknown)

        # If they asked for it, give it to them.  All of it.
        if self._cross_references:
            self.do_full_xrefs()

        r = True
        while r:
            r = self._tidy_data_references()

        CFGBase._post_analysis(self)

        self._finish_progress()

    def do_full_xrefs(self, overlay_state=None):
        """
        Perform xref recovery on all functions.

        :param SimState overlay:    An overlay state for loading constant data.
        :return:                    None
        """

        l.info("Building cross-references...")
        # Time to make our CPU hurt
        state = self.project.factory.blank_state() if overlay_state is None else overlay_state
        for f_addr in self.functions:
            f = None
            try:
                f = self.functions[f_addr]
                if f.is_simprocedure:
                    continue
                l.debug("\tFunction %s", f.name)
                # constant prop
                prop = self.project.analyses.Propagator(func=f, base_state=state)
                # Collect all the refs
                self.project.analyses.XRefs(func=f, replacements=prop.replacements)
            except Exception:  # pylint: disable=broad-except
                if f is not None:
                    l.exception("Error collecting XRefs for function %s.", f.name, exc_info=True)
                else:
                    l.exception("Error collecting XRefs for function %#x.", f_addr, exc_info=True)

    # Methods to get start points for scanning

    def _func_addrs_from_prologues(self):
        """
        Scan the entire program image for function prologues, and start code scanning at those positions

        :return: A list of possible function addresses
        """

        # Pre-compile all regexes
        regexes = list()
        for ins_regex in self.project.arch.function_prologs:
            r = re.compile(ins_regex)
            regexes.append(r)
        # EDG says: I challenge anyone bothering to read this to come up with a better
        # way to handle CPU modes that affect instruction decoding.
        # Since the only one we care about is ARM/Thumb right now
        # we have this gross hack. Sorry about that.
        thumb_regexes = list()
        if hasattr(self.project.arch, 'thumb_prologs'):
            for ins_regex in self.project.arch.thumb_prologs:
                # Thumb prologues are found at even addrs, but their actual addr is odd!
                # Isn't that great?
                r = re.compile(ins_regex)
                thumb_regexes.append(r)

        # Construct the binary blob first
        unassured_functions = [ ]

        for start_, bytes_ in self._binary.memory.backers():
            for regex in regexes:
                # Match them!
                for mo in regex.finditer(bytes_):
                    position = mo.start() + start_
                    if position % self.project.arch.instruction_alignment == 0:
                        mapped_position = AT.from_rva(position, self._binary).to_mva()
                        if self._addr_in_exec_memory_regions(mapped_position):
                            unassured_functions.append(mapped_position)
            # HACK part 2: Yes, i really have to do this
            for regex in thumb_regexes:
                # Match them!
                for mo in regex.finditer(bytes_):
                    position = mo.start() + start_
                    if position % self.project.arch.instruction_alignment == 0:
                        mapped_position = AT.from_rva(position, self._binary).to_mva()
                        if self._addr_in_exec_memory_regions(mapped_position):
                            unassured_functions.append(mapped_position+1)

        l.info("Found %d functions with prologue scanning.", len(unassured_functions))
        return unassured_functions

    # Basic block scanning

    def _scan_block(self, cfg_job):
        """
        Scan a basic block starting at a specific address

        :param CFGJob cfg_job: The CFGJob instance.
        :return: a list of successors
        :rtype: list
        """

        addr = cfg_job.addr
        current_func_addr = cfg_job.func_addr

        # Fix the function address
        # This is for rare cases where we cannot successfully determine the end boundary of a previous function, and
        # as a consequence, our analysis mistakenly thinks the previous function goes all the way across the boundary,
        # resulting the missing of the second function in function manager.
        if addr in self._function_addresses_from_symbols:
            current_func_addr = addr

        if self._addr_hooked_or_syscall(addr):
            entries = self._scan_procedure(cfg_job, current_func_addr)

        else:
            entries = self._scan_irsb(cfg_job, current_func_addr)

        return entries

    def _scan_procedure(self, cfg_job, current_func_addr):
        """
        Checks the hooking procedure for this address searching for new static
        exit points to add to successors (generating entries for them)
        if this address has not been traced before. Updates previous CFG nodes
        with edges.

        :param CFGJob cfg_job:      The CFGJob instance.
        :param int current_func_addr: Address of the current function.
        :return: List of successors
        :rtype: list
        """

        addr = cfg_job.addr

        try:
            if self.project.is_hooked(addr):
                procedure = self.project.hooked_by(addr)
                name = procedure.display_name
            else:
                procedure = self.project.simos.syscall_from_addr(addr)
                name = procedure.display_name

            if addr not in self._nodes:
                cfg_node = CFGNode(addr, 0, self.model,
                                   function_address=current_func_addr,
                                   simprocedure_name=name,
                                   no_ret=procedure.NO_RET,
                                   block_id=addr,
                                   )

                self._nodes[addr] = cfg_node
                self._nodes_by_addr[addr].append(cfg_node)

            else:
                cfg_node = self._nodes[addr]

        except (SimMemoryError, SimEngineError):
            return [ ]

        self._graph_add_edge(cfg_node, cfg_job.src_node, cfg_job.jumpkind, cfg_job.src_ins_addr,
                             cfg_job.src_stmt_idx
                             )
        self._function_add_node(cfg_node, current_func_addr)

        # Add edges going to this node in function graphs
        cfg_job.apply_function_edges(self, clear=True)

        # If we have traced it before, don't trace it anymore
        if addr in self._traced_addresses:
            return [ ]
        else:
            # Mark the address as traced
            self._traced_addresses.add(addr)

        entries = [ ]

        if procedure.ADDS_EXITS:
            # Get two blocks ahead
            if cfg_job.src_node is None:
                l.warning("%s is supposed to yield new exits, but it fails to do so.", name)
                return []
            grandparent_nodes = list(self.graph.predecessors(cfg_job.src_node))
            grandparent_node = grandparent_nodes[0] if grandparent_nodes else None
            blocks_ahead = [ ]
            if grandparent_node is not None:
                blocks_ahead.append(self._lift(grandparent_node.addr).vex)
            blocks_ahead.append(self._lift(cfg_job.src_node.addr).vex)
            procedure.project = self.project
            procedure.arch = self.project.arch
            new_exits = procedure.static_exits(blocks_ahead)

            for new_exit in new_exits:
                addr_ = new_exit['address']
                jumpkind = new_exit['jumpkind']
                namehint = new_exit.get('namehint', None)
                if isinstance(addr_, claripy.ast.BV) and not addr_.symbolic:
                    addr_ = addr_._model_concrete.value
                if not isinstance(addr_, int):
                    continue
                entries += self._create_jobs(addr_, jumpkind, current_func_addr, None, addr_, cfg_node, None,
                                             None,
                                             )
                if namehint and addr_ not in self.kb.labels:
                    unique_label = self.kb.labels.get_unique_label(namehint)
                    self.kb.labels[addr_] = unique_label

        if not procedure.NO_RET:
            # it returns
            cfg_node.has_return = True
            self._function_exits[current_func_addr].add(addr)
            self._function_add_return_site(addr, current_func_addr)
        else:
            # the procedure does not return
            self._updated_nonreturning_functions.add(current_func_addr)

        return entries

    def _scan_irsb(self, cfg_job, current_func_addr):
        """
        Generate a list of successors (generating them each as entries) to IRSB.
        Updates previous CFG nodes with edges.

        :param CFGJob cfg_job: The CFGJob instance.
        :param int current_func_addr: Address of the current function
        :return: a list of successors
        :rtype: list
        """
        addr, function_addr, cfg_node, irsb = self._generate_cfgnode(cfg_job, current_func_addr)

        # Add edges going to this node in function graphs
        cfg_job.apply_function_edges(self, clear=True)

        # function_addr and current_function_addr can be different. e.g. when tracing an optimized tail-call that jumps
        # into another function that has been identified before.

        if cfg_node is None:
            # exceptions occurred, or we cannot get a CFGNode for other reasons
            return [ ]

        self._graph_add_edge(cfg_node, cfg_job.src_node, cfg_job.jumpkind, cfg_job.src_ins_addr,
                             cfg_job.src_stmt_idx
                             )
        self._function_add_node(cfg_node, function_addr)

        if self.functions.get_by_addr(function_addr).returning is not True:
            self._updated_nonreturning_functions.add(function_addr)

        # If we have traced it before, don't trace it anymore
        real_addr = get_real_address_if_arm(self.project.arch, addr)
        if real_addr in self._traced_addresses:
            # the address has been traced before
            return [ ]
        else:
            # Mark the address as traced
            self._traced_addresses.add(real_addr)

        # irsb cannot be None here
        # assert irsb is not None

        # IRSB is only used once per CFGNode. We should be able to clean up the CFGNode here in order to save memory
        cfg_node.irsb = None

        self._process_block_arch_specific(addr, irsb, function_addr)

        # Scan the basic block to collect data references
        if self._collect_data_ref:
            self._collect_data_references(irsb, addr)

        # Get all possible successors
        irsb_next, jumpkind = irsb.next, irsb.jumpkind
        successors = [ ]

        if irsb.statements:
            last_ins_addr = None
            ins_addr = addr
            for i, stmt in enumerate(irsb.statements):
                if isinstance(stmt, pyvex.IRStmt.Exit):
                    successors.append((i,
                                       last_ins_addr if self.project.arch.branch_delay_slot else ins_addr,
                                       stmt.dst,
                                       stmt.jumpkind
                                       )
                                      )
                elif isinstance(stmt, pyvex.IRStmt.IMark):
                    last_ins_addr = ins_addr
                    ins_addr = stmt.addr + stmt.delta
        else:
            for ins_addr, stmt_idx, exit_stmt in irsb.exit_statements:
                branch_ins_addr = ins_addr
                if self.project.arch.branch_delay_slot \
                        and irsb.instruction_addresses \
                        and ins_addr in irsb.instruction_addresses:
                    idx_ = irsb.instruction_addresses.index(ins_addr)
                    if idx_ > 0:
                        branch_ins_addr = irsb.instruction_addresses[idx_ - 1]
                successors.append((
                    stmt_idx,
                    branch_ins_addr,
                    exit_stmt.dst,
                    exit_stmt.jumpkind
                ))

        # default statement
        default_branch_ins_addr = None
        if irsb.instruction_addresses:
            if self.project.arch.branch_delay_slot:
                if len(irsb.instruction_addresses) > 1:
                    default_branch_ins_addr = irsb.instruction_addresses[-2]
            else:
                default_branch_ins_addr = irsb.instruction_addresses[-1]

        successors.append((DEFAULT_STATEMENT, default_branch_ins_addr, irsb_next, jumpkind))

        # exception handling
        exc = self._exception_handling_by_endaddr.get(addr + irsb.size, None)
        if exc is not None:
            successors.append(
                (DEFAULT_STATEMENT,
                 default_branch_ins_addr,
                 exc.handler_addr,
                 'Ijk_Exception')
            )

        entries = [ ]

        successors = self._post_process_successors(irsb, successors)

        # Process each successor
        for suc in successors:
            stmt_idx, ins_addr, target, jumpkind = suc

            entries += self._create_jobs(target, jumpkind, function_addr, irsb, addr, cfg_node, ins_addr,
                                         stmt_idx
                                         )

        return entries

    def _create_jobs(self, target, jumpkind, current_function_addr, irsb, addr, cfg_node, ins_addr, stmt_idx):
        """
        Given a node and details of a successor, makes a list of CFGJobs
        and if it is a call or exit marks it appropriately so in the CFG

        :param int target:          Destination of the resultant job
        :param str jumpkind:        The jumpkind of the edge going to this node
        :param int current_function_addr: Address of the current function
        :param pyvex.IRSB irsb:     IRSB of the predecessor node
        :param int addr:            The predecessor address
        :param CFGNode cfg_node:    The CFGNode of the predecessor node
        :param int ins_addr:        Address of the source instruction.
        :param int stmt_idx:        ID of the source statement.
        :return:                    a list of CFGJobs
        :rtype:                     list
        """

        if type(target) is pyvex.IRExpr.Const:  # pylint: disable=unidiomatic-typecheck
            target_addr = target.con.value
        elif type(target) in (pyvex.IRConst.U8, pyvex.IRConst.U16, pyvex.IRConst.U32, pyvex.IRConst.U64):  # pylint: disable=unidiomatic-typecheck
            target_addr = target.value
        elif type(target) is int:  # pylint: disable=unidiomatic-typecheck
            target_addr = target
        else:
            target_addr = None

        if target_addr in self._known_thunks and jumpkind == 'Ijk_Boring':
            thunk_kind = self._known_thunks[target_addr][0]
            if thunk_kind == 'ret':
                jumpkind = 'Ijk_Ret'
                target_addr = None
            elif thunk_kind == 'jmp':
                pass # ummmmmm not sure about this one
            else:
                raise AngrCFGError("This shouldn't be possible")

        jobs = [ ]
        is_syscall = jumpkind.startswith("Ijk_Sys")

        # Special handling:
        # If a call instruction has a target that points to the immediate next instruction, we treat it as a boring jump
        if jumpkind == "Ijk_Call" and \
                not self.project.arch.call_pushes_ret and \
                cfg_node.instruction_addrs and \
                ins_addr == cfg_node.instruction_addrs[-1] and \
                target_addr == irsb.addr + irsb.size:
            jumpkind = "Ijk_Boring"

        if target_addr is None:
            # The target address is not a concrete value

            if jumpkind == "Ijk_Ret":
                # This block ends with a return instruction.
                if current_function_addr != -1:
                    self._function_exits[current_function_addr].add(addr)
                    self._function_add_return_site(addr, current_function_addr)
                    self.functions[current_function_addr].returning = True
                    self._pending_jobs.add_returning_function(current_function_addr)

                cfg_node.has_return = True

            elif self._resolve_indirect_jumps and \
                    (jumpkind in ('Ijk_Boring', 'Ijk_Call', 'Ijk_InvalICache') or jumpkind.startswith('Ijk_Sys')):
                # This is an indirect jump. Try to resolve it.
                # FIXME: in some cases, a statementless irsb will be missing its instr addresses
                # and this next part will fail. Use the real IRSB instead
                irsb = self._lift(cfg_node.addr, size=cfg_node.size).vex
                cfg_node.instruction_addrs = irsb.instruction_addresses
                resolved, resolved_targets, ij = self._indirect_jump_encountered(addr, cfg_node, irsb,
                                                                                 current_function_addr, stmt_idx)
                if resolved:
                    for resolved_target in resolved_targets:
                        if jumpkind == 'Ijk_Call':
                            jobs += self._create_job_call(cfg_node.addr, irsb, cfg_node, stmt_idx, ins_addr,
                                                          current_function_addr, resolved_target, jumpkind)
                        else:
                            to_outside, target_func_addr = self._is_branching_to_outside(addr, resolved_target,
                                                                                         current_function_addr)
                            edge = FunctionTransitionEdge(cfg_node, resolved_target, current_function_addr,
                                                          to_outside=to_outside, stmt_idx=stmt_idx, ins_addr=ins_addr,
                                                          dst_func_addr=target_func_addr,
                                                          )
                            ce = CFGJob(resolved_target, target_func_addr, jumpkind,
                                        last_addr=resolved_target, src_node=cfg_node, src_stmt_idx=stmt_idx,
                                        src_ins_addr=ins_addr, func_edges=[ edge ],
                                        )
                            jobs.append(ce)
                    return jobs

                if ij is None:
                    # this is not a valid indirect jump. maybe it failed sanity checks.
                    # for example, `jr $v0` might show up in a MIPS binary without a following instruction (because
                    # decoding failed). in this case, `jr $v0` shouldn't be a valid instruction, either.
                    return [ ]

                if jumpkind in ("Ijk_Boring", 'Ijk_InvalICache'):
                    resolved_as_plt = False

                    if irsb and self._heuristic_plt_resolving:
                        # Test it on the initial state. Does it jump to a valid location?
                        # It will be resolved only if this is a .plt entry
                        resolved_as_plt = self._resolve_plt(addr, irsb, ij)

                        if resolved_as_plt:
                            jump_target = next(iter(ij.resolved_targets))
                            target_func_addr = jump_target  # TODO: FIX THIS

                            edge = FunctionTransitionEdge(cfg_node, jump_target, current_function_addr,
                                                          to_outside=True, dst_func_addr=jump_target,
                                                          stmt_idx=stmt_idx, ins_addr=ins_addr,
                                                          )
                            ce = CFGJob(jump_target, target_func_addr, jumpkind, last_addr=jump_target,
                                        src_node=cfg_node, src_stmt_idx=stmt_idx, src_ins_addr=ins_addr,
                                        func_edges=[edge],
                                        )
                            jobs.append(ce)

                    if resolved_as_plt:
                        # has been resolved as a PLT entry. Remove it from indirect_jumps_to_resolve
                        if ij.addr in self._indirect_jumps_to_resolve:
                            self._indirect_jumps_to_resolve.remove(ij.addr)
                            self._deregister_analysis_job(current_function_addr, ij)
                    else:
                        # add it to indirect_jumps_to_resolve
                        self._indirect_jumps_to_resolve.add(ij)

                        # register it as a job for the current function
                        self._register_analysis_job(current_function_addr, ij)

                else:  # jumpkind == "Ijk_Call" or jumpkind.startswith('Ijk_Sys')
                    self._indirect_jumps_to_resolve.add(ij)
                    self._register_analysis_job(current_function_addr, ij)

                    jobs += self._create_job_call(addr, irsb, cfg_node, stmt_idx, ins_addr, current_function_addr, None,
                                                  jumpkind, is_syscall=is_syscall
                                                  )

        elif target_addr is not None:
            # This is a direct jump with a concrete target.

            # pylint: disable=too-many-nested-blocks
            if jumpkind in {'Ijk_Boring', 'Ijk_InvalICache', 'Ijk_Exception'}:
                to_outside, target_func_addr = self._is_branching_to_outside(addr, target_addr, current_function_addr)
                edge = FunctionTransitionEdge(cfg_node, target_addr, current_function_addr,
                                              to_outside=to_outside,
                                              dst_func_addr=target_func_addr,
                                              ins_addr=ins_addr,
                                              stmt_idx=stmt_idx,
                                              is_exception=jumpkind == 'Ijk_Exception',
                                              )

                ce = CFGJob(target_addr, target_func_addr, jumpkind, last_addr=addr, src_node=cfg_node,
                            src_ins_addr=ins_addr, src_stmt_idx=stmt_idx, func_edges=[ edge ])
                jobs.append(ce)

            elif jumpkind == 'Ijk_Call' or jumpkind.startswith("Ijk_Sys"):
                jobs += self._create_job_call(addr, irsb, cfg_node, stmt_idx, ins_addr, current_function_addr,
                                              target_addr, jumpkind, is_syscall=is_syscall
                                              )

            else:
                # TODO: Support more jumpkinds
                l.debug("Unsupported jumpkind %s", jumpkind)
                l.debug("Instruction address: %#x", ins_addr)

        return jobs

    def _create_job_call(self, addr, irsb, cfg_node, stmt_idx, ins_addr, current_function_addr, target_addr, jumpkind,
                         is_syscall=False):
        """
        Generate a CFGJob for target address, also adding to _pending_entries
        if returning to succeeding position (if irsb arg is populated)

        :param int addr:            Address of the predecessor node
        :param pyvex.IRSB irsb:     IRSB of the predecessor node
        :param CFGNode cfg_node:    The CFGNode instance of the predecessor node
        :param int stmt_idx:        ID of the source statement
        :param int ins_addr:        Address of the source instruction
        :param int current_function_addr: Address of the current function
        :param int target_addr:     Destination of the call
        :param str jumpkind:        The jumpkind of the edge going to this node
        :param bool is_syscall:     Is the jump kind (and thus this) a system call
        :return:                    A list of CFGJobs
        :rtype:                     list
        """

        jobs = [ ]

        if is_syscall:
            # Fix the target_addr for syscalls
            tmp_state = self.project.factory.blank_state(mode="fastpath", addr=cfg_node.addr)
            # Find the first successor with a syscall jumpkind
            successors = self._simulate_block_with_resilience(tmp_state)
            if successors is not None:
                succ = next(iter(succ for succ in successors.flat_successors
                                 if succ.history.jumpkind and succ.history.jumpkind.startswith("Ijk_Sys")), None)
            else:
                succ = None
            if succ is None:
                # For some reason, there is no such successor with a syscall jumpkind
                target_addr = self._unresolvable_call_target_addr
            else:
                try:
                    syscall_stub = self.project.simos.syscall(succ)
                    if syscall_stub:  # can be None if simos is not a subclass of SimUserspace
                        syscall_addr = syscall_stub.addr
                        target_addr = syscall_addr
                    else:
                        target_addr = self._unresolvable_call_target_addr
                except AngrUnsupportedSyscallError:
                    target_addr = self._unresolvable_call_target_addr

        if isinstance(target_addr, SootAddressDescriptor):
            new_function_addr = target_addr.method
        else:
            new_function_addr = target_addr

        if irsb is None:
            return_site = None
        else:
            if self.project.arch.name != 'Soot':
                return_site = addr + irsb.size  # We assume the program will always return to the succeeding position
            else:
                # For Soot, we return to the next statement, which is not necessarily the next block (as Shimple does
                # not break blocks at calls)
                assert isinstance(ins_addr, SootAddressDescriptor)
                soot_block = irsb
                return_block_idx = ins_addr.block_idx
                if stmt_idx + 1 >= soot_block.label + len(soot_block.statements):
                    # tick the block ID
                    return_block_idx += 1
                return_site = SootAddressDescriptor(ins_addr.method, return_block_idx, stmt_idx + 1)

        edge = None
        if new_function_addr is not None:
            edge = FunctionCallEdge(cfg_node, new_function_addr, return_site, current_function_addr, syscall=is_syscall,
                                    ins_addr=ins_addr, stmt_idx=stmt_idx,
                                    )

        if new_function_addr is not None:
            # Keep tracing from the call
            ce = CFGJob(target_addr, new_function_addr, jumpkind, last_addr=addr, src_node=cfg_node,
                        src_stmt_idx=stmt_idx, src_ins_addr=ins_addr, syscall=is_syscall, func_edges=[ edge ]
                        )
            jobs.append(ce)

        callee_might_return = True
        callee_function = None

        if new_function_addr is not None:
            if is_syscall or self.project.is_hooked(new_function_addr):
                # we can create the function if it is a syscall or a SimProcedure and it does not exist yet. Note that
                # syscalls are handled as SimProcedures anyway.
                callee_function = self.kb.functions.function(addr=new_function_addr, syscall=is_syscall, create=True)
            else:
                callee_function = self.kb.functions.function(addr=new_function_addr, syscall=is_syscall)
            if callee_function is not None:
                callee_might_return = not (callee_function.returning is False)

        if callee_might_return:
            func_edges = [ ]
            if return_site is not None:
                if callee_function is not None and callee_function.returning is True:
                    fakeret_edge = FunctionFakeRetEdge(cfg_node, return_site, current_function_addr, confirmed=True)
                    func_edges.append(fakeret_edge)
                    ret_edge = FunctionReturnEdge(new_function_addr, return_site, current_function_addr)
                    func_edges.append(ret_edge)

                    # Also, keep tracing from the return site
                    ce = CFGJob(return_site, current_function_addr, 'Ijk_FakeRet', last_addr=addr, src_node=cfg_node,
                                src_stmt_idx=stmt_idx, src_ins_addr=ins_addr, returning_source=new_function_addr,
                                syscall=is_syscall, func_edges=func_edges)
                    self._pending_jobs.add_job(ce)
                    # register this job to this function
                    self._register_analysis_job(current_function_addr, ce)
                elif callee_function is not None and callee_function.returning is False:
                    pass # Don't go past a call that does not return!
                else:
                    # HACK: We don't know where we are jumping.  Let's assume we fakeret to the
                    # next instruction after the block
                    # TODO: FIXME: There are arch-specific hints to give the correct ret site
                    # Such as looking for constant values of LR in this block for ARM stuff.
                    fakeret_edge = FunctionFakeRetEdge(cfg_node, return_site, current_function_addr, confirmed=None)
                    func_edges.append(fakeret_edge)
                    fr = FunctionReturn(new_function_addr, current_function_addr, addr, return_site)
                    if fr not in self._function_returns[new_function_addr]:
                        self._function_returns[new_function_addr].add(fr)
                    ce = CFGJob(return_site, current_function_addr, 'Ijk_FakeRet', last_addr=addr, src_node=cfg_node,
                                src_stmt_idx=stmt_idx, src_ins_addr=ins_addr, returning_source=new_function_addr,
                                syscall=is_syscall, func_edges=func_edges)
                    self._pending_jobs.add_job(ce)
                    # register this job to this function
                    self._register_analysis_job(current_function_addr, ce)


        return jobs

    def _simulate_block_with_resilience(self, state):
        """
        Execute a basic block with "On Error Resume Next". Give up when there is no way moving forward.

        :param SimState state:  The initial state to start simulation with.
        :return:                A SimSuccessors instance or None if we are unable to resume execution with resilience.
        :rtype:                 SimSuccessors or None
        """

        stmt_idx = 0
        successors = None  # make PyCharm's linting happy

        while True:
            try:
                successors = self.project.factory.successors(state, skip_stmts=stmt_idx)
                break
            except SimOperationError as ex:
                stmt_idx = ex.stmt_idx + 1
                continue
            except SimError:
                return None

        return successors

    def _is_branching_to_outside(self, src_addr, target_addr, current_function_addr):
        """
        Determine if a branch is branching to a different function (i.e., branching to outside the current function).

        :param int src_addr:    The source address.
        :param int target_addr: The destination address.
        :param int current_function_addr:   Address of the current function.
        :return:    A tuple of (to_outside, target_func_addr)
        :rtype:     tuple
        """

        if not self._addrs_belong_to_same_section(src_addr, target_addr):
            # if the target address is at another section, it has to be jumping to a new function
            target_func_addr = target_addr
            to_outside = True
        else:
            # it might be a jumpout
            target_func_addr = None
            real_target_addr = get_real_address_if_arm(self.project.arch, target_addr)
            if real_target_addr in self._traced_addresses:
                node = self.model.get_any_node(target_addr)
                if node is not None:
                    target_func_addr = node.function_address
            if target_func_addr is None:
                target_func_addr = current_function_addr

            to_outside = not target_func_addr == current_function_addr

        return to_outside, target_func_addr

    # Data reference processing

    def _collect_data_references(self, irsb, irsb_addr):
        """
        Unoptimizes IRSB and _add_data_reference's for individual statements or
        for parts of statements (e.g. Store)

        :param pyvex.IRSB irsb: Block to scan for data references
        :param int irsb_addr: Address of block
        :return: None
        """

        if irsb.data_refs:
            self._process_irsb_data_refs(irsb)
        elif irsb.statements:
            # for each statement, collect all constants that are referenced or used.
            self._collect_data_references_by_scanning_stmts(irsb, irsb_addr)

    def _process_irsb_data_refs(self, irsb):
        for ref in irsb.data_refs:
            if ref.data_size:
                self._seg_list.occupy(ref.data_addr, ref.data_size, "unknown")

            self._add_data_reference(
                    irsb.addr,
                    ref.stmt_idx,
                    ref.ins_addr,
                    ref.data_addr,
                    data_size=ref.data_size,
                    data_type=ref.data_type_str
            )

    def _collect_data_references_by_scanning_stmts(self, irsb, irsb_addr):

        # helper methods
        def _process(stmt_idx_, data_, insn_addr, next_insn_addr, data_size=None, data_type=None):
            """
            Helper method used for calling _add_data_reference after checking
            for manipulation of constants

            :param pyvex.IRSB irsb_: Edited block (as might be de-optimised)
            :param pyvex.IRStmt.* stmt_: Statement
            :param int stmt_idx_: Statement ID
            :param data_: data manipulated by statement
            :param int insn_addr: instruction address
            :param int next_insn_addr: next instruction address
            :param data_size: Size of the data being manipulated
            :param str data_type: Type of the data being manipulated
            :return: None
            """
            if type(data_) is pyvex.expr.Const:  # pylint: disable=unidiomatic-typecheck
                val = data_.con.value
            elif type(data_) is int:
                val = data_
            else:
                return

            if val != next_insn_addr:
                if data_size:
                    # Mark the region as unknown so we won't try to create a code block covering this region in the
                    # future.
                    self._seg_list.occupy(val, data_size, "unknown")
                self._add_data_reference(irsb_addr, stmt_idx_, insn_addr, val, data_size=data_size, data_type=data_type)

        # get all instruction addresses
        instr_addrs = irsb.instruction_addresses

        # for each statement, collect all constants that are referenced or used.
        instr_addr = None
        next_instr_addr = None
        for stmt_idx, stmt in enumerate(irsb.statements):
            if type(stmt) is pyvex.IRStmt.IMark:  # pylint: disable=unidiomatic-typecheck
                instr_addr = stmt.addr + stmt.delta
                # there can be weird cases sometimes... I've seen two IMarks with the exact same address showing up one
                # after the other.
                if instr_addrs and instr_addr == instr_addrs[0]:
                    instr_addr = instr_addrs[0]
                    instr_addrs = instr_addrs[1 : ]
                    next_instr_addr = instr_addrs[0] if instr_addrs else None

            elif type(stmt) is pyvex.IRStmt.WrTmp:  # pylint: disable=unidiomatic-typecheck
                if type(stmt.data) is pyvex.IRExpr.Load:  # pylint: disable=unidiomatic-typecheck
                    # load
                    # e.g. t7 = LDle:I64(0x0000000000600ff8)
                    size = stmt.data.result_size(irsb.tyenv) // 8 # convert to bytes
                    _process(stmt_idx, stmt.data.addr, instr_addr, next_instr_addr, data_size=size, data_type='integer')

                elif type(stmt.data) in (pyvex.IRExpr.Binop, ):  # pylint: disable=unidiomatic-typecheck

                    # rip-related addressing
                    if stmt.data.op in ('Iop_Add32', 'Iop_Add64') and \
                            all(type(arg) is pyvex.expr.Const for arg in stmt.data.args):
                        # perform the addition
                        loc = stmt.data.args[0].con.value + stmt.data.args[1].con.value
                        _process(stmt_idx, loc, instr_addr, next_instr_addr)

                    else:
                        # binary operation
                        for arg in stmt.data.args:
                            _process(stmt_idx, arg, instr_addr, next_instr_addr)

                elif type(stmt.data) is pyvex.IRExpr.Const:  # pylint: disable=unidiomatic-typecheck
                    _process(stmt_idx, stmt.data, instr_addr, next_instr_addr)

                elif type(stmt.data) is pyvex.IRExpr.ITE:
                    for child_expr in stmt.data.child_expressions:
                        _process(stmt_idx, child_expr, instr_addr, next_instr_addr)

            elif type(stmt) is pyvex.IRStmt.Put:  # pylint: disable=unidiomatic-typecheck
                # put
                # e.g. PUT(rdi) = 0x0000000000400714
                if stmt.offset not in (self._initial_state.arch.ip_offset, ):
                    _process(stmt_idx, stmt.data, instr_addr, next_instr_addr)

            elif type(stmt) is pyvex.IRStmt.Store:  # pylint: disable=unidiomatic-typecheck
                # store addr
                _process(stmt_idx, stmt.addr, instr_addr, next_instr_addr)
                # store data
                _process(stmt_idx, stmt.data, instr_addr, next_instr_addr)

            elif type(stmt) is pyvex.IRStmt.Dirty:

                _process(stmt_idx, stmt.mAddr, instr_addr, next_instr_addr, data_size=stmt.mSize, data_type='fp')

    def _add_data_reference(self, irsb_addr, stmt_idx, insn_addr, data_addr,  # pylint: disable=unused-argument
                            data_size=None, data_type=None):
        """
        Checks addresses are in the correct segments and creates or updates
        MemoryData in _memory_data as appropriate, labelling as segment
        boundaries or data type

        :param int irsb_addr: irsb address
        :param int stmt_idx: Statement ID
        :param int insn_addr: instruction address
        :param data_addr: address of data manipulated by statement
        :param data_size: Size of the data being manipulated
        :param str data_type: Type of the data being manipulated
        :return: None
        """

        # Make sure data_addr is within a valid memory range
        if not self.project.loader.find_segment_containing(data_addr):

            # data might be at the end of some section or segment...
            # let's take a look
            for segment in self.project.loader.main_object.segments:
                if segment.vaddr + segment.memsize == data_addr:
                    # yeah!
                    new_data = False
                    if data_addr not in self._memory_data:
                        data = MemoryData(data_addr, 0, MemoryDataSort.SegmentBoundary)
                        self._memory_data[data_addr] = data
                        new_data = True

                    if new_data or self._cross_references:
                        cr = XRef(ins_addr=insn_addr, block_addr=irsb_addr, stmt_idx=stmt_idx,
                                  memory_data=self.model.memory_data[data_addr], xref_type=XRefType.Offset,
                                  )
                        self.kb.xrefs.add_xref(cr)
                    break

            return

        new_data = False
        if data_addr not in self._memory_data:
            if data_type is not None and data_size is not None:
                data = MemoryData(data_addr, data_size, data_type, max_size=data_size)
            else:
                data = MemoryData(data_addr, 0, MemoryDataSort.Unknown)
            self._memory_data[data_addr] = data
            new_data = True
        if new_data or self._cross_references:
            cr = XRef(ins_addr=insn_addr, block_addr=irsb_addr, stmt_idx=stmt_idx,
                      memory_data=self.model.memory_data[data_addr],
                      xref_type=XRefType.Offset,
                      )
            self.kb.xrefs.add_xref(cr)

        self.insn_addr_to_memory_data[insn_addr] = self._memory_data[data_addr]

    def _tidy_data_references(self):
        """

        :return: True if new data entries are found, False otherwise.
        :rtype: bool
        """

        # Make sure all memory data entries cover all data sections
        keys = sorted(self._memory_data.keys())
        for i, data_addr in enumerate(keys):
            data = self._memory_data[data_addr]
            if self._addr_in_exec_memory_regions(data.address):
                # TODO: Handle data among code regions (or executable regions)
                pass
            else:
                if i + 1 != len(keys):
                    next_data_addr = keys[i + 1]
                else:
                    next_data_addr = None

                # goes until the end of the section/segment
                # TODO: the logic needs more testing

                sec = self.project.loader.find_section_containing(data_addr)
                next_sec_addr = None
                if sec is not None:
                    last_addr = sec.vaddr + sec.memsize
                else:
                    # it does not belong to any section. what's the next adjacent section? any memory data does not go
                    # beyong section boundaries
                    next_sec = self.project.loader.find_section_next_to(data_addr)
                    if next_sec is not None:
                        next_sec_addr = next_sec.vaddr

                    seg = self.project.loader.find_segment_containing(data_addr)
                    if seg is not None:
                        last_addr = seg.vaddr + seg.memsize
                    else:
                        # We got an address that is not inside the current binary...
                        l.warning('_tidy_data_references() sees an address %#08x that does not belong to any '
                                  'section or segment.', data_addr
                                  )
                        last_addr = None

                if next_data_addr is None:
                    boundary = last_addr
                elif last_addr is None:
                    boundary = next_data_addr
                else:
                    boundary = min(last_addr, next_data_addr)

                if next_sec_addr is not None:
                    boundary = min(boundary, next_sec_addr)

                if boundary is not None:
                    data.max_size = boundary - data_addr

                if data.max_size is None:
                    print('wtf')

        keys = sorted(self._memory_data.keys())

        new_data_found = False

        i = 0
        # pylint:disable=too-many-nested-blocks
        while i < len(keys):
            data_addr = keys[i]
            i += 1

            memory_data = self._memory_data[data_addr]

            if memory_data.sort == MemoryDataSort.SegmentBoundary:
                continue

            content_holder = [ ]

            # let's see what sort of data it is
            if memory_data.sort in (MemoryDataSort.Unknown, MemoryDataSort.Unspecified) or \
                    (memory_data.sort == MemoryDataSort.Integer and memory_data.size == self.project.arch.bytes):
                data_type, data_size = self._guess_data_type(data_addr, memory_data.max_size,
                                                             content_holder=content_holder)
            else:
                data_type, data_size = memory_data.sort, memory_data.size

            if data_type is not None:
                memory_data.size = data_size
                memory_data.sort = data_type

                if len(content_holder) == 1:
                    memory_data.content = content_holder[0]

                if memory_data.max_size is not None and (0 < memory_data.size < memory_data.max_size):
                    # Create another memory_data object to fill the gap
                    new_addr = data_addr + memory_data.size
                    new_md = MemoryData(new_addr, None, None, max_size=memory_data.max_size - memory_data.size)
                    self._memory_data[new_addr] = new_md
                    # Make a copy of all old references
                    old_crs = self.kb.xrefs.get_xrefs_by_dst(data_addr)
                    crs = [ ]
                    for old_cr in old_crs:
                        cr = old_cr.copy()
                        cr.memory_data = new_md
                        crs.append(cr)
                    self.kb.xrefs.add_xrefs(crs)
                    keys.insert(i, new_addr)

                if data_type == MemoryDataSort.PointerArray:
                    # make sure all pointers are identified
                    pointer_size = self.project.arch.bytes
                    old_crs = self.kb.xrefs.get_xrefs_by_dst(data_addr)

                    for j in range(0, data_size, pointer_size):
                        ptr = self._fast_memory_load_pointer(data_addr + j)

                        # is this pointer coming from the current binary?
                        obj = self.project.loader.find_object_containing(ptr, membership_check=False)
                        if obj is not self.project.loader.main_object:
                            # the pointer does not come from current binary. skip.
                            continue

                        if self._seg_list.is_occupied(ptr):
                            sort = self._seg_list.occupied_by_sort(ptr)
                            if sort == 'code':
                                continue
                            elif sort == 'pointer-array':
                                continue
                            # TODO: other types
                        if ptr not in self._memory_data:
                            new_md = MemoryData(ptr, 0, MemoryDataSort.Unknown, pointer_addr=data_addr + j)
                            self._memory_data[ptr] = new_md
                            # Make a copy of the old reference
                            crs = [ ]
                            for old_cr in old_crs:
                                cr = old_cr.copy()
                                cr.memory_data = new_md
                                crs.append(cr)
                            self.kb.xrefs.add_xrefs(crs)
                            new_data_found = True

            else:
                memory_data.size = memory_data.max_size

            self._seg_list.occupy(data_addr, memory_data.size, memory_data.sort)

        return new_data_found

    def _guess_data_type(self, data_addr, max_size, content_holder=None):
        """
        Make a guess to the data type.

        Users can provide their own data type guessing code when initializing CFGFast instance, and each guessing
        handler will be called if this method fails to determine what the data is.

        :param int data_addr: Address of the data.
        :param int max_size: The maximum size this data entry can be.
        :return: a tuple of (data type, size). (None, None) if we fail to determine the type or the size.
        :rtype: tuple
        """
        if max_size is None:
            max_size = 0

        # quick check: if it's at the beginning of a binary, it might be the ELF header
        elfheader_sort, elfheader_size = self._guess_data_type_elfheader(data_addr, max_size)
        if elfheader_sort:
            return elfheader_sort, elfheader_size

        try:
            ref = next(iter(self.kb.xrefs.get_xrefs_by_dst(data_addr)))  # type: XRef
            irsb_addr = ref.block_addr
            stmt_idx = ref.stmt_idx
        except StopIteration:
            irsb_addr, stmt_idx = None, None


        if self._seg_list.is_occupied(data_addr) and self._seg_list.occupied_by_sort(data_addr) == 'code':
            # it's a code reference
            # TODO: Further check if it's the beginning of an instruction
            return MemoryDataSort.CodeReference, 0

        pointer_size = self.project.arch.bytes

        # who's using it?
        if isinstance(self.project.loader.main_object, cle.MetaELF):
            plt_entry = self.project.loader.main_object.reverse_plt.get(irsb_addr, None)
            if plt_entry is not None:
                # IRSB is owned by plt!
                return MemoryDataSort.GOTPLTEntry, pointer_size

        # is it in a section with zero bytes, like .bss?
        obj = self.project.loader.find_object_containing(data_addr)
        section = obj.find_section_containing(data_addr)
        if section is not None and section.only_contains_uninitialized_data:
            # Nothing much you can do
            return None, None

        pointers_count = 0

        max_pointer_array_size = min(512 * pointer_size, max_size)
        for i in range(0, max_pointer_array_size, pointer_size):
            ptr = self._fast_memory_load_pointer(data_addr + i)

            if ptr is not None:
                #if self._seg_list.is_occupied(ptr) and self._seg_list.occupied_by_sort(ptr) == 'code':
                #    # it's a code reference
                #    # TODO: Further check if it's the beginning of an instruction
                #    pass
                if self.project.loader.find_section_containing(ptr) is not None or \
                        self.project.loader.find_segment_containing(ptr) is not None or \
                        (self._extra_memory_regions and
                         next(((a < ptr < b) for (a, b) in self._extra_memory_regions), None)
                         ):
                    # it's a pointer of some sort
                    # TODO: Determine what sort of pointer it is
                    pointers_count += 1
                else:
                    break

        if pointers_count:
            return MemoryDataSort.PointerArray, pointer_size * pointers_count

        try:
            data = self.project.loader.memory.load(data_addr, 1024)
        except KeyError:
            data = b''

        # Is it an unicode string?
        # TODO: Support unicode string longer than the max length
        if len(data) >= 4 and data[1] == 0 and data[3] == 0 and data[0] in self.PRINTABLES:
            def can_decode(n):
                try:
                    data[:n*2].decode('utf_16_le')
                except UnicodeDecodeError:
                    return False
                return True
            if can_decode(4) or can_decode(5) or can_decode(6):
                running_failures = 0
                last_success = 4
                for i in range(4, len(data) // 2):
                    if can_decode(i):
                        last_success = i
                        running_failures = 0
                        if data[i*2-2] == 0 and data[i*2-1] == 0:
                            break
                    else:
                        running_failures += 1
                        if running_failures > 3:
                            break

                return MemoryDataSort.UnicodeString, last_success

        if data:
            try:
                zero_pos = data.index(0)
            except ValueError:
                zero_pos = None
            if (zero_pos is not None and zero_pos > 0 and all(c in self.PRINTABLES for c in data[:zero_pos])) or \
                    all(c in self.PRINTABLES for c in data):
                # it's a string
                # however, it may not be terminated
                string_data = data if zero_pos is None else data[:zero_pos]
                if content_holder is not None:
                    content_holder.append(string_data)
                return MemoryDataSort.String, min(len(string_data) + 1, 1024)

        for handler in self._data_type_guessing_handlers:
            irsb = None if irsb_addr is None else self.model.get_any_node(irsb_addr).block.vex
            sort, size = handler(self, irsb, irsb_addr, stmt_idx, data_addr, max_size)
            if sort is not None:
                return sort, size

        return None, None

    def _guess_data_type_elfheader(self, data_addr, max_size):
        """
        Is the specified data chunk an ELF header?

        :param int data_addr:   Address of the data chunk
        :param int max_size:    Size of the data chunk.
        :return:                A tuple of ('elf-header', size) if it is, or (None, None) if it is not.
        :rtype:                 tuple
        """

        obj = self.project.loader.find_object_containing(data_addr)
        if obj is None:
            # it's not mapped
            return None, None

        if data_addr == obj.min_addr and 4 < max_size < 1000:
            # Does it start with the ELF magic bytes?
            try:
                data = self.project.loader.memory.load(data_addr, 4)
            except KeyError:
                return None, None
            if data == b"\x7fELF":
                # yes!
                return MemoryDataSort.ELFHeader, max_size

        return None, None

    # Indirect jumps processing

    def _resolve_plt(self, addr, irsb, indir_jump: IndirectJump):
        """
        Determine if the IRSB at the given address is a PLT stub. If it is, concretely execute the basic block to
        resolve the jump target.

        :param int addr:                Address of the block.
        :param irsb:                    The basic block.
        :param indir_jump:              The IndirectJump instance.
        :return:                        True if the IRSB represents a PLT stub and we successfully resolved the target.
                                        False otherwise.
        :rtype:                         bool
        """

        # is the address identified by CLE as a PLT stub?
        if self.project.loader.all_elf_objects:
            # restrict this heuristics to ELF files only
            if not any([ addr in obj.reverse_plt for obj in self.project.loader.all_elf_objects ]):
                return False

        # Make sure the IRSB has statements
        if not irsb.has_statements:
            irsb = self.project.factory.block(irsb.addr, size=irsb.size, opt_level=1, cross_insn_opt=False).vex

        # try to resolve the jump target
        simsucc = self.project.factory.default_engine.process(self._initial_state, irsb, force_addr=addr)
        if len(simsucc.successors) == 1:
            ip = simsucc.successors[0].ip
            if ip._model_concrete is not ip:
                target_addr = ip._model_concrete.value
                if (self.project.loader.find_object_containing(target_addr, membership_check=False) is not
                        self.project.loader.main_object) \
                        or self.project.is_hooked(target_addr):
                    # resolved!
                    # Fill the IndirectJump object
                    indir_jump.resolved_targets.add(target_addr)
                    l.debug("Address %#x is resolved as a PLT entry, jumping to %#x", addr, target_addr)
                    return True

        return False

    def _indirect_jump_resolved(self, jump: IndirectJump, jump_addr, resolved_by, targets: List[int]):
        """
        Called when an indirect jump is successfully resolved.

        :param jump:                                The resolved indirect jump.
        :param IndirectJumpResolver resolved_by:    The resolver used to resolve this indirect jump.
        :param list targets:                        List of indirect jump targets.

        :return:                                    None
        """

        source_addr = jump.addr

        if jump.jumptable:
            # Fill in the jump_tables dict
            self.jump_tables[jump.addr] = jump
            # occupy the jump table region
            if jump.jumptable_addr is not None:
                self._seg_list.occupy(jump.jumptable_addr, jump.jumptable_size, "data")

        jump.resolved_targets = targets
        all_targets = set(targets)
        for addr in all_targets:
            to_outside = addr in self.functions or not self._addrs_belong_to_same_section(jump.addr, addr)

            # TODO: get a better estimate of the function address
            target_func_addr = jump.func_addr if not to_outside else addr
            func_edge = FunctionTransitionEdge(self._nodes[source_addr], addr, jump.func_addr, to_outside=to_outside,
                                               dst_func_addr=target_func_addr
                                               )
            job = CFGJob(addr, target_func_addr, jump.jumpkind,
                         last_addr=source_addr,
                         src_node=self._nodes[source_addr],
                         src_ins_addr=None,
                         src_stmt_idx=None,
                         func_edges=[func_edge],
                         )
            self._insert_job(job)
            self._register_analysis_job(target_func_addr, job)

        self._deregister_analysis_job(jump.func_addr, jump)

        CFGBase._indirect_jump_resolved(self, jump, jump.addr, resolved_by, targets)

    def _indirect_jump_unresolved(self, jump):
        """
        Called when we cannot resolve an indirect jump.

        :param IndirectJump jump: The unresolved indirect jump.

        :return:    None
        """

        # add a node from this node to UnresolvableJumpTarget or UnresolvalbeCallTarget node,
        # depending on its jump kind
        src_node = self._nodes[jump.addr]
        if jump.jumpkind == 'Ijk_Boring':
            unresolvable_target_addr = self._unresolvable_jump_target_addr
            simprocedure_name = 'UnresolvableJumpTarget'
        elif jump.jumpkind == 'Ijk_Call':
            unresolvable_target_addr = self._unresolvable_call_target_addr
            simprocedure_name = 'UnresolvableCallTarget'
        else:
            raise AngrCFGError('It should be impossible')

        dst_node = CFGNode(unresolvable_target_addr, 0, self.model,
                           function_address=unresolvable_target_addr,
                           simprocedure_name=simprocedure_name,
                           block_id=unresolvable_target_addr,
                           )

        # add the dst_node to self._nodes
        if unresolvable_target_addr not in self._nodes:
            self._nodes[unresolvable_target_addr] = dst_node
            self._nodes_by_addr[unresolvable_target_addr].append(dst_node)

        self._graph_add_edge(dst_node, src_node, jump.jumpkind, jump.ins_addr, jump.stmt_idx)
        # mark it as a jumpout site for that function
        self._function_add_transition_edge(unresolvable_target_addr, src_node, jump.func_addr,
                                           to_outside=True,
                                           dst_func_addr=unresolvable_target_addr,
                                           ins_addr=jump.ins_addr,
                                           stmt_idx=jump.stmt_idx,
                                           )

        self._deregister_analysis_job(jump.func_addr, jump)

        CFGBase._indirect_jump_unresolved(self, jump)

    # Exception handling

    def _preprocess_exception_handlings(self):

        self._exception_handling_by_endaddr.clear()

        bin_count = 0
        for obj in self.project.loader.all_objects:
            if isinstance(obj, cle.MetaELF) and hasattr(obj, "exception_handlings") and obj.exception_handlings:
                bin_count += 1
                for exc in obj.exception_handlings:
                    if exc.handler_addr is not None and self._inside_regions(exc.handler_addr):
                        if (exc.start_addr + exc.size) in self._exception_handling_by_endaddr:
                            l.warning("Multiple exception handlings ending at %#x. Please report it to GitHub.",
                                      exc.start_addr + exc.size)
                            continue
                        self._exception_handling_by_endaddr[exc.start_addr + exc.size] = exc

        l.info("Loaded %d exception handlings from %d binaries.",
               len(self._exception_handling_by_endaddr),
               bin_count,
               )

    # Removers

    def _remove_redundant_overlapping_blocks(self):
        """
        On some architectures there are sometimes garbage bytes (usually nops) between functions in order to properly
        align the succeeding function. CFGFast does a linear sweeping which might create duplicated blocks for
        function epilogues where one block starts before the garbage bytes and the other starts after the garbage bytes.

        This method enumerates all blocks and remove overlapping blocks if one of them is aligned to 0x10 and the other
        contains only garbage bytes.

        :return: None
        """

        sorted_nodes = sorted(self.graph.nodes(), key=lambda n: n.addr if n is not None else 0)

        all_plt_stub_addrs = set(itertools.chain.from_iterable(obj.reverse_plt.keys() for obj in self.project.loader.all_objects if isinstance(obj, cle.MetaELF)))

        # go over the list. for each node that is the beginning of a function and is not properly aligned, if its
        # leading instruction is a single-byte or multi-byte nop, make sure there is another CFGNode starts after the
        # nop instruction

        nodes_to_append = {}
        # pylint:disable=too-many-nested-blocks
        for a in sorted_nodes:
            if a.addr in self.functions and a.addr not in all_plt_stub_addrs and \
                    not self._addr_hooked_or_syscall(a.addr):
                all_in_edges = self.graph.in_edges(a, data=True)
                if not any([data['jumpkind'] == 'Ijk_Call' for _, _, data in all_in_edges]):
                    # no one is calling it
                    # this function might be created from linear sweeping
                    try:
                        block = self._lift(a.addr, size=0x10 - (a.addr % 0x10))
                    except SimTranslationError:
                        continue

                    nop_length = None

                    if self._is_noop_block(self.project.arch, block):
                        # fast path: in most cases, the entire block is a single byte or multi-byte nop, which VEX
                        # optimizer is able to tell
                        nop_length = block.size

                    else:
                        # this is not a no-op block. Determine where nop instructions terminate.
                        insns = block.capstone.insns
                        if insns:
                            nop_length = self._get_nop_length(insns)

                    if nop_length is None or nop_length <= 0:
                        continue

                    # leading nop for alignment.
                    next_node_addr = a.addr + nop_length
                    if nop_length < a.size and \
                            not (next_node_addr in self._nodes or next_node_addr in nodes_to_append):
                        # create a new CFGNode that starts there
                        next_node_size = a.size - nop_length
                        next_node = CFGNode(next_node_addr, next_node_size, self.model,
                                            function_address=next_node_addr,
                                            instruction_addrs=[i for i in a.instruction_addrs
                                                                      if next_node_addr <= i
                                                                      < next_node_addr + next_node_size
                                                                    ],
                                            thumb=a.thumb,
                                            byte_string=None if a.byte_string is None else a.byte_string[nop_length:],
                                            block_id=next_node_addr,
                                            )
                        self.graph.add_node(next_node)

                        # create edges accordingly
                        all_out_edges = self.graph.out_edges(a, data=True)
                        for _, dst, data in all_out_edges:
                            self.graph.add_edge(next_node, dst, **data)

                        nodes_to_append[next_node_addr] = next_node

                        # make sure there is a function begins there
                        try:
                            snippet = self._to_snippet(addr=next_node_addr, size=next_node_size,
                                                       base_state=self._base_state)
                            self.functions._add_node(next_node_addr, snippet)
                        except (SimEngineError, SimMemoryError):
                            continue

        # append all new nodes to sorted nodes
        if nodes_to_append:
            sorted_nodes = sorted(sorted_nodes + list(nodes_to_append.values()), key=lambda n: n.addr if n is not None else 0)

        removed_nodes = set()

        a = None  # it always hold the very recent non-removed node

        for i in range(len(sorted_nodes)):  # pylint:disable=consider-using-enumerate

            if a is None:
                a = sorted_nodes[0]
                continue

            b = sorted_nodes[i]
            if self._addr_hooked_or_syscall(b.addr):
                continue

            if b in removed_nodes:
                # skip all removed nodes
                continue

            if a.addr <= b.addr and \
                    (a.addr + a.size > b.addr):
                # They are overlapping

                try:
                    block = self.project.factory.fresh_block(a.addr, b.addr - a.addr, backup_state=self._base_state)
                except SimTranslationError:
                    a = b
                    continue
                if block.capstone.insns and all([ self._is_noop_insn(insn) for insn in block.capstone.insns ]):
                    # It's a big nop - no function starts with nop

                    # add b to indices
                    self._nodes[b.addr] = b
                    self._nodes_by_addr[b.addr].append(b)

                    # shrink a
                    self._shrink_node(a, b.addr - a.addr, remove_function=False)

                    a = b
                    continue

                all_functions = self.kb.functions

                # now things are a little harder
                # if there is no incoming edge to b, we should replace b with a
                # this is mostly because we misidentified the function beginning. In fact a is the function beginning,
                # but somehow we thought b is the beginning
                if a.addr + a.size == b.addr + b.size:
                    in_edges = len([ _ for _, _, data in self.graph.in_edges([b], data=True) ])
                    if in_edges == 0:
                        # we use node a to replace node b
                        # link all successors of b to a
                        for _, dst, data in self.graph.out_edges([b], data=True):
                            self.graph.add_edge(a, dst, **data)

                        if b.addr in self._nodes:
                            del self._nodes[b.addr]
                        if b.addr in self._nodes_by_addr and b in self._nodes_by_addr[b.addr]:
                            self._nodes_by_addr[b.addr].remove(b)

                        self.graph.remove_node(b)

                        if b.addr in all_functions:
                            del all_functions[b.addr]

                        # skip b
                        removed_nodes.add(b)

                        continue

                # next case - if b is directly from function prologue detection, or a basic block that is a successor of
                # a wrongly identified basic block, we might be totally misdecoding b
                if b.instruction_addrs[0] not in a.instruction_addrs:
                    # use a, truncate b

                    new_b_addr = a.addr + a.size  # b starts right after a terminates
                    new_b_size = b.addr + b.size - new_b_addr  # this may not be the size we want, since b might be
                                                               # misdecoded

                    # totally remove b
                    if b.addr in self._nodes:
                        del self._nodes[b.addr]
                    if b.addr in self._nodes_by_addr and b in self._nodes_by_addr[b.addr]:
                        self._nodes_by_addr[b.addr].remove(b)

                    self.graph.remove_node(b)

                    if b.addr in all_functions:
                        del all_functions[b.addr]

                    removed_nodes.add(b)

                    if new_b_size > 0:
                        # there are still some parts left in node b - we don't want to lose it
                        dummy_job = CFGJob(new_b_addr, a.function_address, None)
                        self._scan_block(dummy_job)

                    continue

                # for other cases, we'll let them be for now

            a = b # update a

    def _remove_node(self, node):
        """
        Remove a CFGNode from self.graph as well as from the function manager (if it is the beginning of a function)

        :param CFGNode node: The CFGNode to remove from the graph.
        :return: None
        """

        self.graph.remove_node(node)
        if node.addr in self._nodes:
            del self._nodes[node.addr]

        # We wanna remove the function as well
        if node.addr in self.kb.functions:
            del self.kb.functions[node.addr]

        if node.addr in self.kb.functions.callgraph:
            self.kb.functions.callgraph.remove_node(node.addr)

    def _shrink_node(self, node, new_size, remove_function=True):
        """
        Shrink the size of a node in CFG.

        :param CFGNode node: The CFGNode to shrink
        :param int new_size: The new size of the basic block
        :param bool remove_function: If there is a function starting at `node`, should we remove that function or not.
        :return: None
        """

        # Generate the new node
        new_node = CFGNode(node.addr, new_size, self.model,
                           function_address=None if remove_function else node.function_address,
                           instruction_addrs=[i for i in node.instruction_addrs
                                                     if node.addr <= i < node.addr + new_size
                                                   ],
                           thumb=node.thumb,
                           byte_string=None if node.byte_string is None else node.byte_string[:new_size],
                           block_id=node.addr,
                           )

        old_in_edges = self.graph.in_edges(node, data=True)

        for src, _, data in old_in_edges:
            self.graph.add_edge(src, new_node, **data)

        successor_node_addr = node.addr + new_size
        if successor_node_addr in self._nodes:
            successor = self._nodes[successor_node_addr]
        else:
            successor_size = node.size - new_size
            successor = CFGNode(successor_node_addr, successor_size, self.model,
                                function_address=successor_node_addr if remove_function else node.function_address,
                                instruction_addrs=[i for i in node.instruction_addrs if i >= node.addr + new_size],
                                thumb=node.thumb,
                                byte_string=None if node.byte_string is None else node.byte_string[new_size:]
                                )
        self.graph.add_edge(new_node, successor, jumpkind='Ijk_Boring')

        # if the node B already has resolved targets, we will skip all unresolvable successors when adding old out edges
        # from node A to node B.
        # this matters in cases where node B is resolved as a special indirect jump entry (like a PLT stub), but (node
        # A + node B) wasn't properly resolved.
        unresolvable_target_addrs = (self._unresolvable_jump_target_addr, self._unresolvable_call_target_addr)

        has_resolved_targets = any([ node_.addr not in unresolvable_target_addrs
                                     for node_ in self.graph.successors(successor) ]
                                   )

        old_out_edges = self.graph.out_edges(node, data=True)
        for _, dst, data in old_out_edges:
            if (has_resolved_targets and dst.addr not in unresolvable_target_addrs) or \
                    not has_resolved_targets:
                self.graph.add_edge(successor, dst, **data)

        # remove the old node from indices
        if node.addr in self._nodes and self._nodes[node.addr] is node:
            del self._nodes[node.addr]
        if node.addr in self._nodes_by_addr and node in self._nodes_by_addr[node.addr]:
            self._nodes_by_addr[node.addr].remove(node)

        # remove the old node form the graph
        self.graph.remove_node(node)

        # add the new node to indices
        self._nodes[new_node.addr] = new_node
        self._nodes_by_addr[new_node.addr].append(new_node)

        # the function starting at this point is probably totally incorrect
        # hopefull future call to `make_functions()` will correct everything
        if node.addr in self.kb.functions:
            del self.kb.functions[node.addr]

            if not remove_function:
                # add functions back
                self._function_add_node(node, node.addr)
                successor_node = self.model.get_any_node(successor_node_addr)
                if successor_node and successor_node.function_address == node.addr:
                    # if there is absolutely no predecessors to successor_node, we'd like to add it as a new function
                    # so that it will not be left behind
                    if not list(self.graph.predecessors(successor_node)):
                        self._function_add_node(successor_node, successor_node_addr)

        #if node.addr in self.kb.functions.callgraph:
        #    self.kb.functions.callgraph.remove_node(node.addr)

    def _analyze_all_function_features(self, all_funcs_completed=False):
        """
        Iteratively analyze all changed functions, update their returning attribute, until a fix-point is reached (i.e.
        no new returning/not-returning functions are found).

        :return: None
        """

        while True:
            new_changes = self._iteratively_analyze_function_features(all_funcs_completed=all_funcs_completed)
            new_returning_functions = new_changes['functions_return']
            new_not_returning_functions = new_changes['functions_do_not_return']

            if not new_returning_functions and not new_not_returning_functions:
                break

            for returning_function in new_returning_functions:
                self._pending_jobs.add_returning_function(returning_function.addr)
                if returning_function.addr in self._function_returns:
                    for fr in self._function_returns[returning_function.addr]:
                        # Confirm them all
                        if not self.kb.functions.contains_addr(fr.caller_func_addr):
                            # FIXME: A potential bug might arise here. After post processing (phase 2), if the function
                            # specified by fr.caller_func_addr has been merged to another function during phase 2, we
                            # will simply skip this FunctionReturn here. It might lead to unconfirmed fake_ret edges
                            # in the newly merged function. Fix this bug in the future when it becomes an issue.
                            continue

                        if self.kb.functions.get_by_addr(fr.caller_func_addr).returning is not True:
                            self._updated_nonreturning_functions.add(fr.caller_func_addr)

                        return_to_node = self._nodes.get(fr.return_to, None)
                        if return_to_node is None:
                            return_to_snippet = self._to_snippet(addr=fr.return_to, base_state=self._base_state)
                        else:
                            return_to_snippet = self._to_snippet(cfg_node=self._nodes[fr.return_to])

                        self.kb.functions._add_return_from_call(fr.caller_func_addr, fr.callee_func_addr,
                                                                return_to_snippet)

                    del self._function_returns[returning_function.addr]

            for nonreturning_function in new_not_returning_functions:
                self._pending_jobs.add_nonreturning_function(nonreturning_function.addr)
                if nonreturning_function.addr in self._function_returns:
                    for fr in self._function_returns[nonreturning_function.addr]:
                        # Remove all pending FakeRet edges
                        if self.kb.functions.contains_addr(fr.caller_func_addr) and \
                                self.kb.functions.get_by_addr(fr.caller_func_addr).returning is not True:
                            self._updated_nonreturning_functions.add(fr.caller_func_addr)

                    del self._function_returns[nonreturning_function.addr]

    def _pop_pending_job(self, returning=True):
        return self._pending_jobs.pop_job(returning=returning)

    def _clean_pending_exits(self):
        self._pending_jobs.cleanup()

    #
    # Graph utils
    #

    def _graph_add_edge(self, cfg_node, src_node, src_jumpkind, src_ins_addr, src_stmt_idx):
        """
        Add edge between nodes, or add node if entry point

        :param CFGNode cfg_node: node which is jumped to
        :param CFGNode src_node: node which is jumped from none if entry point
        :param str src_jumpkind: what type of jump the edge takes
        :param int or str src_stmt_idx: source statements ID
        :return: None
        """

        if src_node is None:
            self.graph.add_node(cfg_node)
        else:
            self.graph.add_edge(src_node, cfg_node, jumpkind=src_jumpkind, ins_addr=src_ins_addr,
                                stmt_idx=src_stmt_idx)

    @staticmethod
    def _get_return_endpoints(func):
        all_endpoints = func.endpoints_with_type
        return all_endpoints.get('return', [])

    def _get_jumpout_targets(self, func):
        jumpout_targets = set()
        callgraph_outedges = self.functions.callgraph.out_edges(func.addr, data=True)
        # find the ones whose type is transition
        for _, dst, data in callgraph_outedges:
            if data.get('type', None) == 'transition':
                jumpout_targets.add(dst)
        return jumpout_targets

    def _get_return_sources(self, func):

        # We will create a return edge for each returning point of this function

        # Get all endpoints
        all_endpoints = func.endpoints_with_type
        # However, we do not want to create return edge if the endpoint is not a returning endpoint.
        # For example, a PLT stub on x86/x64 always jump to the real library function, so we should create a return
        # edge from that library function to the call site, instead of creating a return edge from the PLT stub to
        # the call site.
        if all_endpoints['transition']:
            # it has jump outs
            # it is, for example, a PLT stub
            # we take the endpoints of the function it calls. this is not always correct, but it can handle many
            # cases.
            jumpout_targets = self._get_jumpout_targets(func)
            jumpout_target_endpoints = set()

            for jumpout_func_addr in jumpout_targets:
                if jumpout_func_addr in self.functions:
                    jumpout_target_endpoints |= set(self._get_return_endpoints(self.functions[jumpout_func_addr]))

            endpoints = jumpout_target_endpoints
        else:
            endpoints = set()

        # then we take all return endpoints of the current function
        endpoints |= all_endpoints.get('return', set())

        return endpoints

    def _get_tail_caller(self, tailnode, seen):
        """
        recursively search predecessors for the actual caller
        for a tailnode that we will return to

        :return: list of callers for a possible tailnode
        """

        if tailnode.addr in seen:
            return []
        seen.add(tailnode.addr)

        callers = self.model.get_predecessors(tailnode, jumpkind='Ijk_Call')
        direct_jumpers = self.model.get_predecessors(tailnode, jumpkind='Ijk_Boring')
        jump_callers = []

        for jn in direct_jumpers:
            jf = self.model.get_any_node(jn.function_address)
            if jf is not None:
                jump_callers.extend(self._get_tail_caller(jf, seen))

        callers.extend(jump_callers)

        return callers


    def _make_return_edges(self):
        """
        For each returning function, create return edges in self.graph.

        :return: None
        """

        for func_addr, func in self.functions.items():
            if func.returning is False:
                continue

            # get the node on CFG
            if func.startpoint is None:
                l.warning('Function %#x does not have a startpoint (yet).', func_addr)
                continue

            startpoint = self.model.get_any_node(func.startpoint.addr)
            if startpoint is None:
                # weird...
                l.warning('No CFGNode is found for function %#x in _make_return_edges().', func_addr)
                continue

            endpoints = self._get_return_sources(func)

            # get all callers
            callers = self.model.get_predecessors(startpoint, jumpkind='Ijk_Call')

            # handle callers for tailcall optimizations if flag is enabled
            if self._detect_tail_calls and startpoint.addr in self._tail_calls:
                l.debug("Handling return address for tail call for func %x", func_addr)
                seen = set()
                tail_callers = self._get_tail_caller(startpoint, seen)
                callers.extend(tail_callers)

            # for each caller, since they all end with a call instruction, get the immediate successor
            return_targets = itertools.chain.from_iterable(
                self.model.get_successors(caller, excluding_fakeret=False, jumpkind='Ijk_FakeRet') for caller in callers
            )
            return_targets = set(return_targets)

            for ep in endpoints:
                src = self.model.get_any_node(ep.addr)
                for rt in return_targets:
                    if not src.instruction_addrs:
                        ins_addr = None
                    else:
                        if self.project.arch.branch_delay_slot:
                            if len(src.instruction_addrs) > 1:
                                ins_addr = src.instruction_addrs[-2]
                            else:
                                l.error('At %s: expecting more than one instruction. Only got one.', src)
                                ins_addr = None
                        else:
                            ins_addr = src.instruction_addrs[-1]

                    self._graph_add_edge(rt, src, 'Ijk_Ret', ins_addr, DEFAULT_STATEMENT)

    #
    # Function utils
    #

    def _function_add_node(self, cfg_node, function_addr):
        """
        Adds node to function manager, converting address to CodeNode if
        possible

        :param CFGNode cfg_node:    A CFGNode instance.
        :param int function_addr:   Address of the current function.
        :return: None
        """
        snippet = self._to_snippet(cfg_node=cfg_node)
        self.kb.functions._add_node(function_addr, snippet)

    def _function_add_transition_edge(self, dst_addr, src_node, src_func_addr, to_outside=False, dst_func_addr=None,
                                      stmt_idx=None, ins_addr=None, is_exception=False):
        """
        Add a transition edge to the function transiton map.

        :param int dst_addr: Address that the control flow transits to.
        :param CFGNode src_node: The source node that the control flow transits from.
        :param int src_func_addr: Function address.
        :return: True if the edge is correctly added. False if any exception occurred (for example, the target address
                 does not exist)
        :rtype: bool
        """

        try:
            target_node = self._nodes.get(dst_addr, None)
            if target_node is None:
                target_snippet = self._to_snippet(addr=dst_addr, base_state=self._base_state)
            else:
                target_snippet = self._to_snippet(cfg_node=target_node)

            if src_node is None:
                # Add this basic block into the function manager
                self.kb.functions._add_node(src_func_addr, target_snippet)
            else:
                src_snippet = self._to_snippet(cfg_node=src_node)
                if not to_outside:
                    self.kb.functions._add_transition_to(src_func_addr, src_snippet, target_snippet, stmt_idx=stmt_idx,
                                                         ins_addr=ins_addr, is_exception=is_exception
                                                         )
                else:
                    self.kb.functions._add_outside_transition_to(src_func_addr, src_snippet, target_snippet,
                                                                 to_function_addr=dst_func_addr,
                                                                 stmt_idx=stmt_idx, ins_addr=ins_addr,
                                                                 is_exception=is_exception,
                                                                 )
            return True
        except (SimMemoryError, SimEngineError):
            return False

    def _function_add_call_edge(self, addr, src_node, function_addr, syscall=False, stmt_idx=None, ins_addr=None):
        """
        Add a call edge to the function transition map.

        :param int addr: Address that is being called (callee).
        :param CFGNode src_node: The source CFG node (caller).
        :param int ret_addr: Address that returns to (in case the function returns).
        :param int function_addr: Function address..
        :param bool syscall: If this is a call to a syscall or not.
        :param int or str stmt_idx: Statement ID of this call.
        :param int or None ins_addr: Instruction address of this call.
        :return: True if the edge is added. False if any exception occurred.
        :rtype: bool
        """
        try:
            if src_node is None:
                self.kb.functions._add_node(function_addr, addr, syscall=syscall)
            else:
                src_snippet = self._to_snippet(cfg_node=src_node)

                return_to_outside = False

                ret_snippet = None

                self.kb.functions._add_call_to(function_addr, src_snippet, addr, ret_snippet, syscall=syscall,
                                               stmt_idx=stmt_idx, ins_addr=ins_addr,
                                               return_to_outside=return_to_outside,
                                               )
            return True
        except (SimMemoryError, SimEngineError):
            return False

    def _function_add_fakeret_edge(self, addr, src_node, src_func_addr, confirmed=None):
        """
        Generate CodeNodes for target and source, if no source node add node
        for function, otherwise creates fake return to in function manager

        :param int addr: target address
        :param angr.analyses.CFGNode src_node: source node
        :param int src_func_addr: address of function
        :param confirmed: used as attribute on eventual digraph
        :return: None
        """

        target_node = self._nodes.get(addr, None)
        if target_node is None:
            target_snippet = self._to_snippet(addr=addr, base_state=self._base_state)
        else:
            target_snippet = self._to_snippet(cfg_node=target_node)

        if src_node is None:
            self.kb.functions._add_node(src_func_addr, target_snippet)
        else:
            src_snippet = self._to_snippet(cfg_node=src_node)
            self.kb.functions._add_fakeret_to(src_func_addr, src_snippet, target_snippet, confirmed=confirmed)

    def _function_add_return_site(self, addr, function_addr):
        """
        Generate CodeNodes for target address, registers node for function to
        function manager as return site

        :param int addr: target address
        :param int function_addr: address of function
        :return: None
        """
        try:
            target = self._to_snippet(self._nodes[addr])
        except KeyError:
            target = addr

        self.kb.functions._add_return_from(function_addr, target)

    def _function_add_return_edge(self, return_from_addr, return_to_addr, function_addr):
        """
        Generate CodeNodes for return_to_addr, add this node for function to
        function manager generating new edge

        :param int return_from_addr: target address
        :param int return_to_addr: target address
        :param int function_addr: address of function
        :return: None
        """

        return_to_node = self._nodes.get(return_to_addr, None)
        if return_to_node is None:
            return_to_snippet = self._to_snippet(addr=return_to_addr, base_state=self._base_state)
            to_outside = False
        else:
            return_to_snippet = self._to_snippet(cfg_node=return_to_node)
            to_outside = return_to_node.function_address != function_addr

        self.kb.functions._add_return_from_call(function_addr, return_from_addr, return_to_snippet,
                                                to_outside=to_outside)

    #
    # Architecture-specific methods
    #

    def _arm_track_lr_on_stack(self, addr, irsb, function):
        """
        At the beginning of the basic block, we check if the first instruction stores the LR register onto the stack.
        If it does, we calculate the offset of that store, and record the offset in function.info.

        For instance, here is the disassembly of a THUMB mode function:

        000007E4  STR.W           LR, [SP,#var_4]!
        000007E8  MOV             R2, R1
        000007EA  SUB             SP, SP, #0xC
        000007EC  MOVS            R1, #0
        ...
        00000800  ADD             SP, SP, #0xC
        00000802  LDR.W           PC, [SP+4+var_4],#4

        The very last basic block has a jumpkind of Ijk_Boring, which is because VEX cannot do such complicated analysis
        to determine the real jumpkind.

        As we can see, instruction 7e4h stores LR at [sp-4], and at the end of this function, instruction 802 loads LR
        from [sp], then increments sp by 4. We execute the first instruction, and track the following things:
        - if the value from register LR is stored onto the stack.
        - the difference between the offset of the LR store on stack, and the SP after the store.

        If at the end of the function, the LR is read out from the stack at the exact same stack offset, we will change
        the jumpkind of the final IRSB to Ijk_Ret.

        This method can be enabled by setting "ret_jumpkind_heuristics", which is an architecture-specific option on
        ARM, to True.

        :param int addr: Address of the basic block.
        :param pyvex.IRSB irsb: The basic block object.
        :param Function function: The function instance.
        :return: None
        """

        if irsb.statements is None:
            return

        if 'lr_saved_on_stack' in function.info:
            return

        # if it does, we log it down to the Function object.
        lr_offset = self.project.arch.registers['lr'][0]
        sp_offset = self.project.arch.sp_offset
        initial_sp = 0x7fff0000
        initial_lr = 0xabcdef
        tmps = {}

        # pylint:disable=too-many-nested-blocks
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.IMark):
                if stmt.addr + stmt.delta != addr:
                    break
            elif isinstance(stmt, pyvex.IRStmt.WrTmp):
                data = stmt.data
                if isinstance(data, pyvex.IRExpr.Get):
                    if data.offset == sp_offset:
                        tmps[stmt.tmp] = initial_sp
                    elif data.offset == lr_offset:
                        tmps[stmt.tmp] = initial_lr
                elif isinstance(data, pyvex.IRExpr.Binop):
                    if data.op == 'Iop_Sub32':
                        arg0, arg1 = data.args
                        if isinstance(arg0, pyvex.IRExpr.RdTmp) and isinstance(arg1, pyvex.IRExpr.Const):
                            if arg0.tmp in tmps:
                                tmps[stmt.tmp] = tmps[arg0.tmp] - arg1.con.value

            elif isinstance(stmt, (pyvex.IRStmt.Store, pyvex.IRStmt.StoreG)):
                data = stmt.data
                storing_lr = False
                if isinstance(data, pyvex.IRExpr.RdTmp):
                    if data.tmp in tmps:
                        val = tmps[data.tmp]
                        if val == initial_lr:
                            # we are storing LR to somewhere
                            storing_lr = True
                if storing_lr:
                    if isinstance(stmt.addr, pyvex.IRExpr.RdTmp):
                        if stmt.addr.tmp in tmps:
                            storing_addr = tmps[stmt.addr.tmp]

                            function.info['lr_saved_on_stack'] = True
                            function.info['lr_on_stack_offset'] = storing_addr - initial_sp
                            break

        if 'lr_saved_on_stack' not in function.info:
            function.info['lr_saved_on_stack'] = False

    def _arm_track_read_lr_from_stack(self, irsb, function):  # pylint:disable=unused-argument
        """
        At the end of a basic block, simulate the very last instruction to see if the return address is read from the
        stack and written in PC. If so, the jumpkind of this IRSB will be set to Ijk_Ret. For detailed explanations,
        please see the documentation of _arm_track_lr_on_stack().

        :param pyvex.IRSB irsb: The basic block object.
        :param Function function: The function instance.
        :return: None
        """

        if 'lr_saved_on_stack' not in function.info or not function.info['lr_saved_on_stack']:
            return

        sp_offset = self.project.arch.sp_offset
        initial_sp = 0x7fff0000
        last_sp = None
        tmps = {}
        tmp_irsb = self._lift(irsb.instruction_addresses[-1]).vex
        # pylint:disable=too-many-nested-blocks
        for stmt in tmp_irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.WrTmp):
                data = stmt.data
                if isinstance(data, pyvex.IRExpr.Get) and data.offset == sp_offset:
                    # t0 = GET:I32(sp)
                    tmps[stmt.tmp] = initial_sp
                elif isinstance(data, pyvex.IRExpr.Binop):
                    # only support Add
                    if data.op == 'Iop_Add32':
                        arg0, arg1 = data.args
                        if isinstance(arg0, pyvex.IRExpr.RdTmp) and isinstance(arg1, pyvex.IRExpr.Const):
                            if arg0.tmp in tmps:
                                tmps[stmt.tmp] = tmps[arg0.tmp] + arg1.con.value
                elif isinstance(data, pyvex.IRExpr.Load):
                    if isinstance(data.addr, pyvex.IRExpr.RdTmp):
                        if data.addr.tmp in tmps:
                            tmps[stmt.tmp] = ('load', tmps[data.addr.tmp])
            elif isinstance(stmt, pyvex.IRStmt.Put):
                if stmt.offset == sp_offset and isinstance(stmt.data, pyvex.IRExpr.RdTmp):
                    if stmt.data.tmp in tmps:
                        # loading things into sp
                        last_sp = tmps[stmt.data.tmp]

        if last_sp is not None and isinstance(tmp_irsb.next, pyvex.IRExpr.RdTmp):
            val = tmps.get(tmp_irsb.next.tmp, None)
            # val being None means there are statements that we do not handle
            if isinstance(val, tuple) and val[0] == 'load':
                # the value comes from memory
                memory_addr = val[1]
                if isinstance(last_sp, int):
                    lr_on_stack_offset = memory_addr - last_sp
                else:
                    lr_on_stack_offset = memory_addr - last_sp[1]

                if lr_on_stack_offset == function.info['lr_on_stack_offset']:
                    # the jumpkind should be Ret instead of boring
                    irsb.jumpkind = 'Ijk_Ret'

    #
    # Other methods
    #

    def _generate_cfgnode(self, cfg_job, current_function_addr):
        """
        Generate a CFGNode that starts at `cfg_job.addr`.

        Since lifting machine code to IRSBs is slow, self._nodes is used as a cache of CFGNodes.

        If the current architecture is ARM, this method will try to lift the block in the mode specified by the address
        (determined by the parity of the address: even for ARM, odd for THUMB), and in case of decoding failures, try
        the other mode. If the basic block is successfully decoded in the other mode (different from the initial one),
         `addr` and `current_function_addr` are updated.

        :param CFGJob cfg_job: The CFGJob instance.
        :param int current_function_addr: Address of the current function.
        :return: A 4-tuple of (new address, new function address, CFGNode instance, IRSB object)
        :rtype: tuple
        """

        addr = cfg_job.addr

        try:

            if addr in self._nodes:
                cfg_node = self._nodes[addr]
                irsb = cfg_node.irsb

                if cfg_node.function_address != current_function_addr:
                    # the node has been assigned to another function before.
                    # we should update the function address.
                    current_function_addr = cfg_node.function_address

                return addr, current_function_addr, cfg_node, irsb

            is_x86_x64_arch = self.project.arch.name in ('X86', 'AMD64')

            if is_arm_arch(self.project.arch):
                real_addr = addr & (~1)
            else:
                real_addr = addr

            distance = VEX_IRSB_MAX_SIZE
            # if there is exception handling code, check the distance between `addr` and the cloest ending address
            if self._exception_handling_by_endaddr:
                next_end = next(self._exception_handling_by_endaddr.irange(minimum=real_addr), None)
                if next_end is not None:
                    distance = min(distance, next_end - real_addr)

            # if possible, check the distance between `addr` and the end of this section
            obj = self.project.loader.find_object_containing(addr, membership_check=False)
            if obj:
                # is there a section?
                has_executable_section = self._object_has_executable_sections(obj)
                section = obj.find_section_containing(addr)
                if has_executable_section and section is None:
                    # the basic block should not exist here...
                    return None, None, None, None
                if section is not None:
                    if not section.is_executable:
                        # the section is not executable...
                        return None, None, None, None
                    distance_ = section.vaddr + section.memsize - real_addr
                    distance = min(distance_, VEX_IRSB_MAX_SIZE)
                # TODO: handle segment information as well

            # also check the distance between `addr` and the closest function.
            # we don't want to have a basic block that spans across function boundaries
            next_func = self.functions.ceiling_func(addr + 1)
            if next_func is not None:
                distance_to_func = (next_func.addr & (~1) if is_arm_arch(self.project.arch) else next_func.addr) - real_addr
                if distance_to_func != 0:
                    if distance is None:
                        distance = distance_to_func
                    else:
                        distance = min(distance, distance_to_func)

            # in the end, check the distance between `addr` and the closest occupied region in segment list
            next_noncode_addr = self._seg_list.next_pos_with_sort_not_in(addr, { "code" }, max_distance=distance)
            if next_noncode_addr is not None:
                distance_to_noncode_addr = next_noncode_addr - real_addr
                distance = min(distance, distance_to_noncode_addr)

            # Let's try to create the pyvex IRSB directly, since it's much faster
            nodecode = False
            irsb = None
            irsb_string = None
            lifted_block = None
            try:
                lifted_block = self._lift(addr, size=distance, collect_data_refs=True, strict_block_end=True)
                irsb = lifted_block.vex_nostmt
                irsb_string = lifted_block.bytes[:irsb.size]
            except SimTranslationError:
                nodecode = True

            if (nodecode or irsb.size == 0 or irsb.jumpkind == 'Ijk_NoDecode') and \
                    is_arm_arch(self.project.arch) and \
                    self._arch_options.switch_mode_on_nodecode:
                # maybe the current mode is wrong?
                nodecode = False
                if addr % 2 == 0:
                    addr_0 = addr + 1
                else:
                    addr_0 = addr - 1

                if addr_0 in self._nodes:
                    # it has been analyzed before
                    cfg_node = self._nodes[addr_0]
                    irsb = cfg_node.irsb
                    return addr_0, cfg_node.function_address, cfg_node, irsb

                try:
                    lifted_block = self._lift(addr_0, size=distance, collect_data_refs=True, strict_block_end=True)
                    irsb = lifted_block.vex_nostmt
                    irsb_string = lifted_block.bytes[:irsb.size]
                except SimTranslationError:
                    nodecode = True

                if not (nodecode or irsb.size == 0 or irsb.jumpkind == 'Ijk_NoDecode'):
                    # it is decodeable
                    if current_function_addr == addr:
                        current_function_addr = addr_0
                    addr = addr_0

            if nodecode or irsb.size == 0 or irsb.jumpkind == 'Ijk_NoDecode':
                # decoding error
                # is the current location already occupied and marked as non-code?
                # it happens in cases like the following:
                #
                #     BL a_nonreturning_func (but we don't know it does not return)
                #     alignment  (mov r8, r8)
                #  data_ref_0:
                #     DCD "type found!"
                #
                occupied_sort = self._seg_list.occupied_by_sort(real_addr)
                if occupied_sort and occupied_sort != "code":
                    # no wonder we cannot decode it
                    return None, None, None, None

                # we still occupy that location since it cannot be decoded anyways
                if irsb is None:
                    irsb_size = 0
                else:
                    irsb_size = irsb.size
                # special handling for ud, ud1, and ud2 on x86 and x86-64
                if irsb_string[-2:] == b'\x0f\x0b' and self.project.arch.name == 'AMD64':
                    # VEX supports ud2 and make it part of the block size, only in AMD64.
                    valid_ins = True
                    nodecode_size = 0
                elif lifted_block is not None \
                        and is_x86_x64_arch \
                        and len(lifted_block.bytes) - irsb_size > 2 \
                        and lifted_block.bytes[irsb_size : irsb_size + 2] in {
                            b'\x0f\xff',  # ud0
                            b'\x0f\xb9',  # ud1
                            b'\x0f\x0b',  # ud2
                        }:
                    # ud0, ud1, and ud2 are actually valid instructions.
                    valid_ins = True
                    # VEX does not support ud0 or ud1 or ud2 under AMD64. they are not part of the block size.
                    nodecode_size = 2
                else:
                    valid_ins = False
                    nodecode_size = 1
                self._seg_list.occupy(addr, irsb_size, 'code')
                self._seg_list.occupy(addr + irsb_size, nodecode_size, 'nodecode')
                if not valid_ins:
                    l.error("Decoding error occurred at address %#x of function %#x.",
                            addr + irsb_size,
                            current_function_addr
                            )
                    return None, None, None, None

            is_thumb = False
            # Occupy the block in segment list
            if irsb.size > 0:
                if is_arm_arch(self.project.arch) and addr % 2 == 1:
                    # thumb mode
                    is_thumb=True
                self._seg_list.occupy(real_addr, irsb.size, "code")

            # Create a CFG node, and add it to the graph
            cfg_node = CFGNode(addr, irsb.size, self.model,
                               function_address=current_function_addr,
                               block_id=addr,
                               irsb=irsb,
                               thumb=is_thumb,
                               byte_string=irsb_string,
                               )
            if self._cfb is not None:
                self._cfb.add_obj(addr, lifted_block)

            self._nodes[addr] = cfg_node
            self._nodes_by_addr[addr].append(cfg_node)

            return addr, current_function_addr, cfg_node, irsb

        except (SimMemoryError, SimEngineError):
            return None, None, None, None

    def _process_block_arch_specific(self, addr, irsb, func_addr):  # pylint: disable=unused-argument
        """
        According to arch types ['ARMEL', 'ARMHF', 'MIPS32'] does different
        fixes

        For ARM deals with link register on the stack
        (see _arm_track_lr_on_stack)
        For MIPS32 simulates a new state where the global pointer is 0xffffffff
        from current address after three steps if the first successor does not
        adjust this value updates this function address (in function manager)
        to use a conrete global pointer

        :param int addr: irsb address
        :param pyvex.IRSB irsb: irsb
        :param func_addr: function address
        :return: None
        """
        if is_arm_arch(self.project.arch):
            if self._arch_options.ret_jumpkind_heuristics:
                if addr == func_addr:
                    self._arm_track_lr_on_stack(addr, irsb, self.functions[func_addr])

                elif 'lr_saved_on_stack' in self.functions[func_addr].info and \
                        self.functions[func_addr].info['lr_saved_on_stack'] and \
                        irsb.jumpkind == 'Ijk_Boring' and \
                        irsb.next is not None and \
                        isinstance(irsb.next, pyvex.IRExpr.RdTmp):
                    # do a bunch of checks to avoid unnecessary simulation from happening
                    self._arm_track_read_lr_from_stack(irsb, self.functions[func_addr])

        elif self.project.arch.name in {"MIPS32", "MIPS64"}:
            function = self.kb.functions.function(func_addr)
            if addr >= func_addr and addr - func_addr < 15 * 4 and 'gp' not in function.info:
                # check if gp is being written to
                last_gp_setting_insn_id = None
                insn_ctr = 0

                if not irsb.statements:
                    # Get an IRSB with statements
                    irsb = self.project.factory.block(irsb.addr, size=irsb.size, opt_level=1, cross_insn_opt=False).vex

                for stmt in irsb.statements:
                    if isinstance(stmt, pyvex.IRStmt.IMark):
                        insn_ctr += 1
                        if insn_ctr >= 10:
                            break
                    elif isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == self.project.arch.registers['gp'][0]:
                        last_gp_setting_insn_id = insn_ctr
                        break

                if last_gp_setting_insn_id is None:
                    return

                # Prudently search for $gp values
                state = self.project.factory.blank_state(addr=addr, mode="fastpath",
                                                         remove_options={o.OPTIMIZE_IR}
                                                         )
                state.regs.t9 = func_addr
                state.regs.gp = 0xffffffff
                try:
                    succ = self.project.factory.successors(state, num_inst=last_gp_setting_insn_id + 1)
                except SimIRSBNoDecodeError:
                    # if last_gp_setting_insn_id is the last instruction, a SimIRSBNoDecodeError will be raised since
                    # there is no instruction left in the current block
                    return

                if not succ.flat_successors:
                    return

                state = succ.flat_successors[0]
                if not state.regs.gp.symbolic and state.solver.is_false(state.regs.gp == 0xffffffff):
                    function.info['gp'] = state.regs.gp._model_concrete.value

    def _find_thunks(self):
        if self.project.arch.name not in self.SPECIAL_THUNKS:
            return {}
        result = {}
        for code, meaning in self.SPECIAL_THUNKS[self.project.arch.name].items():
            for addr in self.project.loader.memory.find(code):
                if self._addr_in_exec_memory_regions(addr):
                    result[addr] = meaning

        return result

    def _lift(self, addr, *args, opt_level=1, cross_insn_opt=False, **kwargs): # pylint:disable=arguments-differ
        kwargs['extra_stop_points'] = set(self._known_thunks)
        if self._use_patches:
            # let's see if there is a patch at this location
            all_patches = self.kb.patches.get_all_patches(addr, VEX_IRSB_MAX_SIZE)
            if all_patches:
                # Use bytes from patches instead
                offset = addr
                byte_string = b""
                for p in all_patches:
                    if offset < p.addr:
                        byte_string += self._fast_memory_load_bytes(offset, p.addr - offset)
                        offset = p.addr
                    assert p.addr <= offset < p.addr + len(p)
                    byte_string += p.new_bytes[offset - p.addr: min(VEX_IRSB_MAX_SIZE - (offset-addr), p.addr + len(p) - offset)]
                    offset = p.addr + len(p)
                kwargs['byte_string'] = byte_string
        return super(CFGFast, self)._lift(addr, *args, opt_level=opt_level, cross_insn_opt=cross_insn_opt, **kwargs)

    #
    # Public methods
    #

    def copy(self):
        n = CFGFast.__new__(CFGFast)

        for attr, value in self.__dict__.items():
            if attr.startswith('__') and attr.endswith('__'):
                continue
            setattr(n, attr, value)

        n._exec_mem_regions = self._exec_mem_regions[::]
        n._seg_list = self._seg_list.copy()
        n._function_addresses_from_symbols = self._function_addresses_from_symbols.copy()

        n._model = self._model.copy()

        return n

    def output(self):
        s = "%s" % self._graph.edges(data=True)

        return s

    @deprecated(replacement="angr.analyses.CFB")
    def generate_code_cover(self):
        """
        Generate a list of all recovered basic blocks.
        """

        lst = []
        for cfg_node in self.graph.nodes():
            size = cfg_node.size
            lst.append((cfg_node.addr, size))

        lst = sorted(lst, key=lambda x: x[0])
        return lst


from angr.analyses import AnalysesHub
AnalysesHub.register_default('CFGFast', CFGFast)
