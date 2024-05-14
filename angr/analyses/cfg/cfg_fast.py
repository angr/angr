# pylint:disable=superfluous-parens,too-many-boolean-expressions,line-too-long
import itertools
import logging
import math
import re
import string
from typing import DefaultDict
from collections import defaultdict, OrderedDict
from enum import Enum, unique

import networkx
from sortedcontainers import SortedDict
import capstone

import claripy
import cle
import pyvex
from cle.address_translator import AT
from archinfo import Endness
from archinfo.arch_soot import SootAddressDescriptor
from archinfo.arch_arm import is_arm_arch, get_real_address_if_arm

from angr.analyses import AnalysesHub
from angr.knowledge_plugins.cfg import CFGNode, MemoryDataSort, MemoryData, IndirectJump, IndirectJumpType
from angr.knowledge_plugins.xrefs import XRef, XRefType
from angr.knowledge_plugins.functions import Function
from angr.misc.ux import deprecated
from angr.codenode import HookNode
from angr import sim_options as o
from angr.errors import (
    AngrCFGError,
    AngrSkipJobNotice,
    AngrUnsupportedSyscallError,
    SimEngineError,
    SimMemoryError,
    SimTranslationError,
    SimValueError,
    SimOperationError,
    SimError,
    SimIRSBNoDecodeError,
)
from angr.utils.constants import DEFAULT_STATEMENT
from angr.utils.funcid import (
    is_function_security_check_cookie,
    is_function_security_init_cookie,
    is_function_security_init_cookie_win8,
    is_function_likely_security_init_cookie,
)
from angr.analyses import ForwardAnalysis
from angr.utils.segment_list import SegmentList
from .cfg_arch_options import CFGArchOptions
from .cfg_base import CFGBase
from .indirect_jump_resolvers.jumptable import JumpTableResolver


VEX_IRSB_MAX_SIZE = 400


l = logging.getLogger(name=__name__)


class ContinueScanningNotification(RuntimeError):
    """
    A notification raised by _next_code_addr_core() to indicate no code address is found and _next_code_addr_core()
    should be invoked again.
    """


class ARMDecodingMode:
    """
    Enums indicating decoding mode for ARM code.
    """

    ARM = 0
    THUMB = 1


class DecodingAssumption:
    """
    Describes the decoding mode (ARM/THUMB) for a given basic block identified by its address.
    """

    def __init__(self, addr: int, size: int, mode: int):
        self.addr = addr
        self.size = size
        self.mode = mode
        self.attempted_arm = mode == ARMDecodingMode.ARM
        self.attempted_thumb = mode == ARMDecodingMode.THUMB
        self.data_segs = None

    def add_data_seg(self, addr: int, size: int) -> None:
        if self.data_segs is None:
            self.data_segs = set()
        self.data_segs.add((addr, size))


class FunctionReturn:
    """
    FunctionReturn describes a function call in a specific location and its return location. Hashable and equatable
    """

    __slots__ = (
        "callee_func_addr",
        "caller_func_addr",
        "call_site_addr",
        "return_to",
    )

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
        return (
            self.callee_func_addr == other.callee_func_addr
            and self.caller_func_addr == other.caller_func_addr
            and self.call_site_addr == other.call_site_addr
            and self.return_to == other.return_to
        )

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

    def _pop_job(self, func_addr: int | None):
        jobs = self._jobs[func_addr]
        j = jobs.pop(-1)
        if not jobs:
            del self._jobs[func_addr]
        self._job_count -= 1
        return j

    def add_job(self, job):
        func_addr = job.returning_source
        if func_addr not in self._jobs:
            self._jobs[func_addr] = []
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
            if None in self._jobs:
                # return sites for indirect calls are all put under the None key. in the majority of cases, indirect
                # calls are returning.
                return self._pop_job(None)
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
                    l.warning(
                        "An expected function at %s is not found. Please report it to Fish.",
                        pe.returning_source if pe.returning_source is not None else "None",
                    )
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
    """
    Describes an edge in functions' transition graphs. Base class for all types of edges.
    """

    __slots__ = (
        "src_func_addr",
        "stmt_idx",
        "ins_addr",
    )

    def apply(self, cfg):
        raise NotImplementedError()


class FunctionTransitionEdge(FunctionEdge):
    """
    Describes a transition edge in functions' transition graphs.
    """

    __slots__ = (
        "src_node",
        "dst_addr",
        "to_outside",
        "dst_func_addr",
        "is_exception",
    )

    def __init__(
        self,
        src_node,
        dst_addr,
        src_func_addr,
        to_outside=False,
        dst_func_addr=None,
        stmt_idx=None,
        ins_addr=None,
        is_exception=False,
    ):
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
    """
    Describes a call edge in functions' transition graphs.
    """

    __slots__ = ("src_node", "dst_addr", "ret_addr", "syscall")

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
    """
    Describes a FakeReturn (also called fall-through) edge in functions' transition graphs.
    """

    __slots__ = ("src_node", "dst_addr", "confirmed")

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
    """
    Describes a return (from a function call or a syscall) edge in functions' transition graphs.
    """

    __slots__ = ("ret_from_addr", "ret_to_addr", "dst_func_addr")

    def __init__(self, ret_from_addr, ret_to_addr, dst_func_addr):
        self.ret_from_addr = ret_from_addr
        self.ret_to_addr = ret_to_addr
        self.dst_func_addr = dst_func_addr

    def apply(self, cfg):
        return cfg._function_add_return_edge(self.ret_from_addr, self.ret_to_addr, self.dst_func_addr)


#
# CFGJob
#


@unique
class CFGJobType(Enum):
    """
    Defines the type of work of a CFGJob
    """

    NORMAL = 0
    FUNCTION_PROLOGUE = 1
    COMPLETE_SCANNING = 2
    IFUNC_HINTS = 3
    DATAREF_HINTS = 4


class CFGJob:
    """
    Defines a job to work on during the CFG recovery
    """

    __slots__ = (
        "addr",
        "func_addr",
        "jumpkind",
        "ret_target",
        "last_addr",
        "src_node",
        "src_ins_addr",
        "src_stmt_idx",
        "returning_source",
        "syscall",
        "_func_edges",
        "job_type",
        "gp",
    )

    def __init__(
        self,
        addr: int,
        func_addr: int,
        jumpkind: str,
        ret_target: int | None = None,
        last_addr: int | None = None,
        src_node: CFGNode | None = None,
        src_ins_addr: int | None = None,
        src_stmt_idx: int | None = None,
        returning_source=None,
        syscall: bool = False,
        func_edges: list | None = None,
        job_type: CFGJobType = CFGJobType.NORMAL,
        gp: int | None = None,
    ):
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
        self.gp = gp  # Used in MIPS32/MIPS64. Value of the gp register in the caller function. Only set at call sites.

        self._func_edges = func_edges

    def add_function_edge(self, edge):
        if self._func_edges is None:
            self._func_edges = []
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
            return f"<CFGJob {self.addr}>"
        else:
            return "<CFGJob{} {:#08x} @ func {:#08x}>".format(
                " syscall" if self.syscall else "", self.addr, self.func_addr
            )

    def __eq__(self, other):
        return (
            self.addr == other.addr
            and self.func_addr == other.func_addr
            and self.jumpkind == other.jumpkind
            and self.ret_target == other.ret_target
            and self.last_addr == other.last_addr
            and self.src_node == other.src_node
            and self.src_stmt_idx == other.src_stmt_idx
            and self.src_ins_addr == other.src_ins_addr
            and self.returning_source == other.returning_source
            and self.syscall == other.syscall
            and self.job_type == other.job_type
            and self.gp == other.gp
        )

    def __hash__(self):
        return hash(
            (
                self.addr,
                self.func_addr,
                self.jumpkind,
                self.ret_target,
                self.last_addr,
                self.src_node,
                self.src_stmt_idx,
                self.src_ins_addr,
                self.returning_source,
                self.syscall,
                self.job_type,
                self.gp,
            )
        )


class CFGFast(ForwardAnalysis[CFGNode, CFGNode, CFGJob, int], CFGBase):  # pylint: disable=abstract-method
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
        "AMD64": {
            bytes.fromhex("E807000000F3900FAEE8EBF9488D642408C3"): ("ret",),
            bytes.fromhex("E807000000F3900FAEE8EBF948890424C3"): ("jmp", "rax"),
        }
    }

    tag = "CFGFast"

    def __init__(
        self,
        binary=None,
        objects=None,
        regions=None,
        pickle_intermediate_results=False,
        symbols=True,
        function_prologues=True,
        resolve_indirect_jumps=True,
        force_segment=False,
        force_smart_scan=True,
        force_complete_scan=False,
        indirect_jump_target_limit=100000,
        data_references=True,
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
        elf_eh_frame=True,
        exceptions=True,
        skip_unmapped_addrs=True,
        nodecode_window_size=512,
        nodecode_threshold=0.3,
        nodecode_step=16483,
        indirect_calls_always_return: bool | None = None,
        jumptable_resolver_resolves_calls: bool | None = None,
        start=None,  # deprecated
        end=None,  # deprecated
        collect_data_references=None,  # deprecated
        extra_cross_references=None,  # deprecated
        **extra_arch_options,
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
        :param skip_unmapped_addrs:     Ignore all branches into unmapped regions. True by default. You may want to set
                                        it to False if you are analyzing manually patched binaries or malware samples.
        :param indirect_calls_always_return:    Should CFG assume indirect calls must return or not. Assuming indirect
                                        calls must return will significantly reduce the number of constant propagation
                                        runs, but may reduce the overall CFG recovery precision when facing
                                        non-returning indirect calls. By default, we only assume indirect calls always
                                        return for large binaries (region > 50KB).
        :param jumptable_resolver_resolves_calls: Whether JumpTableResolver should resolve indirect calls or not. Most
                                        indirect calls in C++ binaries or UEFI binaries cannot be resolved using jump
                                        table resolver and must be resolved using their specific resolvers. By default,
                                        we will only disable JumpTableResolver from resolving indirect calls for large
                                        binaries (region > 50 KB).
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

        if start is not None or end is not None:
            l.warning(
                '"start" and "end" are deprecated and will be removed soon. Please use "regions" to specify one '
                "or more memory regions instead."
            )
            if regions is None:
                regions = [(start, end)]
            else:
                l.warning('"regions", "start", and "end" are all specified. Ignoring "start" and "end".')

        if binary is not None and not objects:
            objects = [binary]

        CFGBase.__init__(
            self,
            "fast",
            0,
            normalize=normalize,
            binary=binary,
            objects=objects,
            regions=regions,
            exclude_sparse_regions=exclude_sparse_regions,
            skip_specific_regions=skip_specific_regions,
            force_segment=force_segment,
            base_state=base_state,
            resolve_indirect_jumps=resolve_indirect_jumps,
            indirect_jump_resolvers=indirect_jump_resolvers,
            indirect_jump_target_limit=indirect_jump_target_limit,
            detect_tail_calls=detect_tail_calls,
            skip_unmapped_addrs=skip_unmapped_addrs,
            low_priority=low_priority,
            model=model,
        )

        # necessary warnings
        if collect_data_references is not None:
            l.warning(
                '"collect_data_references" is deprecated and will be removed soon. Please use '
                '"data_references" instead'
            )
            data_references = collect_data_references
        if extra_cross_references is not None:
            l.warning(
                '"extra_cross_references" is deprecated and will be removed soon. Please use '
                '"cross_references" instead'
            )
            cross_references = extra_cross_references

        # data references collection and force smart scan must be enabled at the same time. otherwise decoding errors
        # caused by decoding data will lead to incorrect cascading re-lifting, which is suboptimal
        if force_smart_scan and not data_references:
            l.warning(
                'It is recommended to enable "data_references" if "force_smart_scan" is enabled for best '
                'result. Otherwise you may want to disable "force_smart_scan" or enable '
                '"force_complete_scan".'
            )

        # smart complete scanning and naive complete scanning cannot be enabled at the same time
        if force_smart_scan and force_complete_scan:
            l.warning(
                'You cannot enable "force_smart_scan" and "force_complete_scan" at the same time. I am disabling '
                '"force_complete_scan".'
            )
            force_complete_scan = False

        self._pickle_intermediate_results = pickle_intermediate_results

        self._use_symbols = symbols
        self._use_function_prologues = function_prologues
        self._force_smart_scan = force_smart_scan
        self._force_complete_scan = force_complete_scan
        self._use_elf_eh_frame = elf_eh_frame
        self._use_exceptions = exceptions

        self._nodecode_window_size = nodecode_window_size
        self._nodecode_threshold = nodecode_threshold
        self._nodecode_step = nodecode_step
        self._indirect_calls_always_return = indirect_calls_always_return
        self._jumptable_resolver_resolve_calls = jumptable_resolver_resolves_calls

        if self._indirect_calls_always_return is None:
            # heuristics
            self._indirect_calls_always_return = self._regions_size >= 50_000

        if self._jumptable_resolver_resolve_calls is None:
            # heuristics
            self._jumptable_resolver_resolve_calls = self._regions_size < 50_000
        for ijr in self.indirect_jump_resolvers:
            if isinstance(ijr, JumpTableResolver):
                ijr.resolve_calls = self._jumptable_resolver_resolve_calls

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

        self._arch_options = (
            arch_options if arch_options is not None else CFGArchOptions(self.project.arch, **extra_arch_options)
        )

        self._data_type_guessing_handlers = [] if data_type_guessing_handlers is None else data_type_guessing_handlers

        self._cfb = cfb

        # mapping to all known thunks
        self._known_thunks = {}

        self._initial_state = None
        self._next_addr: int | None = None

        # Create the segment list
        self._seg_list = SegmentList()

        self._read_addr_to_run = defaultdict(list)
        self._write_addr_to_run = defaultdict(list)

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
        self._gp_value: int | None = None
        self._ro_region_cdata_cache: list | None = None
        self._job_ctr = 0
        self._decoding_assumptions: dict[int, DecodingAssumption] = {}
        self._decoding_assumption_relations = None

        # A mapping between address and the actual data in memory
        # self._memory_data = { }
        # A mapping between address of the instruction that's referencing the memory data and the memory data itself
        # self.insn_addr_to_memory_data = { }
        # self._graph = None

        # Start working!
        self._analyze()

    def __getstate__(self):
        d = dict(self.__dict__)
        d["_progress_callback"] = None
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
                entropy += -p_x * math.log(p_x, 2)
        return entropy

    #
    # Properties
    #

    @property
    def graph(self):
        return self._model.graph

    @property
    def _insn_addr_to_memory_data(self):
        l.warning("_insn_addr_to_memory_data has been made public and is deprecated. Please fix your code accordingly.")
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

    # Methods for scanning the entire image

    def _next_unscanned_addr(self, alignment=None):
        """
        Find the next address that we haven't processed

        :param alignment: Assures the address returns must be aligned by this number
        :return: An address to process next, or None if all addresses have been processed
        """

        # TODO: Take care of those functions that are already generated
        if self._next_addr is None:
            self._next_addr = curr_addr = self._get_min_addr()
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

    def _update_unscanned_addr(self, new_addr: int):
        if self._next_addr is not None and self._next_addr >= new_addr:
            self._next_addr = new_addr - 1

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
            # avoid commonly seen ambiguous cases
            if is_arm_arch(self.project.arch):
                # little endian
                sz_bytes = bytes(sz)
                if self.project.arch.memory_endness == Endness.LE:
                    if b"\x70\x47" in sz_bytes:  # bx lr
                        return 0
                if self.project.arch.memory_endness == Endness.BE:
                    if b"\x47\x70" in sz_bytes:  # bx lr
                        return 0
            l.debug("Got a string of %d chars", len(sz))
            string_length = len(sz) + 1
            return string_length

        # no string is found
        return 0

    def _scan_for_printable_widestrings(self, start_addr: int):
        addr = start_addr
        sz = []
        is_sz = True

        # Get data until we meet two null bytes
        while self._inside_regions(addr):
            l.debug("Searching address %x", addr)
            val0 = self._load_a_byte_as_int(addr)
            if val0 is None:
                break
            val1 = self._load_a_byte_as_int(addr + 1)
            if val1 is None:
                break
            if val0 == 0 and val1 == 0:
                if len(sz) <= 10:
                    is_sz = False
                break
            if val0 != 0 and val1 == 0 and val0 in self.PRINTABLES:
                sz += [val0, val1]
                addr += 2
                continue

            is_sz = False
            break

        if sz and is_sz:
            l.debug("Got a wide-string of %d wide chars", len(sz))
            string_length = len(sz) + 2
            return string_length

        # no wide string is found
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
            if string_length == 0:
                string_length = self._scan_for_printable_widestrings(start_addr)

            if string_length:
                self._seg_list.occupy(start_addr, string_length, "string")
                start_addr += string_length

            if self.project.arch.name in ("X86", "AMD64"):
                cc_length = self._scan_for_repeating_bytes(start_addr, 0xCC, threshold=1)
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
            self._seg_list.occupy(start_addr, instr_alignment - (start_addr % instr_alignment), "alignment")
            start_addr = start_addr - start_addr % instr_alignment + instr_alignment
            # trickiness: aligning the start_addr may create a new address that is outside any mapped region.
            if not self._inside_regions(start_addr):
                raise ContinueScanningNotification()

        return start_addr

    def _next_code_addr(self):
        while True:
            try:
                addr = self._next_code_addr_core()
            except ContinueScanningNotification:
                continue

            if addr is None:
                return None

            # if the new address is already occupied
            if not self._seg_list.is_occupied(addr):
                return addr

    def _nodecode_bytes_ratio(self, cutoff_addr: int, window_size: int) -> float:
        idx = self._seg_list.search(cutoff_addr - 1)
        if idx is None or idx >= len(self._seg_list):
            return 0.0
        segment = self._seg_list[idx]
        if segment.sort != "nodecode":
            return 0.0

        total_bytes = 0
        nodecode_bytes = 0
        while idx >= 0:
            segment = self._seg_list[idx]
            if segment.sort == "nodecode":
                nodecode_bytes += segment.size
            total_bytes += segment.size
            if total_bytes >= window_size:
                break
            idx -= 1

        if total_bytes < window_size:
            return 0.0

        return nodecode_bytes / total_bytes

    def _next_code_addr_smart(self) -> int | None:
        # in the smart scanning mode, if there are more than N consecutive no-decode cases, we skip an entire window of
        # bytes.
        nodecode_bytes_ratio = (
            0.0 if self._next_addr is None else self._nodecode_bytes_ratio(self._next_addr, self._nodecode_window_size)
        )
        if nodecode_bytes_ratio >= self._nodecode_threshold:
            next_allowed_addr = self._next_addr + self._nodecode_step
        else:
            next_allowed_addr = 0

        while True:
            try:
                addr = self._next_code_addr_core()
            except ContinueScanningNotification:
                continue

            if addr is None:
                return None

            # if the new address is already occupied
            if not self._seg_list.is_occupied(addr):
                if addr < next_allowed_addr:
                    self._seg_list.occupy(addr, self.project.arch.instruction_alignment, "skip")
                    continue
                return addr

    # Overridden methods from ForwardAnalysis

    def _job_key(self, job: CFGJob):
        return job.addr

    def _pre_analysis(self):
        # Call _initialize_cfg() before self.functions is used.
        self._initialize_cfg()

        # Scan for __x86_return_thunk and friends
        self._known_thunks = self._find_thunks()

        # Initialize variables used during analysis
        self._pending_jobs: PendingJobs = PendingJobs(self.functions, self._deregister_analysis_job)
        self._traced_addresses: set[int] = {a for a, n in self._nodes_by_addr.items() if n}
        self._function_returns = defaultdict(set)

        # Populate known objects in segment tracker
        # FIXME: Cache the segment list, or add a new CFG analysis state tracking object
        for n in self.model.nodes():
            self._seg_list.occupy(n.addr, n.size, "code")
        for d in self.model.memory_data.values():
            self._seg_list.occupy(d.addr, d.size, d.sort)

        # Sadly, not all calls to functions are explicitly made by call
        # instruction - they could be a jmp or b, or something else. So we
        # should record all exits from a single function, and then add
        # necessary calling edges in our call map during the post-processing
        # phase.
        self._function_exits: DefaultDict[int, set[int]] = defaultdict(set)

        # Create an initial state. Store it to self so we can use it globally.
        self._initial_state = self.project.factory.blank_state(
            mode="fastpath", add_options={o.SYMBOL_FILL_UNCONSTRAINED_MEMORY, o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
        )
        initial_options = self._initial_state.options - {o.TRACK_CONSTRAINTS} - o.refs
        initial_options |= {o.SUPER_FASTPATH}
        # initial_options.remove(o.COW_STATES)
        self._initial_state.options = initial_options

        # Process known exception handlings
        if self._use_exceptions:
            self._preprocess_exception_handlings()

        starting_points: set[int] = set()

        if self._use_symbols:
            starting_points |= self._function_addresses_from_symbols

        if self._use_elf_eh_frame:
            starting_points |= self._function_addresses_from_eh_frame

        if self._extra_function_starts:
            starting_points |= set(self._extra_function_starts)

        # Sort it
        sorted_starting_points: list[int] = sorted(list(starting_points), reverse=False)

        if self._start_at_entry and self.project.entry is not None and self._inside_regions(self.project.entry):
            if self.project.entry not in starting_points:
                # make sure self.project.entry is inserted
                sorted_starting_points = [self.project.entry] + sorted_starting_points
            else:
                # make sure project.entry is the first item
                sorted_starting_points.remove(self.project.entry)
                sorted_starting_points = [self.project.entry] + sorted_starting_points

        # Create jobs for all starting points
        for sp in sorted_starting_points:
            job = CFGJob(sp, sp, "Ijk_Boring", job_type=CFGJobType.NORMAL)
            self._insert_job(job)
            # register the job to function `sp`
            self._register_analysis_job(sp, job)

        self._updated_nonreturning_functions = set()

        if self._use_function_prologues and self.project.concrete_target is None:
            self._remaining_function_prologue_addrs = sorted(self._func_addrs_from_prologues())

        # assumption management
        self._decoding_assumptions: dict[int, DecodingAssumption] = {}
        self._decoding_assumption_relations = networkx.DiGraph()

        # register read-only regions to PyVEX
        self._lifter_register_readonly_regions()

        self._job_ctr = 0

    def _pre_job_handling(self, job: CFGJob):  # pylint:disable=arguments-differ
        """
        Some pre job-processing tasks, like update progress bar.

        :param CFGJob job: The CFGJob instance.
        :return: None
        """

        self._job_ctr += 1
        if self._low_priority:
            self._release_gil(self._job_ctr, 2000, 0.000001)

        # a new entry is picked. Deregister it
        self._deregister_analysis_job(job.func_addr, job)

        if not self._inside_regions(job.addr):
            obj = self.project.loader.find_object_containing(job.addr)
            if obj is not None and isinstance(obj, self._cle_pseudo_objects):
                pass
            else:
                # it's outside permitted regions. skip.
                if job.jumpkind == "Ijk_Call":
                    # still add call edges so we will not lose track of the functions later, especially in decompiler
                    _, _, cfg_node, _ = self._generate_cfgnode(job, job.func_addr)
                    if cfg_node is not None:
                        self._graph_add_edge(cfg_node, job.src_node, job.jumpkind, job.src_ins_addr, job.src_stmt_idx)
                    job.apply_function_edges(self, clear=True)
                raise AngrSkipJobNotice()

        # Do not calculate progress if the user doesn't care about the progress at all
        if self._show_progressbar or self._progress_callback:
            max_percentage_stage_1 = 50.0
            percentage = min(
                self._seg_list.occupied_size * max_percentage_stage_1 / self._regions_size, max_percentage_stage_1
            )
            self._update_progress(percentage, cfg=self)

    def _intra_analysis(self):
        pass

    def _get_successors(self, job: CFGJob) -> list[CFGJob]:  # type: ignore[override] # pylint:disable=arguments-differ
        # current_function_addr = job.func_addr
        # addr = job.addr

        # if current_function_addr != -1:
        #    l.debug("Tracing new exit %#x in function %#x", addr, current_function_addr)
        # else:
        #    l.debug("Tracing new exit %#x", addr)

        jobs = self._scan_block(job)

        # l.debug("... got %d jobs: %s", len(jobs), jobs)

        job_: CFGJob
        for job_ in jobs:
            # register those jobs
            self._register_analysis_job(job_.func_addr, job_)

        return jobs

    def _handle_successor(self, job, successor, successors):
        return [successor]

    def _merge_jobs(self, *jobs):
        pass

    def _widen_jobs(self, *jobs):
        pass

    def _post_process_successors(self, irsb, successors):
        if is_arm_arch(self.project.arch):
            if irsb.addr % 2 == 1:
                # we are in thumb mode. filter successors
                successors = self._arm_thumb_filter_jump_successors(
                    irsb,
                    successors,
                    lambda tpl: tpl[1],
                    lambda tpl: tpl[0],
                    lambda tpl: tpl[3],
                )

            # make sure we don't jump to the beginning of another function with a different mode
            filtered_successors = []
            for successor in successors:
                addr_v = successor[2]
                if isinstance(addr_v, pyvex.expr.Const):
                    addr = addr_v.con.value
                elif isinstance(addr_v, int):
                    addr = addr_v
                else:
                    # do nothing
                    filtered_successors.append(successor)
                    continue
                if addr % 2 == 1:
                    # THUMB mode - test if there is an existing ARM function
                    addr_to_test = addr - 1
                else:
                    # ARM mode - test if there is an existing THUMB function
                    addr_to_test = addr + 1
                if self.functions.contains_addr(addr_to_test):
                    # oops. skip it
                    continue
                filtered_successors.append(successor)
            successors = filtered_successors

        return successors

    def _post_job_handling(self, job, new_jobs, successors):
        pass

    def _function_completed(self, func_addr: int):
        if self._collect_data_ref and self.project is not None and ":" in self.project.arch.name:
            # this is a pcode arch - use Clinic to recover data references

            if not self.kb.functions.contains_addr(func_addr):
                return

            # we add an arbitrary limit to function sizes for now to ensure we are now slowing down CFG recovery by too
            # much. we can remove this limit once we significantly speed up RDA and Propagator.

            func = self.kb.functions.get_by_addr(func_addr)
            if func.is_plt or func.is_simprocedure or func.is_syscall:
                return
            if not (9 <= len(func.block_addrs_set) < 12):
                return

            from angr.analyses.decompiler.clinic import ClinicMode  # pylint:disable=wrong-import-position

            clinic = self.project.analyses.Clinic(func, mode=ClinicMode.COLLECT_DATA_REFS)
            for irsb_addr, refs in clinic.data_refs.items():
                self._process_irsb_data_refs(irsb_addr, refs)

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

                job = CFGJob(prolog_addr, prolog_addr, "Ijk_Boring", job_type=CFGJobType.FUNCTION_PROLOGUE)
                self._insert_job(job)
                self._register_analysis_job(prolog_addr, job)
                return

        if self._force_complete_scan or self._force_smart_scan:
            if self._force_smart_scan:
                addr = self._next_code_addr_smart()
            else:
                addr = self._next_code_addr()

            if addr is None:
                l.debug("Force-scan jumping failed")
            else:
                l.debug("Force-scanning to %#x", addr)

            if addr is not None:
                # if this is ARM and addr % 4 != 0, it has to be THUMB
                if is_arm_arch(self.project.arch):
                    if addr % 2 == 0 and addr % 4 != 0:
                        # it's not aligned by 4, so it's definitely not ARM mode
                        addr |= 1
                    else:
                        # load 8 bytes and test with THUMB-mode prologues
                        bytes_prefix = self._fast_memory_load_bytes(addr, 8)
                        if bytes_prefix is None:
                            # we are out of the mapped memory range - just return
                            return
                        if any(re.match(prolog, bytes_prefix) for prolog in self.project.arch.thumb_prologs):
                            addr |= 1

                    if addr % 2 == 0:
                        # another heuristics: take a look at the closest function. if it's THUMB mode, this address
                        # should be THUMB, too.
                        func = self.functions.floor_func(addr)
                        if func is None:
                            func = self.functions.ceiling_func(addr)
                        if func is not None and func.addr % 2 == 1:
                            addr |= 1
                            # print(f"GUESSING: {hex(addr)} because of function {repr(func)}.")

                job = CFGJob(addr, addr, "Ijk_Boring", last_addr=None, job_type=CFGJobType.COMPLETE_SCANNING)
                self._insert_job(job)
                self._register_analysis_job(addr, job)

    def _repair_edges(self):
        remaining_edges_to_repair = []

        for edge in self._model.edges_to_repair:
            (src, dst, data) = edge

            if not self._model.graph.has_node(src):
                continue  # Source no longer in the graph, drop it

            new_dst = self._model.get_any_node(dst.addr)
            if new_dst is None:
                # The node may be defined in a later edit. Keep it for subsequent analyses.
                l.debug("Cannot repair edge %s at this time, destination node does not exist", edge)
                remaining_edges_to_repair.append(edge)
                continue

            if not self._model.graph.has_edge(src, new_dst):
                l.debug("Repairing edge: %s", edge)
                self._graph_add_edge(new_dst, src, data["jumpkind"], data["ins_addr"], data["stmt_idx"])

        self._model.edges_to_repair = remaining_edges_to_repair

    def _post_analysis(self):
        self._repair_edges()

        self._make_completed_functions()

        if self._normalize:
            # Normalize the control flow graph first before rediscovering all functions
            self.normalize()

        if self.project.arch.name in ("X86", "AMD64", "MIPS32"):
            self._remove_redundant_overlapping_blocks()
        elif is_arm_arch(self.project.arch):
            self._remove_redundant_overlapping_blocks(function_alignment=4, is_arm=True)

        self._updated_nonreturning_functions = set()
        # Revisit all edges and rebuild all functions to correctly handle returning/non-returning functions.
        self.make_functions()

        self._analyze_all_function_features(all_funcs_completed=True)

        # Scan all functions, and make sure all fake ret edges are either confirmed or removed
        for f in self.functions.values():
            all_edges = f.transition_graph.edges(data=True)

            callsites_to_functions = defaultdict(list)  # callsites to functions mapping

            for src, dst, data in all_edges:
                if "type" in data:
                    if data["type"] == "call":
                        callsites_to_functions[src.addr].append(dst.addr)

            edges_to_remove = []
            for src, dst, data in all_edges:
                if "type" in data:
                    if data["type"] == "fake_return" and data.get("confirmed", False) is False:
                        # Get all possible functions being called here
                        target_funcs = [
                            self.functions.function(addr=func_addr) for func_addr in callsites_to_functions[src.addr]
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

        # optional: find and mark functions that must be alignments
        self.mark_function_alignments()

        # make return edges
        self._make_return_edges()

        if self.project.arch.name != "Soot":
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
            r = self.model.tidy_data_references(
                exec_mem_regions=self._exec_mem_regions,
                xrefs=self.kb.xrefs,
                seg_list=self._seg_list,
                data_type_guessing_handlers=self._data_type_guessing_handlers,
            )

        if self._collect_data_ref:
            self._post_process_string_references()

        self._rename_common_functions_and_symbols()

        CFGBase._post_analysis(self)

        # Clean up
        self._traced_addresses = None
        self._lifter_deregister_readonly_regions()

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

    def _rename_common_functions_and_symbols(self):
        """
        This function implements logic for renaming some commonly seen functions in an architecture- and OS-specific
        way.
        """

        if (
            self.project.simos is not None
            and self.project.arch.name == "AMD64"
            and self.project.simos.name == "Win32"
            and isinstance(self.project.loader.main_object, cle.PE)
        ):
            security_cookie_addr = self.project.loader.main_object.load_config.get("SecurityCookie", None)
            security_check_cookie_found = False
            security_init_cookie_found = False
            if security_cookie_addr is not None:
                if security_cookie_addr not in self.kb.labels:
                    self.kb.labels[security_cookie_addr] = "_security_cookie"
                # identify _security_init_cookie and _security_check_cookie
                xrefs = self.kb.xrefs.get_xrefs_by_dst(security_cookie_addr)
                tested_func_addrs = set()
                for xref in xrefs:
                    cfg_node = self.model.get_any_node(xref.block_addr)
                    if cfg_node is None:
                        continue
                    func_addr = cfg_node.function_address
                    if func_addr not in tested_func_addrs:
                        func = self.kb.functions.get_by_addr(func_addr)
                        if not security_check_cookie_found and is_function_security_check_cookie(
                            func, self.project, security_cookie_addr
                        ):
                            security_check_cookie_found = True
                            func.is_default_name = False
                            func.name = "_security_check_cookie"
                        elif not security_init_cookie_found and is_function_security_init_cookie(
                            func, self.project, security_cookie_addr
                        ):
                            security_init_cookie_found = True
                            func.is_default_name = False
                            func.name = "_security_init_cookie"
                        elif not security_init_cookie_found and is_function_security_init_cookie_win8(
                            func, self.project, security_cookie_addr
                        ):
                            security_init_cookie_found = True
                            func.is_default_name = False
                            func.name = "_security_init_cookie"
                        tested_func_addrs.add(func_addr)
                    if security_init_cookie_found and security_check_cookie_found:
                        # both are found. exit from the loop
                        break

            # special handling: some binaries do not have SecurityCookie set, but still contain _security_init_cookie
            if security_init_cookie_found is False:
                start_func = self.functions.get_by_addr(self.project.entry)
                if start_func is not None:
                    for callee in start_func.transition_graph:
                        if isinstance(callee, Function):
                            if not security_init_cookie_found and is_function_likely_security_init_cookie(callee):
                                security_init_cookie_found = True
                                callee.is_default_name = False
                                callee.name = "_security_init_cookie"
                                break

    def _post_process_string_references(self) -> None:
        """
        Finds overlapping string references and retrofit them so that we see full strings in memory data.

        This function does not work well for Go binaries or any other binaries where a large non-null-terminating
        string table is used for all strings in the binary: All strings will be made much longer than they should have
        been. We try to accommodate these cases using UPDATE_RATIO.
        """

        MAX_STRING_SIZE = 256
        UPDATE_RATIO = 0.5

        all_memory_data = sorted(list(self.model.memory_data.items()), key=lambda x: x[0])  # sorted by addr
        to_update: dict[int, bytes] = {}
        total_string_refs: int = 0
        for i, (addr, md) in enumerate(all_memory_data):
            if not md.sort == MemoryDataSort.String:
                continue
            total_string_refs += 1
            if md.content is None:
                continue
            if md.size != len(md.content):
                # ending with a null byte
                continue

            new_content = md.content
            last_end_addr = addr + md.size
            for j in range(i + 1, len(all_memory_data)):
                _, next_md = all_memory_data[j]
                if (
                    next_md.addr == last_end_addr
                    and next_md.sort == MemoryDataSort.String
                    and next_md.content is not None
                ):
                    new_content += next_md.content
                    if next_md.size != len(next_md.content):
                        # ending with a null byte
                        break
                    # otherwise, continue
                    last_end_addr = next_md.addr + next_md.size
                else:
                    # another data item that's not a string or not immediately following the previous string item
                    break

                if len(new_content) > MAX_STRING_SIZE:
                    new_content = new_content[:MAX_STRING_SIZE]
                    break

            if len(new_content) > len(md.content):
                to_update[addr] = new_content

        ratio = 1.0 if total_string_refs == 0 else len(to_update) / total_string_refs
        if ratio < UPDATE_RATIO:
            # update!
            for addr, new_content in to_update.items():
                md = self.model.memory_data[addr]
                md.reference_size = len(new_content)
                md.content = new_content

    # Methods to get start points for scanning

    def _func_addrs_from_prologues(self):
        """
        Scan the entire program image for function prologues, and start code scanning at those positions

        :return: A list of possible function addresses
        """

        # Pre-compile all regexes
        regexes = []
        for ins_regex in self.project.arch.function_prologs:
            r = re.compile(ins_regex)
            regexes.append(r)
        # EDG says: I challenge anyone bothering to read this to come up with a better
        # way to handle CPU modes that affect instruction decoding.
        # Since the only one we care about is ARM/Thumb right now
        # we have this gross hack. Sorry about that.
        thumb_regexes = []
        if hasattr(self.project.arch, "thumb_prologs"):
            for ins_regex in self.project.arch.thumb_prologs:
                # Thumb prologues are found at even addrs, but their actual addr is odd!
                # Isn't that great?
                r = re.compile(ins_regex)
                thumb_regexes.append(r)

        # Construct the binary blob first
        unassured_functions = []

        is_arm = is_arm_arch(self.project.arch)

        for start_, bytes_ in self._binary.memory.backers():
            for regex in regexes:
                # Match them!
                for mo in regex.finditer(bytes_):
                    position = mo.start() + start_
                    if (not is_arm and position % self.project.arch.instruction_alignment == 0) or (
                        is_arm and position % 4 == 0
                    ):
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
                            unassured_functions.append(mapped_position + 1)

        l.info("Found %d functions with prologue scanning.", len(unassured_functions))
        return unassured_functions

    # Basic block scanning

    def _scan_block(self, cfg_job: CFGJob) -> list[CFGJob]:
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

    def _scan_procedure(self, cfg_job, current_func_addr) -> list[CFGJob]:
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
                assert procedure is not None
                name = procedure.display_name
            else:
                procedure = self.project.simos.syscall_from_addr(addr)
                assert procedure is not None
                name = procedure.display_name

            if addr not in self._nodes:
                cfg_node = CFGNode(
                    addr,
                    0,
                    self.model,
                    function_address=current_func_addr,
                    simprocedure_name=name,
                    no_ret=procedure.NO_RET,
                    block_id=addr,
                )
                self._model.add_node(addr, cfg_node)

            else:
                cfg_node = self._nodes[addr]

        except (SimMemoryError, SimEngineError):
            return []

        self._graph_add_edge(cfg_node, cfg_job.src_node, cfg_job.jumpkind, cfg_job.src_ins_addr, cfg_job.src_stmt_idx)
        self._function_add_node(cfg_node, current_func_addr)

        # Add edges going to this node in function graphs
        cfg_job.apply_function_edges(self, clear=True)

        # If we have traced it before, don't trace it anymore
        if addr in self._traced_addresses:
            return []
        else:
            # Mark the address as traced
            self._traced_addresses.add(addr)

        entries: list[CFGJob] = []

        if (
            cfg_job.src_node is not None
            and self.functions.contains_addr(cfg_job.src_node.addr)
            and self.functions[cfg_job.src_node.addr].is_default_name
            and cfg_job.src_node.addr not in self.kb.labels
            and cfg_job.jumpkind == "Ijk_Boring"
        ):
            # assign a name to the caller function that jumps to this procedure
            self.functions[cfg_job.src_node.addr].name = procedure.display_name

        if procedure.ADDS_EXITS:
            # Get two blocks ahead
            if cfg_job.src_node is None:
                l.warning("%s is supposed to yield new exits, but it fails to do so.", name)
                return []
            grandparent_nodes = list(self.graph.predecessors(cfg_job.src_node))
            grandparent_node = grandparent_nodes[0] if grandparent_nodes else None
            blocks_ahead = []
            if grandparent_node is not None:
                blocks_ahead.append(self._lift(grandparent_node.addr).vex)
            blocks_ahead.append(self._lift(cfg_job.src_node.addr).vex)
            procedure.project = self.project
            procedure.arch = self.project.arch
            new_exits = procedure.static_exits(blocks_ahead, cfg=self)

            for new_exit in new_exits:
                addr_ = new_exit["address"]
                jumpkind = new_exit["jumpkind"]
                namehint = new_exit.get("namehint", None)
                if (
                    isinstance(addr_, claripy.ast.BV) and not addr_.symbolic
                ):  # pylint:disable=isinstance-second-argument-not-valid-type
                    addr_ = addr_.concrete_value
                if not isinstance(addr_, int):
                    continue
                entries += self._create_jobs(
                    addr_,
                    jumpkind,
                    current_func_addr,
                    None,
                    addr_,
                    cfg_node,
                    None,
                    None,
                )
                if namehint:
                    if addr_ not in self.kb.labels or self.kb.labels[addr_] in {
                        "_ftext",
                    }:
                        unique_label = self.kb.labels.get_unique_label(namehint)
                        self.kb.labels[addr_] = unique_label

        # determine if this procedure returns
        if procedure.DYNAMIC_RET:
            # whether this procedure returns or not depends on the context
            # the procedure may return, but we will determine if we are inserting a fake_ret edge at each call site
            proc_returns = True
        else:
            proc_returns = not procedure.NO_RET

        if proc_returns:
            # it returns
            cfg_node.has_return = True
            self._function_exits[current_func_addr].add(addr)
            self._function_add_return_site(addr, current_func_addr)
        else:
            # the procedure does not return
            self._updated_nonreturning_functions.add(current_func_addr)
            cfg_node.no_ret = True  # update cfg_node
            self.kb.functions.get_by_addr(current_func_addr).returning = False

        return entries

    def _scan_irsb(self, cfg_job, current_func_addr) -> list[CFGJob]:
        """
        Generate a list of successors (generating them each as entries) to IRSB.
        Updates previous CFG nodes with edges.

        :param CFGJob cfg_job: The CFGJob instance.
        :param int current_func_addr: Address of the current function
        :return: a list of successors
        :rtype: list
        """
        addr, function_addr, cfg_node, irsb = self._generate_cfgnode(cfg_job, current_func_addr)

        # function_addr and current_function_addr can be different. e.g. when tracing an optimized tail-call that jumps
        # into another function that has been identified before.

        if cfg_node is None:
            # exceptions occurred, or we cannot get a CFGNode for other reasons
            return []

        # Add edges going to this node in function graphs
        cfg_job.apply_function_edges(self, clear=True)

        self._graph_add_edge(cfg_node, cfg_job.src_node, cfg_job.jumpkind, cfg_job.src_ins_addr, cfg_job.src_stmt_idx)
        self._function_add_node(cfg_node, function_addr)

        if self.functions.get_by_addr(function_addr).returning is not True:
            self._updated_nonreturning_functions.add(function_addr)

        if current_func_addr != function_addr:
            # the function address is updated by _generate_cfgnode() because the CFG node has been assigned to a
            # different function (`function_addr`) before. this can happen when the beginning block of a function is
            # first reached through a direct jump (as the result of tail-call optimization) and then reached through a
            # call.
            # this is very likely to be fixed during the second phase of CFG traversal, so we can just let it be.
            # however, extra call edges pointing to the expected function address (`current_func_addr`) will lead to
            # the creation of an empty function in function manager, and because the function is empty, we cannot
            # determine if the function will return or not!
            # assuming tail-call optimization is what is causing this situation, and if the original function has been
            # determined to be returning, we update the newly created function's returning status here.
            # this is still a hack. the complete solution is to record this situation and account for it when CFGBase
            # analyzes the returning status of each function. we will cross that bridge when we encounter such cases.
            if self.kb.functions[function_addr].returning is not None and self.kb.functions.contains_addr(
                current_func_addr
            ):
                self.kb.functions[current_func_addr].returning = self.kb.functions[function_addr].returning
                if self.kb.functions[current_func_addr].returning:
                    self._pending_jobs.add_returning_function(current_func_addr)

        # If we have traced it before, don't trace it anymore
        real_addr = get_real_address_if_arm(self.project.arch, addr)
        if real_addr in self._traced_addresses:
            # the address has been traced before
            return []
        else:
            # Mark the address as traced
            self._traced_addresses.add(real_addr)

        # irsb cannot be None here, but we add a check for resilience
        if irsb is None:
            return []

        # IRSB is only used once per CFGNode. We should be able to clean up the CFGNode here in order to save memory
        cfg_node.irsb = None

        caller_gp = None
        if self.project.arch.name in {"MIPS32", "MIPS64"}:
            # the caller might have gp passed on
            caller_gp = cfg_job.gp
        self._process_block_arch_specific(addr, cfg_node, irsb, function_addr, caller_gp=caller_gp)

        # Scan the basic block to collect data references
        if self._collect_data_ref:
            self._collect_data_references(irsb, addr)

        # Get all possible successors
        irsb_next, jumpkind = irsb.next, irsb.jumpkind
        successors = []

        if irsb.statements:
            last_ins_addr = None
            ins_addr = addr
            for i, stmt in enumerate(irsb.statements):
                if isinstance(stmt, pyvex.IRStmt.Exit):
                    branch_ins_addr = last_ins_addr if self.project.arch.branch_delay_slot else ins_addr
                    if self._is_branch_vex_artifact_only(irsb, branch_ins_addr, stmt):
                        continue
                    successors.append((i, branch_ins_addr, stmt.dst, stmt.jumpkind))
                elif isinstance(stmt, pyvex.IRStmt.IMark):
                    last_ins_addr = ins_addr
                    ins_addr = stmt.addr + stmt.delta
        else:
            for ins_addr, stmt_idx, exit_stmt in irsb.exit_statements:
                branch_ins_addr = ins_addr
                if (
                    self.project.arch.branch_delay_slot
                    and irsb.instruction_addresses
                    and ins_addr in irsb.instruction_addresses
                ):
                    idx_ = irsb.instruction_addresses.index(ins_addr)
                    if idx_ > 0:
                        branch_ins_addr = irsb.instruction_addresses[idx_ - 1]
                elif self._is_branch_vex_artifact_only(irsb, branch_ins_addr, exit_stmt):
                    continue
                successors.append((stmt_idx, branch_ins_addr, exit_stmt.dst, exit_stmt.jumpkind))

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
            successors.append((DEFAULT_STATEMENT, default_branch_ins_addr, exc.handler_addr, "Ijk_Exception"))

        entries = []

        successors = self._post_process_successors(irsb, successors)

        # Process each successor
        is_arm = is_arm_arch(self.project.arch)
        for suc in successors:
            stmt_idx, ins_addr, target, jumpkind = suc

            new_jobs = self._create_jobs(target, jumpkind, function_addr, irsb, addr, cfg_node, ins_addr, stmt_idx)
            entries += new_jobs
            if is_arm:
                for job in new_jobs:
                    if job.jumpkind in {"Ijk_Boring", "Ijk_FakeRet"}:
                        self._decoding_assumption_relations.add_edge(real_addr, job.addr & 0xFFFF_FFFE)

        return entries

    def _create_jobs(
        self, target, jumpkind, current_function_addr, irsb, addr, cfg_node, ins_addr, stmt_idx
    ) -> list[CFGJob]:
        """
        Given a node and details of a successor, makes a list of CFGJobs
        and if it is a call or exit marks it appropriately so in the CFG

        :param target:              Destination of the resultant job
        :param str jumpkind:        The jumpkind of the edge going to this node
        :param int current_function_addr: Address of the current function
        :param pyvex.IRSB irsb:     IRSB of the predecessor node
        :param int addr:            The predecessor address
        :param CFGNode cfg_node:    The CFGNode of the predecessor node
        :param int ins_addr:        Address of the source instruction.
        :param int stmt_idx:        ID of the source statement.
        :return:                    a list of CFGJobs
        """
        target_addr: int | None
        if type(target) is pyvex.IRExpr.Const:  # pylint: disable=unidiomatic-typecheck
            target_addr = target.con.value
        elif type(target) in (
            pyvex.IRConst.U8,
            pyvex.IRConst.U16,
            pyvex.IRConst.U32,
            pyvex.IRConst.U64,
        ):  # pylint: disable=unidiomatic-typecheck
            target_addr = target.value
        elif type(target) is int:  # pylint: disable=unidiomatic-typecheck
            target_addr = target
        else:
            target_addr = None

        if target_addr in self._known_thunks and jumpkind == "Ijk_Boring":
            thunk_kind = self._known_thunks[target_addr][0]
            if thunk_kind == "ret":
                jumpkind = "Ijk_Ret"
                target_addr = None
            elif thunk_kind == "jmp":
                pass  # ummmmmm not sure about this one
            else:
                raise AngrCFGError("This shouldn't be possible")

        jobs: list[CFGJob] = []
        is_syscall = jumpkind.startswith("Ijk_Sys")

        # Special handling:
        # If a call instruction has a target that points to the immediate next instruction, we treat it as a boring jump
        if (
            jumpkind == "Ijk_Call"
            and not self.project.arch.call_pushes_ret
            and cfg_node.instruction_addrs
            and ins_addr == cfg_node.instruction_addrs[-1]
            and target_addr == irsb.addr + irsb.size
        ):
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

            elif self._resolve_indirect_jumps and (
                jumpkind in ("Ijk_Boring", "Ijk_Call", "Ijk_InvalICache") or jumpkind.startswith("Ijk_Sys")
            ):
                # This is an indirect jump. Try to resolve it.
                # FIXME: in some cases, a statementless irsb will be missing its instr addresses
                # and this next part will fail. Use the real IRSB instead
                irsb = self._lift(cfg_node.addr, size=cfg_node.size).vex
                cfg_node.instruction_addrs = irsb.instruction_addresses
                resolved, resolved_targets, ij = self._indirect_jump_encountered(
                    addr, cfg_node, irsb, current_function_addr, stmt_idx
                )
                if resolved:
                    for resolved_target in resolved_targets:
                        if jumpkind == "Ijk_Call":
                            jobs += self._create_job_call(
                                cfg_node.addr,
                                irsb,
                                cfg_node,
                                stmt_idx,
                                ins_addr,
                                current_function_addr,
                                resolved_target,
                                jumpkind,
                            )
                        else:
                            to_outside, target_func_addr = self._is_branching_to_outside(
                                addr, resolved_target, current_function_addr
                            )
                            edge = FunctionTransitionEdge(
                                cfg_node,
                                resolved_target,
                                current_function_addr,
                                to_outside=to_outside,
                                stmt_idx=stmt_idx,
                                ins_addr=ins_addr,
                                dst_func_addr=target_func_addr,
                            )
                            ce = CFGJob(
                                resolved_target,
                                target_func_addr,
                                jumpkind,
                                last_addr=resolved_target,
                                src_node=cfg_node,
                                src_stmt_idx=stmt_idx,
                                src_ins_addr=ins_addr,
                                func_edges=[edge],
                            )
                            jobs.append(ce)
                    return jobs

                if ij is None:
                    # this is not a valid indirect jump. maybe it failed sanity checks.
                    # for example, `jr $v0` might show up in a MIPS binary without a following instruction (because
                    # decoding failed). in this case, `jr $v0` shouldn't be a valid instruction, either.
                    return []

                if jumpkind in ("Ijk_Boring", "Ijk_InvalICache"):
                    resolved_as_plt = False

                    if irsb and self._heuristic_plt_resolving:
                        # Test it on the initial state. Does it jump to a valid location?
                        # It will be resolved only if this is a .plt entry
                        resolved_as_plt = self._resolve_plt(addr, irsb, ij)

                        if resolved_as_plt:
                            # this is definitely a PLT stub
                            jump_target = next(iter(ij.resolved_targets))
                            target_func_addr = jump_target  # TODO: FIX THIS

                            edge = FunctionTransitionEdge(
                                cfg_node,
                                jump_target,
                                current_function_addr,
                                to_outside=True,
                                dst_func_addr=jump_target,
                                stmt_idx=stmt_idx,
                                ins_addr=ins_addr,
                            )
                            ce = CFGJob(
                                jump_target,
                                target_func_addr,
                                jumpkind,
                                last_addr=jump_target,
                                src_node=cfg_node,
                                src_stmt_idx=stmt_idx,
                                src_ins_addr=ins_addr,
                                func_edges=[edge],
                            )
                            jobs.append(ce)

                    if resolved_as_plt:
                        # has been resolved as a PLT entry. Remove it from indirect_jumps_to_resolve
                        if ij.addr in self._indirect_jumps_to_resolve:
                            self._indirect_jumps_to_resolve.remove(ij.addr)
                            self._deregister_analysis_job(current_function_addr, ij)
                    else:
                        is_plt = addr in self.functions and self.functions.get_by_addr(addr).is_plt
                        if is_plt:
                            # this is definitely a PLT entry, but we could not resolve it. this is probably due to
                            # missing SimProcedures. we do not want to resolve this indirect jump again in the future.
                            self._indirect_jump_unresolved(ij)
                        else:
                            # add it to indirect_jumps_to_resolve
                            self._indirect_jumps_to_resolve.add(ij)

                            # register it as a job for the current function
                            self._register_analysis_job(current_function_addr, ij)

                else:  # jumpkind == "Ijk_Call" or jumpkind.startswith('Ijk_Sys')
                    self._indirect_jumps_to_resolve.add(ij)
                    self._register_analysis_job(current_function_addr, ij)

                    jobs += self._create_job_call(
                        addr,
                        irsb,
                        cfg_node,
                        stmt_idx,
                        ins_addr,
                        current_function_addr,
                        None,
                        jumpkind,
                        is_syscall=is_syscall,
                    )

        elif target_addr is not None:
            # This is a direct jump with a concrete target.

            # pylint: disable=too-many-nested-blocks
            if jumpkind in {"Ijk_Boring", "Ijk_InvalICache", "Ijk_Exception"}:
                to_outside, target_func_addr = self._is_branching_to_outside(addr, target_addr, current_function_addr)
                edge = FunctionTransitionEdge(
                    cfg_node,
                    target_addr,
                    current_function_addr,
                    to_outside=to_outside,
                    dst_func_addr=target_func_addr,
                    ins_addr=ins_addr,
                    stmt_idx=stmt_idx,
                    is_exception=jumpkind == "Ijk_Exception",
                )

                ce = CFGJob(
                    target_addr,
                    target_func_addr,
                    jumpkind,
                    last_addr=addr,
                    src_node=cfg_node,
                    src_ins_addr=ins_addr,
                    src_stmt_idx=stmt_idx,
                    func_edges=[edge],
                )
                jobs.append(ce)

            elif jumpkind == "Ijk_Call" or jumpkind.startswith("Ijk_Sys"):
                jobs += self._create_job_call(
                    addr,
                    irsb,
                    cfg_node,
                    stmt_idx,
                    ins_addr,
                    current_function_addr,
                    target_addr,
                    jumpkind,
                    is_syscall=is_syscall,
                )

            else:
                # TODO: Support more jumpkinds
                l.debug("Unsupported jumpkind %s", jumpkind)
                if isinstance(ins_addr, int):
                    l.debug("Instruction address: %#x", ins_addr)

        return jobs

    def _create_job_call(
        self,
        addr: int,
        irsb: pyvex.IRSB,
        cfg_node: CFGNode,
        stmt_idx: int,
        ins_addr: int,
        current_function_addr: int,
        target_addr: int | None,
        jumpkind: str,
        is_syscall: bool = False,
    ) -> list[CFGJob]:
        """
        Generate a CFGJob for target address, also adding to _pending_entries
        if returning to succeeding position (if irsb arg is populated)

        :param addr:            Address of the predecessor node
        :param irsb:            IRSB of the predecessor node
        :param cfg_node:        The CFGNode instance of the predecessor node
        :param stmt_idx:        ID of the source statement
        :param ins_addr:        Address of the source instruction
        :param current_function_addr: Address of the current function
        :param target_addr:     Destination of the call
        :param jumpkind:        The jumpkind of the edge going to this node
        :param is_syscall:      Is the jump kind (and thus this) a system call
        :return:                A list of CFGJobs
        """

        jobs: list[CFGJob] = []

        if is_syscall:
            # Fix the target_addr for syscalls
            tmp_state = self.project.factory.blank_state(
                mode="fastpath",
                addr=cfg_node.addr,
                add_options={o.SYMBOL_FILL_UNCONSTRAINED_MEMORY, o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
            )
            # Find the first successor with a syscall jumpkind
            successors = self._simulate_block_with_resilience(tmp_state)
            if successors is not None:
                succ = next(
                    iter(
                        succ
                        for succ in successors.flat_successors
                        if succ.history.jumpkind and succ.history.jumpkind.startswith("Ijk_Sys")
                    ),
                    None,
                )
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
            if self.project.arch.name != "Soot":
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
            edge = FunctionCallEdge(
                cfg_node,
                new_function_addr,
                return_site,
                current_function_addr,
                syscall=is_syscall,
                ins_addr=ins_addr,
                stmt_idx=stmt_idx,
            )

        if new_function_addr is not None:
            # Keep tracing from the call
            ce = CFGJob(
                target_addr,
                new_function_addr,
                jumpkind,
                last_addr=addr,
                src_node=cfg_node,
                src_stmt_idx=stmt_idx,
                src_ins_addr=ins_addr,
                syscall=is_syscall,
                func_edges=[edge],
                gp=self.kb.functions[current_function_addr].info.get("gp", None),
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
                callee_might_return = callee_function.returning is not False

        if callee_might_return:
            func_edges = []
            if return_site is not None:
                call_returning: bool | None
                if callee_function is not None:
                    call_returning = self._is_call_returning(cfg_node, callee_function.addr)
                else:
                    call_returning = (
                        True if (new_function_addr is None and self._indirect_calls_always_return) else None
                    )

                if call_returning is True:
                    fakeret_edge = FunctionFakeRetEdge(cfg_node, return_site, current_function_addr, confirmed=True)
                    func_edges.append(fakeret_edge)
                    if new_function_addr is not None:
                        ret_edge = FunctionReturnEdge(new_function_addr, return_site, current_function_addr)
                        func_edges.append(ret_edge)

                    # Also, keep tracing from the return site
                    ce = CFGJob(
                        return_site,
                        current_function_addr,
                        "Ijk_FakeRet",
                        last_addr=addr,
                        src_node=cfg_node,
                        src_stmt_idx=stmt_idx,
                        src_ins_addr=ins_addr,
                        returning_source=new_function_addr,
                        syscall=is_syscall,
                        func_edges=func_edges,
                    )
                    self._pending_jobs.add_job(ce)
                    # register this job to this function
                    self._register_analysis_job(current_function_addr, ce)
                    # since the callee must return, we should let the pending_jobs be aware of it
                    self._pending_jobs.add_returning_function(new_function_addr)
                elif call_returning is None:
                    # HACK: We don't know where we are jumping.  Let's assume we fakeret to the
                    # next instruction after the block
                    # TODO: FIXME: There are arch-specific hints to give the correct ret site
                    # Such as looking for constant values of LR in this block for ARM stuff.
                    fakeret_edge = FunctionFakeRetEdge(cfg_node, return_site, current_function_addr, confirmed=None)
                    func_edges.append(fakeret_edge)
                    fr = FunctionReturn(new_function_addr, current_function_addr, addr, return_site)
                    if fr not in self._function_returns[new_function_addr]:
                        self._function_returns[new_function_addr].add(fr)
                    ce = CFGJob(
                        return_site,
                        current_function_addr,
                        "Ijk_FakeRet",
                        last_addr=addr,
                        src_node=cfg_node,
                        src_stmt_idx=stmt_idx,
                        src_ins_addr=ins_addr,
                        returning_source=new_function_addr,
                        syscall=is_syscall,
                        func_edges=func_edges,
                    )
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

        if self._skip_unmapped_addrs and not self._addrs_belong_to_same_section(src_addr, target_addr):
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
            self._process_irsb_data_refs(irsb.addr, irsb.data_refs)
        elif irsb.statements:
            # for each statement, collect all constants that are referenced or used.
            self._collect_data_references_by_scanning_stmts(irsb, irsb_addr)

    def _process_irsb_data_refs(self, irsb_addr, data_refs):
        assumption = self._decoding_assumptions.get(irsb_addr & ~1)
        for ref in data_refs:
            if ref.data_type_str == "integer(store)":
                data_type_str = "integer"
                is_store = True
            else:
                data_type_str = ref.data_type_str
                is_store = False

            if ref.data_size:
                # special logic: we do not call occupy for storing attempts in executable memory regions
                if not is_store or (is_store and not self._addr_in_exec_memory_regions(ref.data_addr)):
                    self._seg_list.occupy(ref.data_addr, ref.data_size, "unknown")
                    if assumption is not None:
                        assumption.add_data_seg(ref.data_addr, ref.data_size)

            self._add_data_reference(
                irsb_addr,
                ref.stmt_idx,
                ref.ins_addr,
                ref.data_addr,
                data_size=ref.data_size,
                data_type=data_type_str,
            )

            if ref.data_size == self.project.arch.bytes and is_arm_arch(self.project.arch):
                self._process_irsb_data_ref_inlined_data(irsb_addr, ref)

    def _process_irsb_data_ref_inlined_data(self, irsb_addr: int, ref):
        # ARM (and maybe a few other architectures as well) has inline pointers
        sec = self.project.loader.find_section_containing(ref.data_addr)
        if sec is not None and sec.is_readable and not sec.is_writable:
            # points to a non-writable region. read it out and see if there is another pointer!
            v = self._fast_memory_load_pointer(ref.data_addr, ref.data_size)

            # this value can either be a pointer or an offset from the pc... we need to try them both
            # attempt 1: a direct pointer
            sec_2nd = self.project.loader.find_section_containing(v)
            if sec_2nd is not None and sec_2nd.is_readable and not sec_2nd.is_writable:
                # found it!
                self._add_data_reference(
                    irsb_addr,
                    ref.stmt_idx,
                    ref.ins_addr,
                    v,
                    data_size=None,
                    data_type=MemoryDataSort.Unknown,
                )

                if sec_2nd.is_executable and not self._seg_list.is_occupied(v):
                    if v % self.project.arch.instruction_alignment == 0:
                        # create a new CFG job
                        ce = CFGJob(
                            v,
                            v,
                            "Ijk_Boring",
                            job_type=CFGJobType.DATAREF_HINTS,
                        )
                        self._pending_jobs.add_job(ce)
                        self._register_analysis_job(v, ce)

                return

            # attempt 2: pc + offset
            #   ldr r3, [pc, #0x328]
            #   add r3, pc
            # the pc to add to r3 is the address of that instruction + 4 (THUMB) or 8 (ARM)
            #
            # According to the spec:
            # In ARM state, the value of the PC is the address of the current instruction plus 8 bytes.
            # In Thumb state:
            # - For B, BL, CBNZ, and CBZ instructions, the value of the PC is the address of the current instruction
            #   plus 4 bytes.
            # - For all other instructions that use labels, the value of the PC is the address of the current
            #   instruction plus 4 bytes, with bit[1] of the result cleared to 0 to make it word-aligned.
            #
            if (irsb_addr & 1) == 1:
                actual_ref_ins_addr = ref.ins_addr + 2
                v += 4 + actual_ref_ins_addr
                v &= 0xFFFF_FFFF_FFFF_FFFE
            else:
                actual_ref_ins_addr = ref.ins_addr + 4
                v += 8 + actual_ref_ins_addr
            sec_3rd = self.project.loader.find_section_containing(v)
            if sec_3rd is not None and sec_3rd.is_readable and not sec_3rd.is_writable:
                # found it!
                self._add_data_reference(
                    irsb_addr, ref.stmt_idx, actual_ref_ins_addr, v, data_size=None, data_type=MemoryDataSort.Unknown
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

        # ARM-only: we need to simulate temps and registers to handle addresses that are coming from constant pools
        regs = {}
        tmps = {}

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
                    instr_addrs = instr_addrs[1:]
                    next_instr_addr = instr_addrs[0] if instr_addrs else None

            elif type(stmt) is pyvex.IRStmt.WrTmp:  # pylint: disable=unidiomatic-typecheck
                if type(stmt.data) is pyvex.IRExpr.Load:  # pylint: disable=unidiomatic-typecheck
                    # load
                    # e.g. t7 = LDle:I64(0x0000000000600ff8)
                    size = stmt.data.result_size(irsb.tyenv) // 8  # convert to bytes
                    _process(stmt_idx, stmt.data.addr, instr_addr, next_instr_addr, data_size=size, data_type="integer")
                    # if the architecture is ARM and it's loading from a constant, perform the actual load
                    if is_arm_arch(self.project.arch) and isinstance(stmt.data.addr, pyvex.IRExpr.Const):
                        read_addr = stmt.data.addr.con.value
                        v = self._fast_memory_load_pointer(read_addr, size)
                        if v is not None:
                            tmps[stmt.tmp] = v

                elif type(stmt.data) in (pyvex.IRExpr.Binop,):  # pylint: disable=unidiomatic-typecheck
                    # rip-related addressing
                    if stmt.data.op in ("Iop_Add32", "Iop_Add64"):
                        if all(type(arg) is pyvex.expr.Const for arg in stmt.data.args):
                            # perform the addition
                            loc = stmt.data.args[0].con.value + stmt.data.args[1].con.value
                            _process(stmt_idx, loc, instr_addr, next_instr_addr)
                            continue
                        if (
                            is_arm_arch(self.project.arch)
                            and isinstance(stmt.data.args[0], pyvex.expr.RdTmp)
                            and stmt.data.args[0].tmp in tmps
                            and type(stmt.data.args[1]) is pyvex.expr.Const
                        ):
                            # perform the addition
                            v = tmps[stmt.data.args[0].tmp]
                            loc = v + stmt.data.args[1].con.value
                            _process(stmt_idx, loc, instr_addr, next_instr_addr)
                            continue

                    # binary operation
                    for arg in stmt.data.args:
                        _process(stmt_idx, arg, instr_addr, next_instr_addr)

                elif type(stmt.data) is pyvex.IRExpr.Const:  # pylint: disable=unidiomatic-typecheck
                    _process(stmt_idx, stmt.data, instr_addr, next_instr_addr)

                elif type(stmt.data) is pyvex.IRExpr.ITE:
                    for child_expr in stmt.data.child_expressions:
                        _process(stmt_idx, child_expr, instr_addr, next_instr_addr)

                elif type(stmt.data) is pyvex.IRExpr.Get:
                    if is_arm_arch(self.project.arch) and stmt.data.offset in regs:
                        tmps[stmt.tmp] = regs[stmt.data.offset]

            elif type(stmt) is pyvex.IRStmt.Put:  # pylint: disable=unidiomatic-typecheck
                # put
                # e.g. PUT(rdi) = 0x0000000000400714
                is_itstate = is_arm_arch(self.project.arch) and stmt.offset == self.project.arch.registers["itstate"][0]
                if stmt.offset not in (self._initial_state.arch.ip_offset,) and not is_itstate:
                    _process(stmt_idx, stmt.data, instr_addr, next_instr_addr)

                if is_arm_arch(self.project.arch) and not is_itstate:
                    if type(stmt.data) is pyvex.IRExpr.RdTmp and stmt.data.tmp in tmps:
                        regs[stmt.offset] = tmps[stmt.data.tmp]
                    else:
                        if stmt.offset in regs:
                            del regs[stmt.offset]

            elif type(stmt) is pyvex.IRStmt.Store:  # pylint: disable=unidiomatic-typecheck
                # store addr
                _process(stmt_idx, stmt.addr, instr_addr, next_instr_addr)
                # store data
                _process(stmt_idx, stmt.data, instr_addr, next_instr_addr)

            elif type(stmt) is pyvex.IRStmt.Dirty:
                _process(
                    stmt_idx,
                    stmt.mAddr,
                    instr_addr,
                    next_instr_addr,
                    data_size=stmt.mSize,
                    data_type=MemoryDataSort.FloatingPoint,
                )

            elif type(stmt) is pyvex.IRStmt.LoadG:
                _process(
                    stmt_idx,
                    stmt.addr,
                    instr_addr,
                    next_instr_addr,
                    data_size=stmt.addr.result_size(irsb.tyenv) // self.project.arch.byte_width,
                )

    def _add_data_reference(
        self,
        irsb_addr: int,
        stmt_idx: int,
        insn_addr: int,
        data_addr: int,
        data_size: int | None = None,
        data_type: MemoryDataSort | None = None,
    ) -> None:
        """
        Checks addresses are in the correct segments and creates or updates
        MemoryData in _memory_data as appropriate, labelling as segment
        boundaries or data type

        :param irsb_addr:   Address of the IRSB
        :param stmt_idx:    Statement ID
        :param insn_addr:   Address of the instruction
        :param data_addr:   Address of data manipulated by statement
        :param data_size:   Size of the data being manipulated
        :param data_type:   Type of the data being manipulated
        """

        # Make sure data_addr is within a valid memory range
        if not self.project.loader.find_loadable_containing(data_addr):
            # data might be at the end of some section or segment...
            # let's take a look
            for segment in self.project.loader.main_object.segments:
                if segment.vaddr + segment.memsize == data_addr:
                    # yeah!
                    self.model.add_memory_data(data_addr, MemoryDataSort.SegmentBoundary, data_size=0)
                    cr = XRef(
                        ins_addr=insn_addr,
                        block_addr=irsb_addr,
                        stmt_idx=stmt_idx,
                        memory_data=self.model.memory_data[data_addr],
                        xref_type=XRefType.Offset,
                    )
                    self.kb.xrefs.add_xref(cr)
                    break

            return

        self.model.add_memory_data(data_addr, data_type, data_size=data_size)
        cr = XRef(
            ins_addr=insn_addr,
            block_addr=irsb_addr,
            stmt_idx=stmt_idx,
            memory_data=self.model.memory_data[data_addr],
            xref_type=XRefType.Offset,
        )
        self.kb.xrefs.add_xref(cr)

        if is_arm_arch(self.project.arch):
            if (irsb_addr & 1) == 1 and data_addr == (insn_addr & 0xFFFF_FFFF_FFFF_FFFE) + 4:
                return
            elif data_addr == insn_addr + 8:
                return
        self.insn_addr_to_memory_data[insn_addr] = self.model.memory_data[data_addr]

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
            if not any(addr in obj.reverse_plt for obj in self.project.loader.all_elf_objects):
                return False

        # Make sure the IRSB has statements
        if not irsb.has_statements:
            irsb = self.project.factory.block(irsb.addr, size=irsb.size, opt_level=1, cross_insn_opt=False).vex

        # try to resolve the jump target
        simsucc = self.project.factory.default_engine.process(self._initial_state, irsb, force_addr=addr)
        if len(simsucc.successors) == 1:
            ip = simsucc.successors[0].ip
            if ip._model_concrete is not ip:
                target_addr = ip.concrete_value
                obj = self.project.loader.find_object_containing(target_addr, membership_check=False)
                if (obj is not None and obj is not self.project.loader.main_object) or self.project.is_hooked(
                    target_addr
                ):
                    # resolved!
                    # Fill the IndirectJump object
                    indir_jump.resolved_targets.add(target_addr)
                    l.debug("Address %#x is resolved as a PLT entry, jumping to %#x", addr, target_addr)
                    return True

        return False

    def _indirect_jump_resolved(self, jump: IndirectJump, jump_addr, resolved_by, targets: list[int]):
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
                if self._collect_data_ref:
                    if jump.jumptable_addr in self._memory_data:
                        memory_data = self._memory_data[jump.jumptable_addr]
                        memory_data.size = jump.jumptable_size
                        memory_data.max_size = jump.jumptable_size
                        memory_data.sort = MemoryDataSort.Unknown
                    else:
                        memory_data = MemoryData(
                            jump.jumptable_addr,
                            jump.jumptable_size,
                            MemoryDataSort.Unknown,
                            max_size=jump.jumptable_size,
                        )
                        self._memory_data[jump.jumptable_addr] = memory_data

        jump.resolved_targets = targets
        all_targets = set(targets)
        for addr in all_targets:
            to_outside = (
                jump.jumpkind == "Ijk_Call"
                or jump.type == IndirectJumpType.Vtable
                or addr in self.functions
                or not self._addrs_belong_to_same_section(jump.addr, addr)
            )

            # TODO: get a better estimate of the function address
            if jump.type == IndirectJumpType.Vtable:
                target_func_addr = addr
                self.kb.functions.function(target_func_addr, create=True)  # make sure the target function exists
            else:
                target_func_addr = jump.func_addr if not to_outside else addr
            src_node = self._nodes[source_addr]
            if jump.jumpkind == "Ijk_Call":
                func_edge = FunctionCallEdge(
                    src_node,
                    addr,
                    src_node.addr + src_node.size,
                    jump.func_addr,
                    stmt_idx=jump.stmt_idx,
                    ins_addr=jump.ins_addr,
                )
            else:
                func_edge = FunctionTransitionEdge(
                    src_node, addr, jump.func_addr, to_outside=to_outside, dst_func_addr=target_func_addr
                )
            job = CFGJob(
                addr,
                target_func_addr,
                jump.jumpkind,
                last_addr=source_addr,
                src_node=src_node,
                src_ins_addr=jump.ins_addr,
                src_stmt_idx=jump.stmt_idx,
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

        # add a node from this node to UnresolvableJumpTarget or UnresolvableCallTarget node,
        # depending on its jump kind
        src_node = self._nodes[jump.addr]
        if jump.jumpkind == "Ijk_Boring":
            unresolvable_target_addr = self._unresolvable_jump_target_addr
            simprocedure_name = "UnresolvableJumpTarget"
        elif jump.jumpkind == "Ijk_Call":
            unresolvable_target_addr = self._unresolvable_call_target_addr
            simprocedure_name = "UnresolvableCallTarget"
        else:
            l.error("Unsupported jumpkind in _indirect_jump_unresolved: %s", jump.jumpkind)
            unresolvable_target_addr = self._unresolvable_jump_target_addr
            simprocedure_name = "UnresolvableJumpTarget"

        dst_node = CFGNode(
            unresolvable_target_addr,
            0,
            self.model,
            function_address=unresolvable_target_addr,
            simprocedure_name=simprocedure_name,
            block_id=unresolvable_target_addr,
        )

        # add the dst_node to self._nodes
        if unresolvable_target_addr not in self._nodes:
            self.model.add_node(unresolvable_target_addr, dst_node)

        self._graph_add_edge(dst_node, src_node, jump.jumpkind, jump.ins_addr, jump.stmt_idx)

        if jump.jumpkind == "Ijk_Boring":
            # mark it as a jumpout site for that function
            self._function_add_transition_edge(
                unresolvable_target_addr,
                src_node,
                jump.func_addr,
                to_outside=True,
                dst_func_addr=unresolvable_target_addr,
                ins_addr=jump.ins_addr,
                stmt_idx=jump.stmt_idx,
            )
        else:  # jump.jumpkind == 'Ijk_Call'
            # mark it as a call site for that function
            self._function_add_call_edge(
                unresolvable_target_addr,
                src_node,
                jump.func_addr,
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
                            l.warning(
                                "Multiple exception handlings ending at %#x. Please report it to GitHub.",
                                exc.start_addr + exc.size,
                            )
                            continue
                        self._exception_handling_by_endaddr[exc.start_addr + exc.size] = exc

        l.info(
            "Loaded %d exception handlings from %d binaries.",
            len(self._exception_handling_by_endaddr),
            bin_count,
        )

    # Removers

    def _remove_redundant_overlapping_blocks(self, function_alignment: int = 16, is_arm: bool = False):
        """
        On some architectures there are sometimes garbage bytes (usually nops) between functions in order to properly
        align the succeeding function. CFGFast does a linear sweeping which might create duplicated blocks for
        function epilogues where one block starts before the garbage bytes and the other starts after the garbage bytes.

        This method enumerates all blocks and remove overlapping blocks if one of them is aligned to the specified
        alignment and the other contains only garbage bytes.

        :return: None
        """

        sorted_nodes = sorted(self.graph.nodes(), key=lambda n: n.addr if n is not None else 0)

        all_plt_stub_addrs = set(
            itertools.chain.from_iterable(
                obj.reverse_plt.keys() for obj in self.project.loader.all_objects if isinstance(obj, cle.MetaELF)
            )
        )

        # go over the list. for each node that is the beginning of a function and is not properly aligned, if its
        # leading instruction is a single-byte or multi-byte nop, make sure there is another CFGNode starts after the
        # nop instruction

        nodes_to_append = {}
        # pylint:disable=too-many-nested-blocks
        for a in sorted_nodes:
            if (
                a.addr in self.functions
                and a.addr not in all_plt_stub_addrs
                and not self._addr_hooked_or_syscall(a.addr)
            ):
                all_in_edges = self.graph.in_edges(a, data=True)
                if not any(data["jumpkind"] == "Ijk_Call" for _, _, data in all_in_edges):
                    # no one is calling it
                    # this function might be created from linear sweeping
                    a_real_addr = a.addr & 0xFFFF_FFFE if is_arm else a.addr
                    try:
                        block = self._lift(a.addr, size=function_alignment - (a_real_addr % function_alignment))
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
                    if nop_length < a.size and not (next_node_addr in self._nodes or next_node_addr in nodes_to_append):
                        # create a new CFGNode that starts there
                        next_node_size = a.size - nop_length
                        next_node = CFGNode(
                            next_node_addr,
                            next_node_size,
                            self.model,
                            function_address=next_node_addr,
                            instruction_addrs=[
                                i for i in a.instruction_addrs if next_node_addr <= i < next_node_addr + next_node_size
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
                            snippet = self._to_snippet(
                                addr=next_node_addr, size=next_node_size, base_state=self._base_state
                            )
                            self.functions._add_node(next_node_addr, snippet)
                            # if there are outside transitions, copy them as well
                            for src, dst, data in self.functions[a.addr].transition_graph.edges(data=True):
                                if (
                                    src.addr == a.addr
                                    and data.get("type", None) == "transition"
                                    and data.get("outside", False) is True
                                ):
                                    stmt_idx = data.get("stmt_idx", None)
                                    if stmt_idx != DEFAULT_STATEMENT:
                                        # since we are relifting the block from a new starting address, we should only
                                        # keep stmt_idx if it is the default exit.
                                        stmt_idx = None
                                    self.functions._add_outside_transition_to(
                                        next_node_addr,
                                        snippet,
                                        dst,
                                        to_function_addr=dst.addr,
                                        ins_addr=data.get("ins_addr", None),
                                        stmt_idx=stmt_idx,
                                    )
                        except (SimEngineError, SimMemoryError):
                            continue

        # append all new nodes to sorted nodes
        if nodes_to_append:
            sorted_nodes = sorted(
                sorted_nodes + list(nodes_to_append.values()), key=lambda n: n.addr if n is not None else 0
            )

        removed_nodes = set()

        a = None  # it always holds the very recent non-removed node
        is_arm = is_arm_arch(self.project.arch)

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

            # handle ARM vs THUMB...
            if is_arm:
                a_real_addr = a.addr & 0xFFFF_FFFE
                b_real_addr = b.addr & 0xFFFF_FFFE
            else:
                a_real_addr = a.addr
                b_real_addr = b.addr

            if a_real_addr <= b_real_addr < a_real_addr + a.size:
                # They are overlapping

                try:
                    block = self.project.factory.fresh_block(
                        a.addr, b_real_addr - a_real_addr, backup_state=self._base_state
                    )
                except SimTranslationError:
                    a = b
                    continue
                if block.capstone.insns and all(self._is_noop_insn(insn) for insn in block.capstone.insns):
                    # It's a big nop - no function starts with nop

                    # add b to indices
                    self._model.add_node(b.addr, b)

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
                    in_edges = len([_ for _, _, data in self.graph.in_edges([b], data=True)])
                    if in_edges == 0 and b in self.graph:
                        # we use node a to replace node b
                        # link all successors of b to a
                        for _, dst, data in self.graph.out_edges([b], data=True):
                            self.graph.add_edge(a, dst, **data)

                        self._model.remove_node(b.addr, b)
                        self.graph.remove_node(b)

                        if b.addr in all_functions:
                            del all_functions[b.addr]

                        # skip b
                        removed_nodes.add(b)

                        continue

                # next case - if b is directly from function prologue detection, or a basic block that is a successor of
                # a wrongly identified basic block, we might be totally misdecoding b
                if b.instruction_addrs[0] not in a.instruction_addrs and b in self.graph:
                    # use a, truncate b

                    new_b_addr = a.addr + a.size  # b starts right after a terminates
                    new_b_size = b.addr + b.size - new_b_addr  # this may not be the size we want, since b might be
                    # misdecoded

                    # totally remove b
                    self._model.remove_node(b.addr, b)
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

            a = b  # update a

    def _remove_node(self, node):
        """
        Remove a CFGNode from self.graph as well as from the function manager (if it is the beginning of a function)

        :param CFGNode node: The CFGNode to remove from the graph.
        :return: None
        """

        self.graph.remove_node(node)
        self._model.remove_node(node.addr, node)

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
        new_node = CFGNode(
            node.addr,
            new_size,
            self.model,
            function_address=None if remove_function else node.function_address,
            instruction_addrs=[i for i in node.instruction_addrs if node.addr <= i < node.addr + new_size],
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
            successor = CFGNode(
                successor_node_addr,
                successor_size,
                self.model,
                function_address=successor_node_addr if remove_function else node.function_address,
                instruction_addrs=[i for i in node.instruction_addrs if i >= node.addr + new_size],
                thumb=node.thumb,
                byte_string=None if node.byte_string is None else node.byte_string[new_size:],
            )
        self.graph.add_edge(new_node, successor, jumpkind="Ijk_Boring")

        # if the node B already has resolved targets, we will skip all unresolvable successors when adding old out edges
        # from node A to node B.
        # this matters in cases where node B is resolved as a special indirect jump entry (like a PLT stub), but (node
        # A + node B) wasn't properly resolved.
        unresolvable_target_addrs = (self._unresolvable_jump_target_addr, self._unresolvable_call_target_addr)

        has_resolved_targets = any(
            node_.addr not in unresolvable_target_addrs for node_ in self.graph.successors(successor)
        )

        old_out_edges = self.graph.out_edges(node, data=True)
        for _, dst, data in old_out_edges:
            if (has_resolved_targets and dst.addr not in unresolvable_target_addrs) or not has_resolved_targets:
                self.graph.add_edge(successor, dst, **data)

        # remove the old node from indices
        self._model.remove_node(node.addr, node)

        # remove the old node form the graph
        self.graph.remove_node(node)

        # add the new node to indices
        self._model.add_node(new_node.addr, new_node)

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

        # if node.addr in self.kb.functions.callgraph:
        #    self.kb.functions.callgraph.remove_node(node.addr)

    def _analyze_all_function_features(self, all_funcs_completed=False):
        """
        Iteratively analyze all changed functions, update their returning attribute, until a fix-point is reached (i.e.
        no new returning/not-returning functions are found).

        :return: None
        """

        while True:
            new_changes = self._iteratively_analyze_function_features(all_funcs_completed=all_funcs_completed)
            new_returning_functions = new_changes["functions_return"]
            new_not_returning_functions = new_changes["functions_do_not_return"]

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

                        self.kb.functions._add_return_from_call(
                            fr.caller_func_addr, fr.callee_func_addr, return_to_snippet
                        )

                    del self._function_returns[returning_function.addr]

            for nonreturning_function in new_not_returning_functions:
                self._pending_jobs.add_nonreturning_function(nonreturning_function.addr)
                if nonreturning_function.addr in self._function_returns:
                    for fr in self._function_returns[nonreturning_function.addr]:
                        # Remove all pending FakeRet edges
                        if (
                            self.kb.functions.contains_addr(fr.caller_func_addr)
                            and self.kb.functions.get_by_addr(fr.caller_func_addr).returning is not True
                        ):
                            self._updated_nonreturning_functions.add(fr.caller_func_addr)

                    del self._function_returns[nonreturning_function.addr]

    def _pop_pending_job(self, returning=True) -> CFGJob | None:
        while self._pending_jobs:
            job = self._pending_jobs.pop_job(returning=returning)
            if job is not None and job.job_type == CFGJobType.DATAREF_HINTS and self._seg_list.is_occupied(job.addr):
                # ignore this hint from data refs because the target address has already been analyzed
                continue
            return job
        return None

    def _clean_pending_exits(self):
        self._pending_jobs.cleanup()

    #
    # Graph utils
    #

    def _graph_add_edge(
        self, cfg_node: CFGNode, src_node: CFGNode | None, src_jumpkind: str, src_ins_addr: int, src_stmt_idx: int
    ):
        """
        Add edge between nodes, or add node if entry point

        :param cfg_node: node which is jumped to
        :param src_node: node which is jumped from none if entry point
        :param src_jumpkind: what type of jump the edge takes
        :param src_stmt_idx: source statements ID
        :return: None
        """

        if src_node is None:
            self.graph.add_node(cfg_node)
        else:
            self.graph.add_edge(src_node, cfg_node, jumpkind=src_jumpkind, ins_addr=src_ins_addr, stmt_idx=src_stmt_idx)

    @staticmethod
    def _get_return_endpoints(func):
        all_endpoints = func.endpoints_with_type
        return all_endpoints.get("return", [])

    def _get_jumpout_targets(self, func):
        jumpout_targets = set()
        callgraph_outedges = self.functions.callgraph.out_edges(func.addr, data=True)
        # find the ones whose type is transition
        for _, dst, data in callgraph_outedges:
            if data.get("type", None) == "transition":
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
        if all_endpoints["transition"]:
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
        endpoints |= all_endpoints.get("return", set())

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

        callers = self.model.get_predecessors(tailnode, jumpkind="Ijk_Call")
        direct_jumpers = self.model.get_predecessors(tailnode, jumpkind="Ijk_Boring")
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

            func_addr_str = hex(func_addr) if isinstance(func_addr, int) else str(func_addr)

            # get the node on CFG
            if func.startpoint is None:
                l.warning("Function %s does not have a startpoint (yet).", func_addr_str)
                continue

            startpoint = self.model.get_any_node(func.startpoint.addr)
            if startpoint is None:
                # weird...
                l.warning("No CFGNode is found for function %s in _make_return_edges().", func_addr_str)
                continue

            endpoints = self._get_return_sources(func)

            # get all callers
            callers = self.model.get_predecessors(startpoint, jumpkind="Ijk_Call")

            # handle callers for tailcall optimizations if flag is enabled
            if self._detect_tail_calls and startpoint.addr in self._tail_calls:
                l.debug("Handling return address for tail call for func %s", func_addr_str)
                seen = set()
                tail_callers = self._get_tail_caller(startpoint, seen)
                callers.extend(tail_callers)

            # for each caller, since they all end with a call instruction, get the immediate successor
            return_targets = itertools.chain.from_iterable(
                self.model.get_successors(caller, excluding_fakeret=False, jumpkind="Ijk_FakeRet") for caller in callers
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
                                l.error("At %s: expecting more than one instruction. Only got one.", src)
                                ins_addr = None
                        else:
                            ins_addr = src.instruction_addrs[-1]

                    self._graph_add_edge(rt, src, "Ijk_Ret", ins_addr, DEFAULT_STATEMENT)

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

    def _function_add_transition_edge(
        self,
        dst_addr,
        src_node,
        src_func_addr,
        to_outside=False,
        dst_func_addr=None,
        stmt_idx=None,
        ins_addr=None,
        is_exception=False,
    ):
        """
        Add a transition edge to the function transition map.

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
                    self.kb.functions._add_transition_to(
                        src_func_addr,
                        src_snippet,
                        target_snippet,
                        stmt_idx=stmt_idx,
                        ins_addr=ins_addr,
                        is_exception=is_exception,
                    )
                else:
                    self.kb.functions._add_outside_transition_to(
                        src_func_addr,
                        src_snippet,
                        target_snippet,
                        to_function_addr=dst_func_addr,
                        stmt_idx=stmt_idx,
                        ins_addr=ins_addr,
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

                self.kb.functions._add_call_to(
                    function_addr,
                    src_snippet,
                    addr,
                    ret_snippet,
                    syscall=syscall,
                    stmt_idx=stmt_idx,
                    ins_addr=ins_addr,
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

        self.kb.functions._add_return_from_call(
            function_addr, return_from_addr, return_to_snippet, to_outside=to_outside
        )

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

        if "lr_saved_on_stack" in function.info:
            return

        # if it does, we log it down to the Function object.
        lr_offset = self.project.arch.registers["lr"][0]
        sp_offset = self.project.arch.sp_offset
        initial_sp = 0x7FFF0000
        initial_lr = 0xABCDEF
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
                    if data.op == "Iop_Sub32":
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

                            function.info["lr_saved_on_stack"] = True
                            function.info["lr_on_stack_offset"] = storing_addr - initial_sp
                            break

        if "lr_saved_on_stack" not in function.info:
            function.info["lr_saved_on_stack"] = False

    def _arm_track_read_lr_from_stack(self, irsb, function):  # pylint:disable=unused-argument
        """
        At the end of a basic block, simulate the very last instruction to see if the return address is read from the
        stack and written in PC. If so, the jumpkind of this IRSB will be set to Ijk_Ret. For detailed explanations,
        please see the documentation of _arm_track_lr_on_stack().

        :param pyvex.IRSB irsb: The basic block object.
        :param Function function: The function instance.
        :return: None
        """

        if "lr_saved_on_stack" not in function.info or not function.info["lr_saved_on_stack"]:
            return

        sp_offset = self.project.arch.sp_offset
        initial_sp = 0x7FFF0000
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
                    if data.op == "Iop_Add32":
                        arg0, arg1 = data.args
                        if isinstance(arg0, pyvex.IRExpr.RdTmp) and isinstance(arg1, pyvex.IRExpr.Const):
                            if arg0.tmp in tmps:
                                tmps[stmt.tmp] = tmps[arg0.tmp] + arg1.con.value
                elif isinstance(data, pyvex.IRExpr.Load):
                    if isinstance(data.addr, pyvex.IRExpr.RdTmp):
                        if data.addr.tmp in tmps:
                            tmps[stmt.tmp] = ("load", tmps[data.addr.tmp])
            elif isinstance(stmt, pyvex.IRStmt.Put):
                if stmt.offset == sp_offset and isinstance(stmt.data, pyvex.IRExpr.RdTmp):
                    if stmt.data.tmp in tmps:
                        # loading things into sp
                        last_sp = tmps[stmt.data.tmp]

        if last_sp is not None and isinstance(tmp_irsb.next, pyvex.IRExpr.RdTmp):
            val = tmps.get(tmp_irsb.next.tmp, None)
            # val being None means there are statements that we do not handle
            if isinstance(val, tuple) and val[0] == "load":
                # the value comes from memory
                memory_addr = val[1]
                if isinstance(last_sp, int):
                    lr_on_stack_offset = memory_addr - last_sp
                else:
                    lr_on_stack_offset = memory_addr - last_sp[1]

                if lr_on_stack_offset == function.info["lr_on_stack_offset"]:
                    # the jumpkind should be Ret instead of boring
                    irsb.jumpkind = "Ijk_Ret"

    def _lifter_register_readonly_regions(self):
        pyvex.pvc.deregister_all_readonly_regions()

        if self.project.arch.name in {"MIPS64", "MIPS32"} or is_arm_arch(self.project.arch):
            self._ro_region_cdata_cache = []
            for segment in self.project.loader.main_object.segments:
                if segment.is_readable and not segment.is_writable:
                    content = self.project.loader.memory.load(segment.vaddr, segment.memsize)
                    content_buf = pyvex.ffi.from_buffer(content)
                    self._ro_region_cdata_cache.append(content_buf)
                    pyvex.pvc.register_readonly_region(segment.vaddr, segment.memsize, content_buf)

            if self.project.arch.name in {"MIPS64", "MIPS32"}:
                # also map .got
                for section in self.project.loader.main_object.sections:
                    if section.name == ".got":
                        content = self.project.loader.memory.load(section.vaddr, section.memsize)
                        content_buf = pyvex.ffi.from_buffer(content)
                        self._ro_region_cdata_cache.append(content_buf)
                        pyvex.pvc.register_readonly_region(section.vaddr, section.memsize, content_buf)

    def _lifter_deregister_readonly_regions(self):
        pyvex.pvc.deregister_all_readonly_regions()
        self._ro_region_cdata_cache = None

    #
    # Initial registers
    #

    def _get_initial_registers(self, addr, cfg_job, current_function_addr) -> list[tuple[int, int, int]] | None:
        initial_regs = None
        if self.project.arch.name in {"MIPS64", "MIPS32"}:
            initial_regs = [
                (
                    self.project.arch.registers["t9"][0],
                    self.project.arch.registers["t9"][1],
                    current_function_addr,
                )
            ]
            if self.kb.functions.contains_addr(current_function_addr):
                func = self.kb.functions.get_by_addr(current_function_addr)
                if "gp" in func.info:
                    initial_regs.append(
                        (
                            self.project.arch.registers["gp"][0],
                            self.project.arch.registers["gp"][1],
                            func.info["gp"],
                        )
                    )
        elif self.project.arch.name == "X86":
            # for x86 GCC-generated PIE binaries, detect calls to __x86.get_pc_thunk
            if (
                cfg_job.jumpkind == "Ijk_FakeRet"
                and cfg_job.returning_source is not None
                and self.kb.functions.contains_addr(cfg_job.returning_source)
            ):
                return_from_func = self.kb.functions.get_by_addr(cfg_job.returning_source)
                if "get_pc" in return_from_func.info:
                    func = self.kb.functions.get_by_addr(current_function_addr)
                    pc_reg = return_from_func.info["get_pc"]
                    # the crazy thing is that GCC-generated code may adjust the register value accordingly after
                    # returning! we must take into account the added offset (in the followin example, 0x8d36)
                    #
                    # e.g.
                    #  000011A1 call    __x86_get_pc_thunk_bx
                    #  000011A6 add     ebx, 8D36h
                    #
                    # this means, for the current block, the initial value of ebx is whatever __x86_get_pc_thunk_bx
                    # returns. for future blocks in this function, the initial value of ebx must be the returning
                    # value plus 0x8d36.
                    pc_reg_offset, pc_reg_size = self.project.arch.registers[pc_reg]
                    initial_regs = [(pc_reg_offset, pc_reg_size, addr)]
                    # find adjustment
                    adjustment = self._x86_gcc_pie_find_pc_register_adjustment(addr, pc_reg_offset)
                    if adjustment is not None:
                        func.info["pc_reg"] = (pc_reg, addr + adjustment)
                    else:
                        func.info["pc_reg"] = (pc_reg, addr)
            if self.kb.functions.contains_addr(current_function_addr):
                func = self.kb.functions.get_by_addr(current_function_addr)
                if not initial_regs and "pc_reg" in func.info:
                    pc_reg, pc_reg_value = func.info["pc_reg"]
                    initial_regs = [
                        (
                            self.project.arch.registers[pc_reg][0],
                            self.project.arch.registers[pc_reg][1],
                            pc_reg_value,
                        )
                    ]
        elif is_arm_arch(self.project.arch):
            if addr != current_function_addr and self.kb.functions.contains_addr(current_function_addr):
                func = self.kb.functions.get_by_addr(current_function_addr)
                if "constant_r4" in func.info:
                    initial_regs = [
                        (
                            self.project.arch.registers["r4"][0],
                            self.project.arch.registers["r4"][1],
                            func.info["constant_r4"],
                        )
                    ]

        return initial_regs

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

            is_x86_x64_arch = self.project.arch.name in ("X86", "AMD64")

            if is_arm_arch(self.project.arch):
                real_addr = addr & (~1)
            else:
                real_addr = addr

            # extra check for ARM
            if is_arm_arch(self.project.arch) and self._seg_list.occupied_by_sort(addr) == "code":
                existing_node = self.get_any_node(addr, anyaddr=True)
                if existing_node is not None and (addr & 1) != (existing_node.addr & 1):
                    # we are trying to break an existing ARM node with a THUMB node, or vice versa
                    # this is probably because our current node is unexpected
                    return None, None, None, None

            distance = VEX_IRSB_MAX_SIZE
            # if there is exception handling code, check the distance between `addr` and the closest ending address
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
                # If section is None, is there a segment?
                segment = None
                if section is None:
                    has_executable_segment = self._object_has_executable_segments(obj)
                    segment = obj.find_segment_containing(addr)
                if (
                    (has_executable_section and section is None)
                    and (section is None and has_executable_segment and segment is None)
                    and self._skip_unmapped_addrs
                ):
                    # the basic block should not exist here...
                    return None, None, None, None
                if section is not None:
                    if not section.is_executable:
                        # the section is not executable...
                        return None, None, None, None
                    distance_ = section.vaddr + section.memsize - real_addr
                    distance = min(distance_, VEX_IRSB_MAX_SIZE)
                elif segment is not None:
                    if not segment.is_executable:
                        # the segment is not executable...
                        return None, None, None, None
                    distance_segment = segment.vaddr + segment.memsize - real_addr
                    distance = min(distance_segment, VEX_IRSB_MAX_SIZE)

            # also check the distance between `addr` and the closest function.
            # we don't want to have a basic block that spans across function boundaries
            next_func = self.functions.ceiling_func(addr + 1)
            if next_func is not None:
                distance_to_func = (
                    next_func.addr & (~1) if is_arm_arch(self.project.arch) else next_func.addr
                ) - real_addr
                if distance_to_func != 0:
                    if distance is None:
                        distance = distance_to_func
                    else:
                        distance = min(distance, distance_to_func)

            # in the end, check the distance between `addr` and the closest occupied region in segment list
            next_noncode_addr = self._seg_list.next_pos_with_sort_not_in(addr, {"code"}, max_distance=distance)
            if next_noncode_addr is not None:
                distance_to_noncode_addr = next_noncode_addr - real_addr
                distance = min(distance, distance_to_noncode_addr)

            switch_mode_on_nodecode = False
            if is_arm_arch(self.project.arch):
                switch_mode_on_nodecode = self._arch_options.switch_mode_on_nodecode
                if real_addr in self._decoding_assumptions:
                    # we have come across this address before
                    assumption = self._decoding_assumptions[real_addr]
                    if assumption.attempted_thumb and assumption.attempted_arm:
                        # unfortunately, we have attempted both, and it couldn't be decoded as any. time to give up
                        self._seg_list.occupy(real_addr, self.project.arch.instruction_alignment, "nodecode")
                        return None, None, None, None
                    if assumption.attempted_thumb:
                        switch_mode_on_nodecode = False
                        if addr % 2 == 1 and cfg_job.job_type == CFGJobType.COMPLETE_SCANNING:
                            # we have attempted THUMB mode. time to try ARM mode instead.
                            if current_function_addr == addr:
                                current_function_addr &= ~1
                            addr &= ~1
                        elif addr % 2 == 0:
                            # we are about to attempt ARM mode
                            pass
                        else:
                            # we have attempted THUMB mode and failed to decode.
                            if (
                                cfg_job.job_type == CFGJobType.NORMAL
                                and cfg_job.jumpkind in {"Ijk_Boring", "Ijk_FakeRet"}
                                and cfg_job.src_node is not None
                            ):
                                self._cascading_remove_lifted_blocks(cfg_job.src_node.addr & 0xFFFF_FFFE)
                            return None, None, None, None
                    elif assumption.attempted_arm:
                        switch_mode_on_nodecode = False
                        if addr % 2 == 0 and cfg_job.job_type == CFGJobType.COMPLETE_SCANNING:
                            # we have attempted ARM mode. time to try THUMB mode instead.
                            if current_function_addr == addr:
                                current_function_addr |= 1
                            addr |= 1
                        elif addr % 2 == 1:
                            # we are about to attempt THUMB mode
                            pass
                        else:
                            # we have attempted ARM mode and failed to decode.
                            if (
                                cfg_job.job_type == CFGJobType.NORMAL
                                and cfg_job.jumpkind == "Ijk_Boring"
                                and cfg_job.src_node is not None
                            ):
                                self._cascading_remove_lifted_blocks(cfg_job.src_node.addr & 0xFFFF_FFFE)
                            return None, None, None, None

            initial_regs = self._get_initial_registers(addr, cfg_job, current_function_addr)

            # Let's try to create the pyvex IRSB directly, since it's much faster
            nodecode = False
            irsb = None
            irsb_string = None
            lifted_block = None
            try:
                lifted_block = self._lift(
                    addr,
                    size=distance,
                    collect_data_refs=True,
                    strict_block_end=True,
                    load_from_ro_regions=True,
                    initial_regs=initial_regs,
                )
                irsb = lifted_block.vex_nostmt
                irsb_string = lifted_block.bytes[: irsb.size]
            except SimTranslationError:
                nodecode = True

            if cfg_job.job_type == CFGJobType.COMPLETE_SCANNING:
                # special logic during the complete scanning phase

                if is_arm_arch(self.project.arch):
                    # it's way too easy to incorrectly disassemble THUMB code contains 0x4f as ARM code svc?? #????
                    # if we get a single block that getting decoded to svc?? under ARM mode, we treat it as nodecode
                    if addr % 4 == 0 and irsb.jumpkind == "Ijk_Sys_syscall":
                        if (
                            lifted_block.capstone.insns
                            and lifted_block.capstone.insns[-1].mnemonic.startswith("svc")
                            and lifted_block.capstone.insns[-1].operands[0].imm > 255
                        ):
                            nodecode = True

                    if (nodecode or irsb.size == 0 or irsb.jumpkind == "Ijk_NoDecode") and switch_mode_on_nodecode:
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
                            lifted_block = self._lift(
                                addr_0,
                                size=distance,
                                collect_data_refs=True,
                                strict_block_end=True,
                                load_from_ro_regions=True,
                                initial_regs=initial_regs,
                            )
                            irsb = lifted_block.vex_nostmt
                            irsb_string = lifted_block.bytes[: irsb.size]
                        except SimTranslationError:
                            nodecode = True

                        if not (nodecode or irsb.size == 0 or irsb.jumpkind == "Ijk_NoDecode"):
                            # it is decodeable
                            if current_function_addr == addr:
                                current_function_addr = addr_0
                            addr = addr_0

            is_thumb = False
            if is_arm_arch(self.project.arch) and addr % 2 == 1:
                # thumb mode
                is_thumb = True

            if is_arm_arch(self.project.arch):
                # track decoding assumptions of ARM blocks
                if cfg_job.src_node is not None:
                    src_node_realaddr = cfg_job.src_node.addr & 0xFFFF_FFFE
                    if src_node_realaddr in self._decoding_assumptions:
                        assumption = DecodingAssumption(
                            real_addr,
                            max(irsb.size, 1) if irsb is not None else 1,
                            ARMDecodingMode.THUMB if is_thumb else ARMDecodingMode.ARM,
                        )
                        if cfg_job.jumpkind != "Ijk_Call":
                            self._decoding_assumption_relations.add_edge(src_node_realaddr, real_addr)
                        self._decoding_assumptions[real_addr] = assumption
                elif cfg_job.job_type in (CFGJobType.FUNCTION_PROLOGUE, CFGJobType.COMPLETE_SCANNING):
                    # this is the source of assumptions. it might be wrong!
                    if real_addr in self._decoding_assumptions:
                        # take the existing one and update it
                        assumption = self._decoding_assumptions[real_addr]
                        if assumption.attempted_thumb and assumption.attempted_arm:
                            l.error("Unreachable reached. Please report to GitHub.")
                            return None, None, None, None

                        assumption.mode = ARMDecodingMode.THUMB if is_thumb else ARMDecodingMode.ARM
                        if is_thumb:
                            assumption.attempted_thumb = True
                        else:
                            assumption.attempted_arm = True
                    else:
                        assumption = DecodingAssumption(
                            real_addr,
                            max(irsb.size, 1) if irsb is not None else 1,
                            ARMDecodingMode.THUMB if is_thumb else ARMDecodingMode.ARM,
                        )
                        self._decoding_assumptions[real_addr] = assumption

            if nodecode or irsb.size == 0 or irsb.jumpkind == "Ijk_NoDecode":
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

                # the default case
                valid_ins = False
                nodecode_size = 1

                # special handling for ud, ud1, and ud2 on x86 and x86-64
                if irsb_string[-2:] == b"\x0f\x0b" and self.project.arch.name == "AMD64":
                    # VEX supports ud2 and make it part of the block size, only in AMD64.
                    valid_ins = True
                    nodecode_size = 0
                elif (
                    lifted_block is not None
                    and is_x86_x64_arch
                    and len(lifted_block.bytes) - irsb_size > 2
                    and lifted_block.bytes[irsb_size : irsb_size + 2]
                    in {
                        b"\x0f\xff",  # ud0
                        b"\x0f\xb9",  # ud1
                        b"\x0f\x0b",  # ud2
                    }
                ):
                    # ud0, ud1, and ud2 are actually valid instructions.
                    valid_ins = True
                    # VEX does not support ud0 or ud1 or ud2 under AMD64. they are not part of the block size.
                    nodecode_size = 2
                elif is_arm_arch(self.project.arch):
                    # check for UND
                    # Ref: https://developer.arm.com/documentation/dui0489/c/arm-and-thumb-instructions/pseudo-instructions/und-pseudo-instruction
                    # load raw bytes
                    trailing = self.project.loader.memory.load((addr & 0xFFFF_FFFE) + irsb_size, 4)
                    trailing = trailing.ljust(4, b"\x00")
                    if is_thumb:
                        if self.project.arch.instruction_endness == Endness.LE:
                            # swap endianness
                            trailing = (
                                bytes([trailing[1]])
                                + bytes([trailing[0]])
                                + bytes([trailing[3]])
                                + bytes([trailing[2]])
                            )
                        if trailing[0] == 0xDE:
                            # UND xx for THUMB-16
                            valid_ins = True
                            nodecode_size = 2
                        elif (
                            trailing[0] == 0xF7
                            and (trailing[1] & 0xF0) == 0xF0
                            and (trailing[2] & 0xF0) == 0xA0
                            and (trailing[3] & 0xF0) == 0xF0
                        ):
                            # UND xxx for THUMB-32
                            valid_ins = True
                            nodecode_size = 4
                    else:
                        if self.project.arch.instruction_endness == Endness.LE:
                            # swap endianness
                            trailing = trailing[::-1]
                        if (trailing[0] & 0xF) == 7 and (trailing[1] & 0xF0) == 0xF0 and (trailing[3] & 0xF0) == 0xF0:
                            # UND xxxx for ARM
                            valid_ins = True
                            nodecode_size = 4

                if not valid_ins:
                    l.debug(
                        "Decoding error occurred at address %#x of function %#x.",
                        addr + irsb_size,
                        current_function_addr,
                    )

                    if is_arm_arch(self.project.arch):
                        if real_addr in self._decoding_assumptions:
                            # remove and re-lift all previous blocks that have the same assumption
                            self._cascading_remove_lifted_blocks(real_addr)
                        else:
                            # in ARM, we do not allow half-decoded blocks
                            self._seg_list.occupy(real_addr, irsb_size + nodecode_size, "nodecode")
                    else:
                        self._seg_list.occupy(real_addr, irsb_size, "code")
                        self._seg_list.occupy(real_addr + irsb_size, nodecode_size, "nodecode")

                    if irsb_size == 0:
                        return None, None, None, None

                self._seg_list.occupy(real_addr, irsb_size, "code")
                if nodecode_size > 0:
                    self._seg_list.occupy(real_addr + irsb_size, nodecode_size, "nodecode")

            # Occupy the block in segment list
            if irsb.size > 0:
                self._seg_list.occupy(real_addr, irsb.size, "code")

            # Create a CFG node, and add it to the graph
            cfg_node = CFGNode(
                addr,
                irsb.size,
                self.model,
                function_address=current_function_addr,
                block_id=addr,
                irsb=irsb,
                thumb=is_thumb,
                byte_string=irsb_string,
            )
            if self._cfb is not None:
                self._cfb.add_obj(real_addr, lifted_block)

            self._model.add_node(addr, cfg_node)

            return addr, current_function_addr, cfg_node, irsb

        except (SimMemoryError, SimEngineError):
            return None, None, None, None

    def _process_block_arch_specific(
        self, addr: int, cfg_node: CFGNode, irsb: pyvex.IRSB, func_addr: int, caller_gp: int | None = None
    ) -> None:  # pylint: disable=unused-argument
        """
        According to arch types ['ARMEL', 'ARMHF', 'MIPS32', 'X86'] does different
        fixes

        For ARM deals with link register on the stack
        (see _arm_track_lr_on_stack)
        For MIPS32 simulates a new state where the global pointer is 0xffffffff
        from current address after three steps if the first successor does not
        adjust this value updates this function address (in function manager)
        to use a conrete global pointer

        :param addr: irsb address
        :param cfg_node:    The corresponding CFG node object.
        :param irsb: irsb
        :param func_addr: function address
        :param caller_gp:   The gp register value that the caller function has. MIPS-specific.
        """
        if is_arm_arch(self.project.arch):
            if self._arch_options.ret_jumpkind_heuristics:
                if addr == func_addr:
                    self._arm_track_lr_on_stack(addr, irsb, self.functions[func_addr])

                elif (
                    "lr_saved_on_stack" in self.functions[func_addr].info
                    and self.functions[func_addr].info["lr_saved_on_stack"]
                    and irsb.jumpkind == "Ijk_Boring"
                    and irsb.next is not None
                    and isinstance(irsb.next, pyvex.IRExpr.RdTmp)
                ):
                    # do a bunch of checks to avoid unnecessary simulation from happening
                    self._arm_track_read_lr_from_stack(irsb, self.functions[func_addr])

            if self._arch_options.pattern_match_ifuncs:
                # e.g.
                # memcpy_ifunc:
                #   tst.w   r0, #0x1000
                #   movw    r3, #0xe80
                #   movt    r3, #0x10   -> 0x100e80
                #   movw    r0, #0x1380
                #   movt    r0, #0x10   -> 0x101380
                #   it      ne
                #   movne   r0, r3
                #   bx      lr

                if (
                    addr % 2 == 1
                    and len(cfg_node.byte_string) == 26
                    and irsb.instructions == 8
                    and irsb.jumpkind == "Ijk_Ret"
                ):
                    block = self.project.factory.block(addr, opt_level=1, cross_insn_opt=True, collect_data_refs=True)
                    insn_mnemonics = [insn.mnemonic for insn in block.capstone.insns]
                    if insn_mnemonics == ["tst.w", "movw", "movt", "movw", "movt", "it", "movne", "bx"]:
                        # extract data refs with vex-optimization enabled
                        added_addrs = set()
                        for ref in block.vex_nostmt.data_refs:
                            if ref.data_addr not in added_addrs:
                                sec = self.project.loader.find_section_containing(ref.data_addr)
                                if sec is not None and sec.is_executable:
                                    job = CFGJob(
                                        ref.data_addr, ref.data_addr, "Ijk_Call", job_type=CFGJobType.IFUNC_HINTS
                                    )
                                    self._insert_job(job)
                                    added_addrs.add(ref.data_addr)

            # detect if there are instructions that set r4 as a constant value
            if (addr & 1) == 0 and addr == func_addr and irsb.size > 0:
                # re-lift the block to get capstone access
                lifted_block = self._lift(irsb.addr, size=irsb.size, collect_data_refs=False, strict_block_end=True)
                for i in range(len(lifted_block.capstone.insns) - 1):
                    insn0 = lifted_block.capstone.insns[i]
                    insn1 = lifted_block.capstone.insns[i + 1]
                    matched_0 = False
                    matched_1 = False
                    reg_dst = None
                    pc_offset = None
                    if insn0.mnemonic == "ldr" and len(insn0.operands) == 2:
                        op0, op1 = insn0.operands
                        if (
                            op0.type == capstone.arm.ARM_OP_REG
                            and op0.value.reg == capstone.arm.ARM_REG_R4
                            and op1.type == capstone.arm.ARM_OP_MEM
                            and op1.mem.base == capstone.arm.ARM_REG_PC
                            and op1.mem.disp > 0
                            and op1.mem.index == 0
                        ):
                            # ldr r4, [pc, #N]
                            matched_0 = True
                            reg_dst = op0.value.reg
                            pc_offset = op1.value.mem.disp
                    if matched_0 and insn1.mnemonic == "add" and len(insn1.operands) == 3:
                        op0, op1, op2 = insn1.operands
                        if (
                            op0.type == capstone.arm.ARM_OP_REG
                            and op0.value.reg == reg_dst
                            and op1.type == capstone.arm.ARM_OP_REG
                            and op1.value.reg == capstone.arm.ARM_REG_PC
                            and op2.type == capstone.arm.ARM_OP_REG
                            and op2.value.reg == reg_dst
                        ):
                            # add r4, pc, r4
                            matched_1 = True

                    if matched_1:
                        r4 = self.project.loader.fast_memory_load_pointer(insn0.address + 4 * 2 + pc_offset, 4)
                        if r4 is not None:
                            r4 += insn1.address + 4 * 2
                            r4 &= 0xFFFF_FFFF
                            func = self.kb.functions.get_by_addr(func_addr)
                            func.info["constant_r4"] = r4
                            break

        elif self.project.arch.name in {"MIPS32", "MIPS64"}:
            func = self.kb.functions.get_by_addr(func_addr)
            if "gp" not in func.info and addr >= func_addr and addr - func_addr < 15 * 4:
                gp_value = self._mips_determine_function_gp(addr, irsb, func_addr)
                if gp_value is not None and self._gp_value is None:
                    self._gp_value = gp_value
                if gp_value is None:
                    gp_value = caller_gp  # fallback
                if gp_value is None:
                    gp_value = self._gp_value  # fallback to a previously found value
                if gp_value is not None:
                    func.info["gp"] = gp_value

        elif self.project.arch.name == "X86":
            # detect __x86.get_pc_thunk.bx
            # TODO: Handle __x86.get_pc_thunk.cx and __x86.get_pc_thunk.ax (but I haven't seen them yet)
            # this requires us to analyze function calls before analyzing the return sites, which is exactly we have
            # been doing for figuring out if a callee returns or not :)
            if cfg_node.addr == func_addr and cfg_node.byte_string == b"\x8b\x1c\x24\xc3":
                # mov ebx, dword ptr [esp]
                # ret
                func = self.kb.functions.get_by_addr(func_addr)
                func.info["get_pc"] = "ebx"

        elif self.project.arch.name == "AMD64":
            # determine if the function uses rbp as a general purpose register or not
            if addr == func_addr or 0 < addr - func_addr <= 0x20:
                rbp_as_gpr = True
                cap = self._lift(addr, size=cfg_node.size).capstone
                for insn in cap.insns:
                    if (
                        insn.mnemonic == "mov"
                        and len(insn.operands) == 2
                        and insn.operands[0].type == capstone.x86.X86_OP_REG
                        and insn.operands[1].type == capstone.x86.X86_OP_REG
                    ):
                        if (
                            insn.operands[0].reg == capstone.x86.X86_REG_RBP
                            and insn.operands[1].reg == capstone.x86.X86_REG_RSP
                        ):
                            rbp_as_gpr = False
                            break
                    elif (
                        insn.mnemonic == "lea"
                        and len(insn.operands) == 2
                        and insn.operands[0].type == capstone.x86.X86_OP_REG
                        and insn.operands[1].type == capstone.x86.X86_OP_MEM
                    ):
                        if (
                            insn.operands[0].reg == capstone.x86.X86_REG_RBP
                            and insn.operands[1].mem.base == capstone.x86.X86_REG_RSP
                        ):
                            rbp_as_gpr = False
                            break
                func = self.kb.functions.get_by_addr(func_addr)
                func.info["bp_as_gpr"] = rbp_as_gpr

    def _extract_node_cluster_by_dependency(self, addr, include_successors=False) -> set[int]:
        to_remove = {addr}
        queue = [addr]
        while queue:
            assumption_addr = queue.pop(0)
            # find parents of this assumption
            if assumption_addr in self._decoding_assumption_relations:
                for pred_addr in self._decoding_assumption_relations.predecessors(assumption_addr):
                    if pred_addr not in to_remove and pred_addr not in queue:
                        to_remove.add(pred_addr)
                        queue.append(pred_addr)
                # find children of this assumption
                if include_successors:
                    for succ_addr in self._decoding_assumption_relations.successors(assumption_addr):
                        if succ_addr not in to_remove and succ_addr not in queue:
                            to_remove.add(succ_addr)
                            queue.append(succ_addr)
        return to_remove

    def _is_branch_vex_artifact_only(self, irsb, branch_ins_addr: int, exit_stmt) -> bool:
        """
        Check if an exit is merely the result of VEX lifting. We should drop these exits.
        These exits point to the same instruction and do not terminate the block.

        Example block:

        1400061c2  lock or byte ptr [rsp], 0x0
        1400061c7  mov     r9, r8
        1400061ca  shr     r9, 0x5
        1400061ce  jne     0x1400060dc

        VEX block:

        00 | ------ IMark(0x1400061c2, 5, 0) ------
        01 | t3 = GET:I64(rsp)
        02 | t2 = LDle:I8(t3)
        03 | t(4,4294967295) = CASle(t3 :: (t2,None)->(t2,None))
        04 | t13 = CasCmpNE8(t4,t2)
        05 | if (t13) { PUT(rip) = 0x1400061c2; Ijk_Boring }
        06 | ------ IMark(0x1400061c7, 3, 0) ------
        07 | t15 = GET:I64(r8)
        08 | ------ IMark(0x1400061ca, 4, 0) ------
        09 | t9 = Shr64(t15,0x05)
        10 | t16 = Shr64(t15,0x04)
        11 | PUT(cc_op) = 0x0000000000000024
        12 | PUT(cc_dep1) = t9
        13 | PUT(cc_dep2) = t16
        14 | PUT(r9) = t9
        15 | PUT(rip) = 0x00000001400061ce
        16 | ------ IMark(0x1400061ce, 6, 0) ------
        17 | t29 = GET:I64(cc_ndep)
        18 | t30 = amd64g_calculate_condition(0x0000000000000004,0x0000000000000024,t9,t16,t29):Ity_I64
        19 | t25 = 64to1(t30)
        20 | if (t25) { PUT(rip) = 0x1400061d4; Ijk_Boring }
        NEXT: PUT(rip) = 0x00000001400060dc; Ijk_Boring

        Statement 5 should not introduce a new exit in the CFG.
        """

        if (
            not self.project.arch.branch_delay_slot
            and irsb.instruction_addresses
            and branch_ins_addr != irsb.instruction_addresses[-1]
            and isinstance(exit_stmt.dst, pyvex.const.IRConst)
            and exit_stmt.dst.value == branch_ins_addr
            and exit_stmt.jumpkind == "Ijk_Boring"
        ):
            return True
        return False

    def _remove_jobs_by_source_node_addr(self, addr: int):
        self._remove_job(lambda j: j.src_node is not None and j.src_node.addr == addr)

    def _cascading_remove_lifted_blocks(self, addr: int):
        # first let's consider both predecessors and successors
        to_remove = self._extract_node_cluster_by_dependency(addr, include_successors=True)

        BLOCK_REMOVAL_LIMIT = 20
        if len(to_remove) > BLOCK_REMOVAL_LIMIT:
            # we are removing too many blocks, which means we are probably removing legitimate blocks
            # let's try only considering predecessors
            to_remove = self._extract_node_cluster_by_dependency(addr, include_successors=False)

            if len(to_remove) > BLOCK_REMOVAL_LIMIT:
                # still too many... give up
                return

        for assumption_addr in to_remove:
            # remove this assumption from the graph (since we may have new relationships formed later)
            if assumption_addr in self._decoding_assumption_relations:
                self._decoding_assumption_relations.remove_node(assumption_addr)

            assumption = self._decoding_assumptions.get(assumption_addr)
            if assumption is None:
                continue

            self._seg_list.release(assumption.addr, assumption.size)
            if assumption.data_segs:
                for data_seg_addr, data_seg_size in assumption.data_segs:
                    self._seg_list.release(data_seg_addr, data_seg_size)
            self._update_unscanned_addr(assumption.addr)
            try:
                existing_node_arm = self._nodes[assumption_addr]
                self._model.remove_node(assumption_addr, existing_node_arm)
            except KeyError:
                existing_node_arm = None
            existing_node_thumb = None
            if existing_node_arm is None:
                try:
                    existing_node_thumb = self._nodes[assumption_addr + 1]
                    self._model.remove_node(assumption_addr + 1, existing_node_thumb)
                except KeyError:
                    existing_node_thumb = None

            for existing_node in [existing_node_arm, existing_node_thumb]:
                if existing_node is None:
                    continue
                # remove the node from the graph
                if existing_node in self.graph:
                    self.graph.remove_node(existing_node)
                # remove the function (if exists)
                if self.functions.contains_addr(existing_node.addr):
                    del self.functions[existing_node.addr]

                # update indirect_jumps_to_resolve
                self._indirect_jumps_to_resolve = {
                    ij for ij in self._indirect_jumps_to_resolve if ij.addr != existing_node.addr
                }

                self._remove_jobs_by_source_node_addr(existing_node.addr)

            if assumption_addr not in self._nodes and assumption_addr + 1 not in self._nodes:
                # remove the address (the real address) from the traced addresses set. only remove this address if both
                # the ARM node and the THUMB node no longer exist.
                self._traced_addresses.discard(assumption.addr)

    def _mips_determine_function_gp(self, addr: int, irsb: pyvex.IRSB, func_addr: int) -> int | None:
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
            elif isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == self.project.arch.registers["gp"][0]:
                last_gp_setting_insn_id = insn_ctr

        if last_gp_setting_insn_id is None:
            return None

        # Prudently search for $gp values
        state = self.project.factory.blank_state(
            addr=addr,
            mode="fastpath",
            remove_options=o.refs,
            add_options={
                o.NO_CROSS_INSN_OPT,
                o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                o.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            },
        )
        state.regs._t9 = func_addr
        state.regs._gp = 0xFFFFFFFF
        try:
            succ = self.project.factory.successors(state, num_inst=last_gp_setting_insn_id + 1)
        except SimIRSBNoDecodeError:
            # if last_gp_setting_insn_id is the last instruction, a SimIRSBNoDecodeError will be raised since
            # there is no instruction left in the current block
            return None

        if not succ.flat_successors:
            return None

        state = succ.flat_successors[0]
        gp = state.regs._gp
        if not gp.symbolic and state.solver.is_false(gp == 0xFFFFFFFF):
            return gp.concrete_value
        return None

    def _find_thunks(self):
        if self.project.arch.name not in self.SPECIAL_THUNKS:
            return {}
        result = {}
        for code, meaning in self.SPECIAL_THUNKS[self.project.arch.name].items():
            for addr in self.project.loader.memory.find(code):
                if self._addr_in_exec_memory_regions(addr):
                    result[addr] = meaning

        return result

    def _x86_gcc_pie_find_pc_register_adjustment(self, addr: int, reg_offset: int) -> int | None:
        """
        Match against a single instruction that adds or subtracts a constant from a specified register.

        :param addr:        Address of the instruction.
        :param reg_offset:  Offset of the PC-storing register.
        :return:            The adjustment, or None if matching fails.
        """

        try:
            lifted_block = self._lift(addr, num_inst=1)
        except SimTranslationError:
            return None
        # Expected:
        #
        # IRSB {
        #    t0:Ity_I32 t1:Ity_I32 t2:Ity_I32 t3:Ity_I32
        #
        #    00 | ------ IMark(0x405b1d, 6, 0) ------
        #    01 | t2 = GET:I32(ebx)
        #    02 | t0 = Add32(t2,0x000043bf)
        #    03 | PUT(cc_op) = 0x00000003
        #    04 | PUT(cc_dep1) = t2
        #    05 | PUT(cc_dep2) = 0x000043bf
        #    06 | PUT(cc_ndep) = 0x00000000
        #    07 | PUT(ebx) = t0
        #    NEXT: PUT(eip) = 0x00405b23; Ijk_Boring
        # }
        if len(lifted_block.vex.statements) > 4:
            stmt1 = lifted_block.vex.statements[1]
            stmt2 = lifted_block.vex.statements[2]
            stmt_last = lifted_block.vex.statements[-1]
            if (
                isinstance(stmt1, pyvex.IRStmt.WrTmp)
                and isinstance(stmt1.data, pyvex.IRExpr.Get)
                and stmt1.data.offset == reg_offset
                and stmt1.data.result_size(lifted_block.vex.tyenv) == 32
            ):
                tmp_0 = stmt1.tmp
                if (
                    isinstance(stmt2, pyvex.IRStmt.WrTmp)
                    and isinstance(stmt2.data, pyvex.IRExpr.Binop)
                    and stmt2.data.op == "Iop_Add32"
                    and isinstance(stmt2.data.args[0], pyvex.IRExpr.RdTmp)
                    and stmt2.data.args[0].tmp == tmp_0
                    and isinstance(stmt2.data.args[1], pyvex.IRExpr.Const)
                ):
                    tmp_1 = stmt2.tmp
                    if (
                        isinstance(stmt_last, pyvex.IRStmt.Put)
                        and stmt_last.offset == reg_offset
                        and isinstance(stmt_last.data, pyvex.IRExpr.RdTmp)
                        and stmt_last.data.tmp == tmp_1
                    ):
                        # found it!
                        return stmt2.data.args[1].con.value
        return None

    def _is_call_returning(self, callsite_cfgnode: CFGNode, callee_func_addr: int) -> bool | None:
        """
        Determine if a function call is returning or not, with a special care for DYNAMIC_RET functions.

        :param callsite_cfgnode:    The CFG node at the call site.
        :param callee_func_addr:    Address of the function to be called.
        :return:                    True if the call must return, False if the call never returns, or None if it cannot
                                    be determined at this moment.
        """

        if self.kb.functions.contains_addr(callee_func_addr):
            callee_func = self.kb.functions.get_by_addr(callee_func_addr)
        else:
            callee_func = None
        if callee_func is not None:
            if callee_func.returning is False:
                return False

            if callee_func.is_plt:
                # get the SimProcedure (if there is one)
                edges = list(callee_func.transition_graph.edges())
                if len(edges) == 1:
                    target_func = edges[0][1]
                    if isinstance(target_func, (HookNode, Function)):
                        if self.project.is_hooked(target_func.addr):
                            hooker = self.project.hooked_by(target_func.addr)
                            if hooker.DYNAMIC_RET:
                                return self._is_call_returning(callsite_cfgnode, target_func.addr)

        if self.project.is_hooked(callee_func_addr):
            hooker = self.project.hooked_by(callee_func_addr)
            if hooker is not None:
                if hooker.DYNAMIC_RET:
                    parent_nodes = list(self.graph.predecessors(callsite_cfgnode))
                    parent_node = parent_nodes[0] if parent_nodes else None
                    blocks_ahead = []
                    if parent_node is not None:
                        blocks_ahead.append(self._lift(parent_node.addr).vex)
                    blocks_ahead.append(self._lift(callsite_cfgnode.addr).vex)
                    hooker.project = self.project
                    hooker.arch = self.project.arch
                    return hooker.dynamic_returns(blocks_ahead)

        if callee_func is not None:
            return callee_func.returning
        return None

    def _lift(self, addr, *args, opt_level=1, cross_insn_opt=False, **kwargs):  # pylint:disable=arguments-differ
        kwargs["extra_stop_points"] = set(self._known_thunks)
        b = super()._lift(addr, *args, opt_level=opt_level, cross_insn_opt=cross_insn_opt, **kwargs)
        return b

    #
    # Public methods
    #

    def copy(self):
        n = CFGFast.__new__(CFGFast)

        for attr, value in self.__dict__.items():
            if attr.startswith("__") and attr.endswith("__"):
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


AnalysesHub.register_default("CFGFast", CFGFast)
