# pylint:disable=line-too-long,multiple-statements
from __future__ import annotations
from typing import TYPE_CHECKING, Any
import logging
from collections import defaultdict

import networkx
from sortedcontainers import SortedDict

import pyvex
from cle import ELF, PE, Blob, TLSObject, MachO, ExternObject, KernelObject, FunctionHintSource, Hex, Coff, SRec, XBE
from cle.backends import NamedRegion
import archinfo
from archinfo.arch_soot import SootAddressDescriptor
from archinfo.arch_arm import is_arm_arch, get_real_address_if_arm

from angr.knowledge_plugins.functions.function_manager import FunctionManager
from angr.knowledge_plugins.functions.function import Function
from angr.knowledge_plugins.cfg import IndirectJump, CFGNode, CFGENode, CFGModel  # pylint:disable=unused-import
from angr.misc.ux import deprecated
from angr.procedures.stubs.UnresolvableJumpTarget import UnresolvableJumpTarget
from angr.utils.constants import DEFAULT_STATEMENT
from angr.procedures.procedure_dict import SIM_PROCEDURES
from angr.errors import (
    AngrCFGError,
    SimTranslationError,
    SimMemoryError,
    SimIRSBError,
    SimEngineError,
    AngrUnsupportedSyscallError,
    SimError,
)
from angr.codenode import HookNode, BlockNode
from angr.engines.vex.lifter import VEX_IRSB_MAX_SIZE, VEX_IRSB_MAX_INST
from angr.analyses import Analysis
from angr.analyses.stack_pointer_tracker import StackPointerTracker
from angr.utils.orderedset import OrderedSet
from .indirect_jump_resolvers.default_resolvers import default_indirect_jump_resolvers

if TYPE_CHECKING:
    from angr.sim_state import SimState


l = logging.getLogger(name=__name__)


class CFGBase(Analysis):
    """
    The base class for control flow graphs.
    """

    tag: str | None = None
    _cle_pseudo_objects = (ExternObject, KernelObject, TLSObject)

    def __init__(
        self,
        sort,
        context_sensitivity_level,
        normalize=False,
        binary=None,
        objects=None,
        regions=None,
        exclude_sparse_regions=True,
        skip_specific_regions=True,
        force_segment=False,
        base_state=None,
        resolve_indirect_jumps=True,
        indirect_jump_resolvers=None,
        indirect_jump_target_limit=100000,
        detect_tail_calls=False,
        low_priority=False,
        skip_unmapped_addrs=True,
        sp_tracking_track_memory=True,
        model=None,
    ):
        """
        :param str sort:                            'fast' or 'emulated'.
        :param int context_sensitivity_level:       The level of context-sensitivity of this CFG (see documentation for
                                                    further details). It ranges from 0 to infinity.
        :param bool normalize:                      Whether the CFG as well as all Function graphs should be normalized.
        :param cle.backends.Backend binary:         The binary to recover CFG on. By default, the main binary is used.
        :param objects:                             A list of objects to recover the CFG on. By default, it will recover
                                                    the CFG of all loaded objects.
        :param iterable regions:                    A list of tuples in the form of (start address, end address)
                                                    describing memory regions that the CFG should cover.
        :param bool force_segment:                  Force CFGFast to rely on binary segments instead of sections.
        :param angr.SimState base_state:            A state to use as a backer for all memory loads.
        :param bool resolve_indirect_jumps:         Whether to try to resolve indirect jumps.
                                                    This is necessary to resolve jump targets from jump tables, etc.
        :param list indirect_jump_resolvers:        A custom list of indirect jump resolvers.
                                                    If this list is None or empty, default indirect jump resolvers
                                                    specific to this architecture and binary types will be loaded.
        :param int indirect_jump_target_limit:      Maximum indirect jump targets to be recovered.
        :param skip_unmapped_addrs:                 Ignore all branches into unmapped regions. True by default. You may
                                                    want to set it to False if you are analyzing manually patched
                                                    binaries or malware samples.
        :param bool detect_tail_calls:              Aggressive tail-call optimization detection. This option is only
                                                    respected in make_functions().
        :param bool sp_tracking_track_memory:       Whether or not to track memory writes if tracking the stack pointer.
                                                    This increases the accuracy of stack pointer tracking,
                                                    especially for architectures without a base pointer.
                                                    Only used if detect_tail_calls is enabled.
        :param None or CFGModel model:              The CFGModel instance to write to. A new CFGModel instance will be
                                                    created and registered with the knowledge base if `model` is None.

        :return: None
        """

        self.sort = sort
        self._context_sensitivity_level = context_sensitivity_level

        # Sanity checks
        if context_sensitivity_level < 0:
            raise ValueError("Unsupported context sensitivity level %d" % context_sensitivity_level)

        self._binary = binary if binary is not None else self.project.loader.main_object
        self._force_segment = force_segment
        self._base_state = base_state
        self._detect_tail_calls = detect_tail_calls
        self._low_priority = low_priority
        self._skip_unmapped_addrs = skip_unmapped_addrs

        # Initialization
        self._edge_map = None
        self._loop_back_edges = None
        self._overlapped_loop_headers = None
        self._thumb_addrs = set()
        self._tail_calls = set()

        # Store all the functions analyzed before the set is cleared
        # Used for performance optimization
        self._updated_nonreturning_functions: set[int] | None = None

        self._normalize = normalize

        # Flag, whether to track memory writes in stack pointer tracking
        self._sp_tracking_track_memory = sp_tracking_track_memory

        # IndirectJump object that describe all indirect exits found in the binary
        # stores as a map between addresses and IndirectJump objects
        self.indirect_jumps: dict[int, IndirectJump] = {}
        self._indirect_jumps_to_resolve = set()

        # Indirect jump resolvers
        self._indirect_jump_target_limit = indirect_jump_target_limit
        self._resolve_indirect_jumps = resolve_indirect_jumps
        self.timeless_indirect_jump_resolvers = []
        self.indirect_jump_resolvers = []
        if not indirect_jump_resolvers:
            indirect_jump_resolvers = default_indirect_jump_resolvers(self._binary, self.project)
        if self._resolve_indirect_jumps and indirect_jump_resolvers:
            # split them into different groups for the sake of speed
            for ijr in indirect_jump_resolvers:
                if ijr.timeless:
                    self.timeless_indirect_jump_resolvers.append(ijr)
                else:
                    self.indirect_jump_resolvers.append(ijr)

        l.info(
            "Loaded %d indirect jump resolvers (%d timeless, %d generic).",
            len(self.timeless_indirect_jump_resolvers) + len(self.indirect_jump_resolvers),
            len(self.timeless_indirect_jump_resolvers),
            len(self.indirect_jump_resolvers),
        )

        # Get all executable memory regions
        self._exec_mem_regions = self._executable_memory_regions(None, self._force_segment)
        self._exec_mem_region_size = sum((end - start) for start, end in self._exec_mem_regions)

        # initialize UnresolvableJumpTarget and UnresolvableCallTarget SimProcedure
        # but we do not want to hook the same symbol multiple times
        ut_jump_addr = self.project.loader.extern_object.get_pseudo_addr("UnresolvableJumpTarget")
        if not self.project.is_hooked(ut_jump_addr):
            self.project.hook(ut_jump_addr, SIM_PROCEDURES["stubs"]["UnresolvableJumpTarget"]())
        self._unresolvable_jump_target_addr = ut_jump_addr
        ut_call_addr = self.project.loader.extern_object.get_pseudo_addr("UnresolvableCallTarget")
        if not self.project.is_hooked(ut_call_addr):
            self.project.hook(ut_call_addr, SIM_PROCEDURES["stubs"]["UnresolvableCallTarget"]())
        self._unresolvable_call_target_addr = ut_call_addr

        # partially and fully analyzed functions
        # this is implemented as a state machine: jobs (CFGJob instances) of each function are put into
        # _jobs_to_analyze_per_function, which essentially makes the keys of this dict being all partially analyzed
        # functions so far. And then when a function does not have any more job to analyze in the future, it will be
        # put in to _completed_functions.

        # a dict of mapping between function addresses and sets of jobs (include both future jobs and pending jobs)
        # a set is used to speed up the job removal procedure
        self._jobs_to_analyze_per_function = defaultdict(set)
        # addresses of functions that have been completely recovered (i.e. all of its blocks are identified) so far
        self._completed_functions = set()

        # TODO: A segment tree to speed up CFG node lookups
        self._node_lookup_index = None
        self._node_lookup_index_warned = False

        self._function_addresses_from_symbols = self._load_func_addrs_from_symbols()
        self._function_addresses_from_eh_frame = self._load_func_addrs_from_eh_frame()

        # Cache if an object has executable sections or not
        self._object_to_executable_sections = {}
        # Cache if an object has executable segments or not
        self._object_to_executable_segments = {}

        if model is not None:
            self._model = model
        else:
            self._model: CFGModel = self.kb.cfgs.new_model(self.tag)

        # necessary warnings
        regions_not_specified = regions is None and binary is None and not objects
        if regions_not_specified and self.project.loader._auto_load_libs and len(self.project.loader.all_objects) > 3:
            l.warning(
                '"auto_load_libs" is enabled. With libraries loaded in project, CFG will cover libraries, '
                "which may take significantly more time than expected. You may reload the binary with "
                '"auto_load_libs" disabled, or specify "regions" to limit the scope of CFG recovery.'
            )

        if regions is None:
            if self._skip_unmapped_addrs:
                regions = self._executable_memory_regions(objects=objects, force_segment=force_segment)
            else:
                if not objects:
                    objects = self.project.loader.all_objects
                regions = [(obj.min_addr, obj.max_addr) for obj in objects]

        for start, end in regions:
            if end < start:
                raise AngrCFGError("Invalid region bounds (end precedes start)")

        # Block factory returns patched state by default, so ensure we are also analyzing the patched state
        if self._base_state is None and self.project.kb.patches.values():
            self._base_state = self.project.kb.patches.patched_entry_state

        if exclude_sparse_regions:
            regions = [r for r in regions if not self._is_region_extremely_sparse(*r, base_state=self._base_state)]

        if skip_specific_regions:
            if base_state is not None:
                l.warning("You specified both base_state and skip_specific_regions. They may conflict with each other.")
            regions = [r for r in regions if not self._should_skip_region(r[0])]

        if not regions and self.project.arch.name != "Soot":
            raise AngrCFGError(
                "Regions are empty, or all regions are skipped. You may want to manually specify regions."
            )

        self._regions_size = sum((end - start) for start, end in regions)
        self._regions: dict[int, int] = SortedDict(regions)

        l.debug("CFG recovery covers %d regions:", len(self._regions))
        for start, end in self._regions.items():
            l.debug("... %#x - %#x", start, end)

    def __contains__(self, cfg_node):
        return cfg_node in self.graph

    #
    # Properties
    #

    @property
    def _nodes(self):
        return self._model._nodes

    @property
    def _nodes_by_addr(self):
        return self._model._nodes_by_addr

    @property
    def model(self) -> CFGModel:
        """
        Get the CFGModel instance.
        :return:    The CFGModel instance that this analysis currently uses.
        """
        return self._model

    @property
    def normalized(self):
        return self._model.normalized

    @normalized.setter
    def normalized(self, v):
        self._model.normalized = v

    @property
    def context_sensitivity_level(self):
        return self._context_sensitivity_level

    @property
    def functions(self):
        """
        A reference to the FunctionManager in the current knowledge base.

        :return: FunctionManager with all functions
        :rtype: angr.knowledge_plugins.FunctionManager
        """
        return self.kb.functions

    #
    # Methods
    #

    def _initialize_cfg(self):
        """
        Re-create the DiGraph
        """

        self._jobs_to_analyze_per_function = defaultdict(set)
        self._completed_functions = set()

    def _function_completed(self, func_addr: int):
        pass

    def _post_analysis(self):
        if self._normalize:
            if not self.normalized:
                self.normalize()

            # Call normalize() on each function
            for f in self.kb.functions.values():
                if not self.project.is_hooked(f.addr):
                    f.normalize()

        # drop all propagation results that start with "cfg_intermediate"
        self.kb.propagations.discard_by_prefix("cfg_intermediate")

    def make_copy(self, copy_to):
        """
        Copy self attributes to the new object.

        :param CFGBase copy_to: The target to copy to.
        :return: None
        """

        for attr, value in self.__dict__.items():
            if attr.startswith("__") and attr.endswith("__"):
                continue
            setattr(copy_to, attr, value)

    # pylint: disable=no-self-use
    def copy(self):
        raise NotImplementedError

    def output(self):
        raise NotImplementedError

    def generate_index(self):
        """
        Generate an index of all nodes in the graph in order to speed up get_any_node() with anyaddr=True.

        :return: None
        """

        raise NotImplementedError("I'm too lazy to implement it right now")

    @deprecated(replacement="self.model.get_predecessors()")
    def get_predecessors(self, cfgnode, excluding_fakeret=True, jumpkind=None):
        return self._model.get_predecessors(cfgnode, excluding_fakeret=excluding_fakeret, jumpkind=jumpkind)

    @deprecated(replacement="self.model.get_successors()")
    def get_successors(self, node, excluding_fakeret=True, jumpkind=None):
        return self._model.get_successors(node, excluding_fakeret=excluding_fakeret, jumpkind=jumpkind)

    @deprecated(replacement="self.model.get_successors_and_jumpkind")
    def get_successors_and_jumpkind(self, node, excluding_fakeret=True):
        return self._model.get_successors_and_jumpkind(node, excluding_fakeret=excluding_fakeret)

    @deprecated(replacement="self.model.get_all_predecessors()")
    def get_all_predecessors(self, cfgnode, depth_limit=None):
        return self._model.get_all_predecessors(cfgnode, depth_limit)

    @deprecated(replacement="self.model.get_all_successors()")
    def get_all_successors(self, cfgnode, depth_limit=None):
        return self._model.get_all_successors(cfgnode, depth_limit)

    @deprecated(replacement="self.model.get_node()")
    def get_node(self, block_id):
        return self._model.get_node(block_id)

    @deprecated(replacement="self.model.get_any_node()")
    def get_any_node(self, addr, is_syscall=None, anyaddr=False, force_fastpath=False):
        return self._model.get_any_node(addr, is_syscall=is_syscall, anyaddr=anyaddr, force_fastpath=force_fastpath)

    @deprecated(replacement="self.model.get_all_nodes()")
    def get_all_nodes(self, addr, is_syscall=None, anyaddr=False):
        return self._model.get_all_nodes(addr, is_syscall=is_syscall, anyaddr=anyaddr)

    @deprecated(replacement="self.model.nodes()")
    def nodes(self):
        return self._model.nodes()

    @deprecated(replacement="nodes")
    def nodes_iter(self):
        """
        (Decrepated) An iterator of all nodes in the graph. Will be removed in the future.

        :return: The iterator.
        :rtype: iterator
        """

        return self.nodes()

    def get_loop_back_edges(self):
        return self._loop_back_edges

    @deprecated(replacement="self.model.get_branching_nodes()")
    def get_branching_nodes(self):
        return self._model.get_branching_nodes()

    @deprecated(replacement="self.model.get_exit_stmt_idx")
    def get_exit_stmt_idx(self, src_block, dst_block):
        return self._model.get_exit_stmt_idx(src_block, dst_block)

    @property
    def graph(self) -> networkx.DiGraph[CFGNode]:
        raise NotImplementedError

    def remove_edge(self, block_from, block_to):
        if self.graph is None:
            raise TypeError("self.graph does not exist.")

        if block_from not in self.graph:
            raise ValueError(f"{block_from!r} is not in CFG.")

        if block_to not in self.graph:
            raise ValueError(f"{block_to!r} is not in CFG.")

        if block_to not in self.graph[block_from]:
            raise ValueError(f"Edge {block_from!r}->{block_to!r} does not exist.")

        self.graph.remove_edge(block_from, block_to)

    def _merge_cfgnodes(self, cfgnode_0, cfgnode_1):
        """
        Merge two adjacent CFGNodes into one.

        :param CFGNode cfgnode_0:   The first CFGNode.
        :param CFGNode cfgnode_1:   The second CFGNode.
        :return:                    None
        """

        assert cfgnode_0.addr + cfgnode_0.size == cfgnode_1.addr
        new_node = cfgnode_0.merge(cfgnode_1)

        # Update the graph and the nodes dict accordingly
        self._model.remove_node(cfgnode_1.block_id, cfgnode_1)
        self._model.remove_node(cfgnode_0.block_id, cfgnode_0)

        in_edges = list(self.graph.in_edges(cfgnode_0, data=True))
        out_edges = list(self.graph.out_edges(cfgnode_1, data=True))

        self.graph.remove_node(cfgnode_0)
        self.graph.remove_node(cfgnode_1)

        self.graph.add_node(new_node)
        for src, _, data in in_edges:
            self.graph.add_edge(src, new_node, **data)
        for _, dst, data in out_edges:
            self.graph.add_edge(new_node, dst, **data)

        # Put the new node into node dicts
        self._model.add_node(new_node.block_id, new_node)

    def _to_snippet(self, cfg_node=None, addr=None, size=None, thumb=False, jumpkind=None, base_state=None):
        """
        Convert a CFGNode instance to a CodeNode object.

        :param angr.analyses.CFGNode cfg_node: The CFGNode instance.
        :param int addr: Address of the node. Only used when `cfg_node` is None.
        :param bool thumb: Whether this is in THUMB mode or not. Only used for ARM code and when `cfg_node` is None.
        :param str or None jumpkind: Jumpkind of this node.
        :param SimState or None base_state: The state where BlockNode should be created from.
        :return: A converted CodeNode instance.
        :rtype: CodeNode
        """

        if cfg_node is not None:
            addr = cfg_node.addr
            size = cfg_node.size
            thumb = cfg_node.thumb

        if addr is None:
            raise ValueError("_to_snippet(): Either cfg_node or addr must be provided.")

        if self.project.is_hooked(addr) and jumpkind != "Ijk_NoHook":
            hooker = self.project._sim_procedures[addr]
            size = hooker.kwargs.get("length", 0)
            return HookNode(addr, size, type(hooker))

        if cfg_node is not None:
            return BlockNode(addr, size, thumb=thumb, bytestr=cfg_node.byte_string)  # pylint: disable=no-member
        return self.project.factory.snippet(addr, size=size, jumpkind=jumpkind, thumb=thumb, backup_state=base_state)

    def is_thumb_addr(self, addr):
        return addr in self._thumb_addrs

    def _arm_thumb_filter_jump_successors(self, irsb, successors, get_ins_addr, get_exit_stmt_idx, get_jumpkind):
        """
        Filter successors for THUMB mode basic blocks, and remove those successors that won't be taken normally.

        :param irsb:            The IRSB object.
        :param list successors: A list of successors.
        :param func get_ins_addr: A callable that returns the source instruction address for a successor.
        :param func get_exit_stmt_idx: A callable that returns the source statement ID for a successor.
        :param func get_jumpkind:      A callable that returns the jumpkind of a successor.
        :return: A new list of successors after filtering.
        :rtype: list
        """

        if not successors:
            return []

        if len(successors) == 1 and get_exit_stmt_idx(successors[0]) == DEFAULT_STATEMENT:
            # only have a default exit. no need to filter
            return successors

        if irsb.instruction_addresses and all(
            get_ins_addr(suc) == irsb.instruction_addresses[-1] for suc in successors
        ):
            # check if all exits are produced by the last instruction
            # only takes the following jump kinds: Boring, FakeRet, Call, Syscall, Ret
            allowed_jumpkinds = {"Ijk_Boring", "Ijk_FakeRet", "Ijk_Call", "Ijk_Ret"}
            successors = [
                suc
                for suc in successors
                if get_jumpkind(suc) in allowed_jumpkinds or get_jumpkind(suc).startswith("Ijk_Sys")
            ]
            if len(successors) == 1:
                return successors

        can_produce_exits = set()  # addresses of instructions that can produce exits
        bb = self._lift(irsb.addr, size=irsb.size, thumb=True)

        # step A: filter exits using capstone (since it's faster than re-lifting the entire block to VEX)
        THUMB_BRANCH_INSTRUCTIONS = {
            "beq",
            "bne",
            "bcs",
            "bhs",
            "bcc",
            "blo",
            "bmi",
            "bpl",
            "bvs",
            "bvc",
            "bhi",
            "bls",
            "bge",
            "blt",
            "bgt",
            "ble",
            "cbz",
            "cbnz",
        }
        for cs_insn in bb.capstone.insns:
            if cs_insn.mnemonic.split(".")[0] in THUMB_BRANCH_INSTRUCTIONS:
                can_produce_exits.add(cs_insn.address)

        if all(
            get_ins_addr(suc) in can_produce_exits or get_exit_stmt_idx(suc) == DEFAULT_STATEMENT for suc in successors
        ):
            # nothing will be filtered.
            return successors

        # step B: consider VEX statements
        it_counter = 0
        conc_temps = {}

        for stmt in bb.vex.statements:
            if stmt.tag == "Ist_IMark":
                if it_counter > 0:
                    it_counter -= 1
                    can_produce_exits.add(stmt.addr + stmt.delta)
            elif stmt.tag == "Ist_WrTmp":
                val = stmt.data
                if val.tag == "Iex_Const":
                    conc_temps[stmt.tmp] = val.con.value
            elif stmt.tag == "Ist_Put" and stmt.offset == self.project.arch.registers["itstate"][0]:
                val = stmt.data
                if val.tag == "Iex_RdTmp":
                    if val.tmp in conc_temps:
                        # We found an IT instruction!!
                        # Determine how many instructions are conditional
                        it_counter = 0
                        itstate = conc_temps[val.tmp]
                        while itstate != 0:
                            it_counter += 1
                            itstate >>= 8
                elif val.tag == "Iex_Const":
                    it_counter = 0
                    itstate = val.con.value
                    while itstate != 0:
                        it_counter += 1
                        itstate >>= 8

        if it_counter != 0:
            l.debug("Basic block ends before calculated IT block (%#x)", irsb.addr)

        return [
            suc
            for suc in successors
            if get_ins_addr(suc) in can_produce_exits or get_exit_stmt_idx(suc) == DEFAULT_STATEMENT
        ]

    # Methods for determining scanning scope

    def _inside_regions(self, address: int | None) -> bool:
        """
        Check if the address is inside any existing region.

        :param int address: Address to check.
        :return:            True if the address is within one of the memory regions, False otherwise.
        """

        try:
            start_addr = next(self._regions.irange(maximum=address, reverse=True))
        except StopIteration:
            return False
        else:
            return address < self._regions[start_addr]

    def _get_min_addr(self) -> int | None:
        """
        Get the minimum address out of all regions. We assume self._regions is sorted.

        :return: The minimum address, or None if there is no such address.
        """

        if not self._regions:
            if self.project.arch.name != "Soot":
                l.error("self._regions is empty or not properly set.")
            return None

        return next(self._regions.irange())

    def _next_address_in_regions(self, address: int | None) -> int | None:
        """
        Return the next immediate address that is inside any of the regions.

        :param address: The address to start scanning.
        :return:        The next address that is inside one of the memory regions, or None if there is no such address.
        """

        if self._inside_regions(address):
            return address

        try:
            return next(self._regions.irange(minimum=address, reverse=False))
        except StopIteration:
            return None

    def _is_region_extremely_sparse(self, start: int, end: int, base_state: SimState | None = None) -> bool:
        """
        Check whether the given memory region is extremely sparse, i.e., all bytes are the same value.

        :param start:      The beginning of the region.
        :param end:        The end of the region (exclusive).
        :param base_state: The base state (optional).
        :return:           True if the region is extremely sparse, False otherwise.
        """

        all_bytes = None

        if base_state is not None:
            all_bytes = base_state.memory.load(start, end - start)
            try:
                all_bytes = base_state.solver.eval(all_bytes, cast_to=bytes)
            except SimError:
                all_bytes = None

        size = end - start

        if all_bytes is None:
            # load from the binary
            all_bytes = self._fast_memory_load_bytes(start, size)

        if all_bytes is None:
            # failed to load bytes in this region. it might be because the region is not fully mapped (i.e., there are
            # holes). we assume this region is good for analysis.
            return False

        if len(all_bytes) < size:
            l.warning(
                "_is_region_extremely_sparse: The given region %#x-%#x is not a continuous memory region in the "
                "memory space. Only the first %d bytes (%#x-%#x) are processed.",
                start,
                end,
                len(all_bytes),
                start,
                start + len(all_bytes),
            )

        the_byte_value = None
        for b in all_bytes:
            if the_byte_value is None:
                the_byte_value = b
            else:
                if the_byte_value != b:
                    return False

        return True

    def _should_skip_region(self, region_start):
        """
        Some regions usually do not contain any executable code, but are still marked as executable. We should skip
        those regions by default.

        :param int region_start: Address of the beginning of the region.
        :return:                 True/False
        :rtype:                  bool
        """

        obj = self.project.loader.find_object_containing(region_start, membership_check=False)
        if obj is None:
            return False
        if isinstance(obj, PE):
            section = obj.find_section_containing(region_start)
            if section is None:
                return False
            if section.name in {".textbss"}:
                return True

        return False

    def _executable_memory_regions(self, objects=None, force_segment=False):
        """
        Get all executable memory regions from the binaries

        :param objects: A collection of binary objects to collect regions from. If None, regions from all project
                        binary objects are used.
        :param bool force_segment: Rely on binary segments instead of sections.
        :return: A sorted list of tuples (beginning_address, end_address)
        """

        binaries = self.project.loader.all_objects if objects is None else objects

        memory_regions = []

        for b in binaries:
            if not b.has_memory:
                continue

            if isinstance(b, ELF):
                # If we have sections, we get result from sections
                sections = []
                if not force_segment and b.sections:
                    # Get all executable sections
                    for section in b.sections:
                        if section.is_executable:
                            tpl = (section.min_addr, section.max_addr + 1)
                            sections.append(tpl)
                    memory_regions += sections

                segments = []
                # Get all executable segments
                for segment in b.segments:
                    if segment.is_executable:
                        tpl = (segment.min_addr, segment.max_addr + 1)
                        segments.append(tpl)
                if sections and segments:
                    # are there executable segments with no sections inside?
                    for segment in segments:
                        for section in sections:
                            if segment[0] <= section[0] < segment[1]:
                                break
                        else:
                            memory_regions.append(segment)

            elif isinstance(b, (Coff, PE)):
                for section in b.sections:
                    if section.is_executable:
                        tpl = (section.min_addr, section.max_addr + 1)
                        memory_regions.append(tpl)

            elif isinstance(b, XBE):
                # some XBE files will mark the data sections as executable
                for section in b.sections:
                    if (
                        section.is_executable
                        and not section.is_writable
                        and section.name not in {".data", ".rdata", ".rodata"}
                    ):
                        tpl = (section.min_addr, section.max_addr + 1)
                        memory_regions.append(tpl)

            elif isinstance(b, MachO):
                if b.segments:
                    # Get all executable segments
                    for seg in b.segments:
                        if seg.is_executable:
                            # Take all sections from this segment (MachO style)
                            for section in seg.sections:
                                tpl = (section.min_addr, section.max_addr + 1)
                                memory_regions.append(tpl)

            elif isinstance(b, (Hex, SRec)):
                if b.regions:
                    for region_addr, region_size in b.regions:
                        memory_regions.append((region_addr, region_addr + region_size))

            elif isinstance(b, Blob):
                # a blob is entirely executable
                tpl = (b.min_addr, b.max_addr + 1)
                memory_regions.append(tpl)

            elif isinstance(b, NamedRegion):
                # NamedRegions have no content! Ignore
                pass

            elif isinstance(b, self._cle_pseudo_objects):
                pass

            else:
                l.warning('Unsupported object format "%s". Treat it as an executable.', b.__class__.__name__)

                tpl = (b.min_addr, b.max_addr + 1)
                memory_regions.append(tpl)

        if not memory_regions:
            memory_regions = [(start, start + len(backer)) for start, backer in self.project.loader.memory.backers()]

        return sorted(memory_regions, key=lambda x: x[0])

    def _addr_in_exec_memory_regions(self, addr):
        """
        Test if the address belongs to an executable memory region.

        :param int addr: The address to test
        :return: True if the address belongs to an exectubale memory region, False otherwise
        :rtype: bool
        """

        return any(start <= addr < end for start, end in self._exec_mem_regions)

    def _addrs_belong_to_same_section(self, addr_a, addr_b):
        """
        Test if two addresses belong to the same section.

        :param int addr_a:  The first address to test.
        :param int addr_b:  The second address to test.
        :return:            True if the two addresses belong to the same section or both of them do not belong to any
                            section, False otherwise.
        :rtype:             bool
        """

        obj = self.project.loader.find_object_containing(addr_a, membership_check=False)

        if obj is None:
            # test if addr_b also does not belong to any object
            obj_b = self.project.loader.find_object_containing(addr_b, membership_check=False)
            return obj_b is None

        src_section = obj.find_section_containing(addr_a)
        if src_section is None:
            # test if addr_b also does not belong to any section
            dst_section = obj.find_section_containing(addr_b)
            if dst_section is None:
                return self._addrs_belong_to_same_segment(addr_a, addr_b)
            return False

        return src_section.contains_addr(addr_b)

    def _addrs_belong_to_same_segment(self, addr_a, addr_b):
        """
        Test if two addresses belong to the same segment.

        :param int addr_a:  The first address to test.
        :param int addr_b:  The second address to test.
        :return:            True if the two addresses belong to the same segment or both of them do not belong to any
                            section, False otherwise.
        :rtype:             bool
        """

        obj = self.project.loader.find_object_containing(addr_a, membership_check=False)

        if obj is None:
            # test if addr_b also does not belong to any object
            obj_b = self.project.loader.find_object_containing(addr_b, membership_check=False)
            return obj_b is None

        src_segment = obj.find_segment_containing(addr_a)
        if src_segment is None:
            # test if addr_b also does not belong to any section
            dst_segment = obj.find_segment_containing(addr_b)
            return dst_segment is None

        return src_segment.contains_addr(addr_b)

    def _object_has_executable_sections(self, obj):
        """
        Check whether an object has at least one executable section.

        :param cle.Backend obj: The object to test.
        :return:                None
        """

        if obj in self._object_to_executable_sections:
            return self._object_to_executable_sections[obj]
        r = any(sec.is_executable for sec in obj.sections)
        self._object_to_executable_sections[obj] = r
        return r

    def _object_has_executable_segments(self, obj):
        """
        Check whether an object has at least one executable segment.

        :param cle.Backend obj: The object to test.
        :return:                None
        """

        if obj in self._object_to_executable_segments:
            return self._object_to_executable_segments[obj]
        r = any(seg.is_executable for seg in obj.segments)
        self._object_to_executable_segments[obj] = r
        return r

    def _addr_hooked_or_syscall(self, addr):
        """
        Check whether the address belongs to a hook or a syscall.

        :param int addr:    The address to check.
        :return:            True if the address is hooked or belongs to a syscall. False otherwise.
        :rtype:             bool
        """

        return self.project.is_hooked(addr) or self.project.simos.is_syscall_addr(addr)

    def _fast_memory_load_byte(self, addr):
        """
        Perform a fast memory loading of a byte.

        :param int addr: Address to read from.
        :return:         A char or None if the address does not exist.
        :rtype:          int or None
        """

        try:
            return self.project.loader.memory[addr]
        except KeyError:
            return None

    def _fast_memory_load_bytes(self, addr, length):
        """
        Perform a fast memory loading of some data.

        :param int addr: Address to read from.
        :param int length: Size of the string to load.
        :return:         A string or None if the address does not exist.
        :rtype:          bytes or None
        """

        try:
            return self.project.loader.memory.load(addr, length)
        except KeyError:
            return None

    def _fast_memory_load_pointer(self, addr, size=None):
        """
        Perform a fast memory loading of a pointer.

        :param int addr: Address to read from.
        :param int size: Size of the pointer. Default to machine-word size.
        :return:         A pointer or None if the address does not exist.
        :rtype:          int
        """

        try:
            return self.project.loader.memory.unpack_word(addr, size=size)
        except KeyError:
            return None

    def _load_func_addrs_from_symbols(self):
        """
        Get all possible function addresses that are specified by the symbols in the binary

        :return: A set of addresses that are probably functions
        :rtype:  set
        """

        return {sym.rebased_addr for sym in self._binary.symbols if sym.is_function}

    def _load_func_addrs_from_eh_frame(self):
        """
        Get possible function addresses from  .eh_frame.

        :return:    A set of addresses that are probably functions.
        :rtype:     set
        """

        addrs = set()
        if isinstance(self._binary, ELF) and self._binary.has_dwarf_info:
            for function_hint in self._binary.function_hints:
                if function_hint.source == FunctionHintSource.EH_FRAME:
                    addrs.add(function_hint.addr)
        return addrs

    #
    # Analyze function features
    #

    def _determine_function_returning(self, func, all_funcs_completed=False):
        """
        Determine if a function returns or not.

        A function does not return if
        a) it is a SimProcedure that has NO_RET being True,
        or
        b) it is completely recovered (i.e. every block of this function has been recovered, and no future block will
           be added to it), and it does not have a ret or any equivalent instruction.

        A function returns if any of its block contains a ret instruction or any equivalence.

        :param Function func:   The function to work on.
        :param bool all_funcs_completed:    Whether we treat all functions as completed functions or not.
        :return:                True if the function returns, False if the function does not return, or None if it is
                                not yet determinable with the information available at the moment.
        :rtype:                 bool or None
        """

        if not self._inside_regions(func.addr):
            # we don't have a full view of this function. assume it returns
            return True

        # If there is at least one return site, then this function is definitely returning
        if func.has_return:
            return True

        # Let's first see if it's a known SimProcedure that does not return
        if self.project.is_hooked(func.addr):
            procedure = self.project.hooked_by(func.addr)
        else:
            try:
                procedure = self.project.simos.syscall_from_addr(func.addr, allow_unsupported=False)
            except AngrUnsupportedSyscallError:
                procedure = None

        if procedure is not None and hasattr(procedure, "NO_RET"):
            return not procedure.NO_RET

        # did we finish analyzing this function?
        if not all_funcs_completed and func.addr not in self._completed_functions:
            return None

        if not func.block_addrs_set:
            # there is no block inside this function
            # it might happen if the function has been incorrectly identified as part of another function
            # the error will be corrected during post-processing. In fact at this moment we cannot say anything
            # about whether this function returns or not. We always assume it returns.
            return True

        bail_out = False

        # if this function has jump-out sites or ret-out sites, it returns as long as any of the target function
        # returns
        for goout_site, type_ in [(site, "jumpout") for site in func.jumpout_sites] + [
            (site, "retout") for site in func.retout_sites
        ]:
            # determine where it jumps/returns to
            goout_site_successors = goout_site.successors()
            # Filter out UnresolvableJumpTarget because those don't mean that we actually know where it jumps to
            known_successors = [
                n
                for n in goout_site_successors
                if not (isinstance(n, HookNode) and n.sim_procedure == UnresolvableJumpTarget)
            ]

            if not known_successors:
                # not sure where it jumps to. bail out
                bail_out = True
                continue

            # for ret-out sites, determine what function it calls
            if type_ == "retout":
                # see whether the function being called returns or not
                func_successors = [succ for succ in goout_site_successors if isinstance(succ, Function)]
                if func_successors and all(
                    func_successor.returning in (None, False) for func_successor in func_successors
                ):
                    # the returning of all possible function calls are undetermined, or they do not return
                    # ignore this site
                    continue

            if type_ == "retout":
                goout_target = next((succ for succ in goout_site_successors if not isinstance(succ, Function)), None)
            else:
                goout_target = next((succ for succ in goout_site_successors), None)
            if goout_target is None:
                # there is no jumpout site, which is weird, but what can we do...
                continue
            if not self.kb.functions.contains_addr(goout_target.addr):
                # wait it does not jump to a function?
                bail_out = True
                continue

            target_func = self.kb.functions[goout_target.addr]
            if target_func.returning is True:
                return True
            if target_func.returning is None:
                # the returning status of at least one of the target functions is not decided yet.
                bail_out = True

        if bail_out:
            # We cannot determine at this point. bail out
            return None

        # well this function does not return then
        return False

    def _analyze_function_features(self, all_funcs_completed=False):
        """
        For each function in the function_manager, try to determine if it returns or not. A function does not return if
        it calls another function that is known to be not returning, and this function does not have other exits.

        We might as well analyze other features of functions in the future.

        :param bool all_funcs_completed:    Ignore _completed_functions set and treat all functions as completed. This
                                            can be set to True after the entire CFG is built and _post_analysis() is
                                            called (at which point analysis on all functions must be completed).
        """

        changes = {"functions_return": [], "functions_do_not_return": []}

        if self._updated_nonreturning_functions is not None:
            all_func_addrs = self._updated_nonreturning_functions

            # Convert addresses to objects
            all_functions = [
                self.kb.functions.get_by_addr(f) for f in all_func_addrs if self.kb.functions.contains_addr(f)
            ]

        else:
            all_functions = list(self.kb.functions.values())

        analyzed_functions = set()
        # short-hand
        functions: FunctionManager = self.kb.functions

        while all_functions:
            func: Function = all_functions.pop(-1)
            analyzed_functions.add(func.addr)

            if func.returning is not None:
                # It has been determined before. Skip it
                continue

            returning = self._determine_function_returning(func, all_funcs_completed=all_funcs_completed)

            if returning:
                func.returning = True
                changes["functions_return"].append(func)
            elif returning is False:
                func.returning = False
                changes["functions_do_not_return"].append(func)

            if returning is not None and func.addr in functions.callgraph:
                # Add all callers of this function to all_functions list
                callers = functions.callgraph.predecessors(func.addr)
                for caller in callers:
                    if caller in analyzed_functions:
                        continue
                    if functions.contains_addr(caller):
                        all_functions.append(functions.get_by_addr(caller))

        return changes

    def _iteratively_analyze_function_features(self, all_funcs_completed=False):
        """
        Iteratively analyze function features until a fixed point is reached.

        :return: the "changes" dict
        :rtype:  dict
        """

        changes = {"functions_do_not_return": set(), "functions_return": set()}

        while True:
            new_changes = self._analyze_function_features(all_funcs_completed=all_funcs_completed)

            changes["functions_do_not_return"] |= set(new_changes["functions_do_not_return"])
            changes["functions_return"] |= set(new_changes["functions_return"])

            if not new_changes["functions_do_not_return"] and not new_changes["functions_return"]:
                # a fixed point is reached
                break

        return changes

    def normalize(self):
        """
        Normalize the CFG, making sure that there are no overlapping basic blocks.

        Note that this method will not alter transition graphs of each function in self.kb.functions. You may call
        normalize() on each Function object to normalize their transition graphs.

        :return: None
        """

        graph = self.graph

        smallest_nodes = {}  # indexed by end address of the node
        end_addresses_to_nodes = defaultdict(set)

        for n in graph.nodes():
            if n.is_simprocedure:
                continue
            end_addr = n.addr + n.size
            key = (end_addr, n.callstack_key)
            # add the new item
            end_addresses_to_nodes[key].add(n)

        for key in list(end_addresses_to_nodes.keys()):
            if len(end_addresses_to_nodes[key]) == 1:
                smallest_nodes[key] = next(iter(end_addresses_to_nodes[key]))
                del end_addresses_to_nodes[key]

        while end_addresses_to_nodes:
            key_to_find = (None, None)
            for tpl, x in end_addresses_to_nodes.items():
                if len(x) > 1:
                    key_to_find = tpl
                    break

            end_addr, callstack_key = key_to_find
            all_nodes = end_addresses_to_nodes[key_to_find]

            all_nodes = sorted(all_nodes, key=lambda node: node.addr, reverse=True)
            smallest_node = all_nodes[0]  # take the one that has the highest address
            other_nodes = all_nodes[1:]

            self._normalize_core(
                graph, callstack_key, smallest_node, other_nodes, smallest_nodes, end_addresses_to_nodes
            )

            del end_addresses_to_nodes[key_to_find]
            # make sure the smallest node is stored in end_addresses
            smallest_nodes[key_to_find] = smallest_node

            # corner case
            # sometimes two overlapping blocks may not be ending at the instruction. this might happen when one of the
            # blocks (the bigger one) hits the instruction count limit or bytes limit before reaching the end address
            # of the smaller block. in this case we manually pick up those blocks.
            if not end_addresses_to_nodes:
                # find if there are still overlapping blocks
                sorted_smallest_nodes = defaultdict(list)  # callstack_key is the key of this dict
                for k, node in smallest_nodes.items():
                    _, callstack_key = k
                    sorted_smallest_nodes[callstack_key].append(node)
                for k in sorted_smallest_nodes:
                    sorted_smallest_nodes[k] = sorted(sorted_smallest_nodes[k], key=lambda node: node.addr)

                for callstack_key, lst in sorted_smallest_nodes.items():
                    lst_len = len(lst)
                    for i, node in enumerate(lst):
                        if i == lst_len - 1:
                            break
                        next_node = lst[i + 1]
                        if node is not next_node and node.addr <= next_node.addr < node.addr + node.size:
                            # umm, those nodes are overlapping, but they must have different end addresses
                            nodekey_a = node.addr + node.size, callstack_key
                            nodekey_b = next_node.addr + next_node.size, callstack_key
                            if nodekey_a == nodekey_b:
                                # error handling: this will only happen if we have completely overlapping nodes
                                # caused by different jumps (one of the jumps is probably incorrect), which usually
                                # indicates an error in CFG recovery. we print a warning and skip this node
                                l.warning(
                                    "Found completely overlapping nodes %s. It usually indicates an error in CFG "
                                    "recovery. Skip.",
                                    node,
                                )
                                continue

                            if nodekey_a in smallest_nodes and nodekey_b in smallest_nodes:
                                # misuse end_addresses_to_nodes
                                end_addresses_to_nodes[(node.addr + node.size, callstack_key)].add(node)
                                end_addresses_to_nodes[(node.addr + node.size, callstack_key)].add(next_node)

                            smallest_nodes.pop(nodekey_a, None)
                            smallest_nodes.pop(nodekey_b, None)

        self.normalized = True

    def _normalize_core(
        self,
        graph: networkx.DiGraph[CFGNode],
        callstack_key,
        smallest_node,
        other_nodes,
        smallest_nodes,
        end_addresses_to_nodes,
    ):
        # Break other nodes
        for n in other_nodes:
            new_size = get_real_address_if_arm(self.project.arch, smallest_node.addr) - get_real_address_if_arm(
                self.project.arch, n.addr
            )
            if new_size == 0:
                # This node has the same size as the smallest one. Don't touch it.
                continue

            new_end_addr = n.addr + new_size

            # Does it already exist?
            new_node = None
            key = (new_end_addr, n.callstack_key)
            # the logic below is a little convoluted. we check if key exists in either end_address_to_nodes or
            # smallest_nodes, since we don't always add the new node back to end_addresses_to_nodes dict - we only do so
            # when there are more than one node with that key.
            if key in end_addresses_to_nodes:
                new_node = next((i for i in end_addresses_to_nodes[key] if i.addr == n.addr), None)
            if new_node is None and key in smallest_nodes and smallest_nodes[key].addr == n.addr:
                new_node = smallest_nodes[key]

            if new_node is None:
                # Create a new one
                if self.tag == "CFGFast":
                    new_node = CFGNode(
                        n.addr,
                        new_size,
                        self.model,
                        function_address=n.function_address,
                        block_id=n.block_id,
                        instruction_addrs=[i for i in n.instruction_addrs if n.addr <= i <= n.addr + new_size],
                        thumb=n.thumb,
                    )
                elif self.tag == "CFGEmulated":
                    new_node = CFGENode(
                        n.addr,
                        new_size,
                        self.model,
                        callstack_key=callstack_key,
                        function_address=n.function_address,
                        block_id=n.block_id,
                        instruction_addrs=[i for i in n.instruction_addrs if n.addr <= i <= n.addr + new_size],
                        thumb=n.thumb,
                    )
                else:
                    raise ValueError(f"Unknown tag {self.tag}.")

                # Copy instruction addresses
                new_node.instruction_addrs = [
                    ins_addr for ins_addr in n.instruction_addrs if ins_addr < n.addr + new_size
                ]
                # Put the new node into end_addresses list
                if key in smallest_nodes:
                    end_addresses_to_nodes[key].add(smallest_nodes[key])
                    end_addresses_to_nodes[key].add(new_node)
                else:
                    smallest_nodes[key] = new_node

            # Modify the CFG
            original_predecessors = list(graph.in_edges([n], data=True))
            original_successors = list(graph.out_edges([n], data=True))

            if smallest_node not in graph:
                continue

            for _s, d, data in original_successors:
                ins_addr = data.get("ins_addr", None)  # ins_addr might be None for FakeRet edges
                if ins_addr is None and data.get("jumpkind", None) != "Ijk_FakeRet":
                    l.warning(
                        "Unexpected edge with ins_addr being None: %s -> %s, data = %s.",
                        _s,
                        d,
                        str(data),
                    )
                if ins_addr is not None and ins_addr < smallest_node.addr:
                    continue
                if d not in graph[smallest_node]:
                    if d is n:
                        graph.add_edge(smallest_node, new_node, **data)
                    else:
                        graph.add_edge(smallest_node, d, **data)

            for p, _, _ in original_predecessors:
                graph.remove_edge(p, n)
            if n in graph:
                graph.remove_node(n)

            # Update nodes dict
            self._model.remove_node(n.block_id, n)
            self._model.add_node(n.block_id, new_node)

            for p, _, data in original_predecessors:
                # Consider the following case: two basic blocks ending at the same position, where A is larger, and
                # B is smaller. Suppose there is an edge going from the end of A to A itself, and apparently there
                # is another edge from B to A as well. After splitting A into A' and B, we DO NOT want to add A back
                # in, otherwise there will be an edge from A to A`, while A should totally be got rid of in the new
                # graph.
                if p not in other_nodes:
                    graph.add_edge(p, new_node, **data)

            # We should find the correct successor
            new_successors = [i for i in [smallest_node, *other_nodes] if i.addr == smallest_node.addr]
            if new_successors:
                new_successor = new_successors[0]
                graph.add_edge(
                    new_node,
                    new_successor,
                    jumpkind="Ijk_Boring",
                    ins_addr=new_node.instruction_addrs[-1] if new_node.instruction_addrs else new_node.addr,
                )
            else:
                # We gotta create a new one
                l.error("normalize(): Please report it to Fish.")

        # deal with duplicated entries in self.jump_tables and self.indirect_jumps
        if smallest_node.addr in self.model.jump_tables:
            for n in other_nodes:
                if n.addr in self.model.jump_tables:
                    del self.model.jump_tables[n.addr]
        if smallest_node.addr in self.indirect_jumps:
            for n in other_nodes:
                if n.addr in self.indirect_jumps:
                    del self.indirect_jumps[n.addr]

    #
    # Job management
    #

    def _register_analysis_job(self, func_addr, job):
        """
        Register an analysis job of a function to job manager. This allows us to track whether we have finished
        analyzing/recovering a function or not.

        :param int func_addr: Address of the function that this job belongs to.
        :param job:           The job to register. Note that it does not necessarily be the a CFGJob instance. There
                              can be PendingJob or PendingJob or other instances, too.
        :return:              None
        """

        self._jobs_to_analyze_per_function[func_addr].add(job)

    def _deregister_analysis_job(self, func_addr, job):
        """
        Deregister/Remove an analysis job of a function from job manager.

        :param int func_addr: Address of the function that this job belongs to.
        :param job:           The job to deregister.
        :return:              None
        """

        self._jobs_to_analyze_per_function[func_addr].discard(job)

    def _get_finished_functions(self):
        """
        Obtain all functions of which we have finished analyzing. As _jobs_to_analyze_per_function is a defaultdict(),
        if a function address shows up in it with an empty job list, we consider we have exhausted all jobs of this
        function (both current jobs and pending jobs), thus the analysis of this function is done.

        :return: a list of function addresses of that we have finished analysis.
        :rtype:  list
        """

        finished_func_addrs = []
        for func_addr, all_jobs in self._jobs_to_analyze_per_function.items():
            if not all_jobs:
                # great! we have finished analyzing this function!
                finished_func_addrs.append(func_addr)

        return finished_func_addrs

    def _cleanup_analysis_jobs(self, finished_func_addrs=None):
        """
        From job manager, remove all functions of which we have finished analysis.

        :param list or None finished_func_addrs: A list of addresses of functions of which we have finished analysis.
                                                 A new list of function addresses will be obtained by calling
                                                 _get_finished_functions() if this parameter is None.
        :return:                                 None
        """

        if finished_func_addrs is None:
            finished_func_addrs = self._get_finished_functions()

        for func_addr in finished_func_addrs:
            if func_addr in self._jobs_to_analyze_per_function:
                del self._jobs_to_analyze_per_function[func_addr]

    def _make_completed_functions(self):
        """
        Fill in self._completed_functions list and clean up job manager.

        :return: None
        """

        finished = self._get_finished_functions()
        for func_addr in finished:
            if func_addr not in self._completed_functions:
                self._function_completed(func_addr)
                self._completed_functions.add(func_addr)
        self._cleanup_analysis_jobs(finished_func_addrs=finished)

    #
    # Function identification and such
    #

    def mark_function_alignments(self):
        """
        Find all potential function alignments and mark them.

        Note that it is not always correct to simply remove them, because these functions may not be actual alignments
        but part of an actual function, and is incorrectly marked as an individual function because of failures in
        resolving indirect jumps. An example is in the test binary ``x86_64/dir_gcc_-O0`` 0x40541d (indirect jump at
        0x4051b0). If the indirect jump cannot be correctly resolved, removing function 0x40541d will cause a missing
        label failure in reassembler.

        :return: None
        """

        # This function requires Capstone engine support
        if not self.project.arch.capstone_support:
            return

        for func_addr in self.kb.functions:
            function = self.kb.functions[func_addr]
            if function.is_simprocedure or function.is_syscall:
                continue
            if len(function.block_addrs_set) == 1:
                block = next((b for b in function.blocks), None)
                if block is None:
                    continue
                if all(self._is_noop_insn(insn) for insn in block.capstone.insns):
                    # all nops. mark this function as a function alignment
                    l.debug("Function chunk %#x is probably used as a function alignment (all nops).", func_addr)
                    self.kb.functions[func_addr].alignment = True
                    continue
                node = function.get_node(block.addr)
                successors = list(function.graph.successors(node))
                if len(successors) == 1 and successors[0].addr == node.addr:
                    # self loop. mark this function as a function alignment
                    l.debug("Function chunk %#x is probably used as a function alignment (self-loop).", func_addr)
                    self.kb.functions[func_addr].alignment = True
                    continue

    def make_functions(self):
        """
        Revisit the entire control flow graph, create Function instances accordingly, and correctly put blocks into
        each function.

        Although Function objects are crated during the CFG recovery, they are neither sound nor accurate. With a
        pre-constructed CFG, this method rebuilds all functions bearing the following rules:

            - A block may only belong to one function.
            - Small functions lying inside the startpoint and the endpoint of another function will be merged with the
              other function
            - Tail call optimizations are detected.
            - PLT stubs are aligned by 16.

        :return: None
        """

        # TODO: Is it required that PLT stubs are always aligned by 16? If so, on what architectures and platforms is it
        # TODO:  enforced?

        tmp_functions = self.kb.functions.copy()

        for function in tmp_functions.values():
            function.mark_nonreturning_calls_endpoints()
            if function.returning is False:
                # remove all FakeRet edges that are related to this function
                func_node = self.model.get_any_node(function.addr)
                if func_node is not None:
                    callsite_nodes = [
                        src
                        for src, _, data in self.graph.in_edges(func_node, data=True)
                        if data.get("jumpkind", None) == "Ijk_Call"
                    ]
                    for callsite_node in callsite_nodes:
                        for _, dst, data in list(self.graph.out_edges(callsite_node, data=True)):
                            if data.get("jumpkind", None) == "Ijk_FakeRet":
                                self.graph.remove_edge(callsite_node, dst)

        # Clear old functions dict
        self.kb.functions.clear()

        blockaddr_to_function = {}
        traversed_cfg_nodes = set()

        function_nodes = set()

        # Find nodes for beginnings of all functions
        for _, dst, data in self.graph.edges(data=True):
            jumpkind = data.get("jumpkind", "")
            if jumpkind == "Ijk_Call" or jumpkind.startswith("Ijk_Sys"):
                function_nodes.add(dst)

        entry_node = self.model.get_any_node(self._binary.entry)
        if entry_node is not None:
            function_nodes.add(entry_node)

        # aggressively remove and merge functions
        # For any function, if there is a call to it, it won't be removed
        called_function_addrs = {n.addr for n in function_nodes}
        # Any function addresses that appear as symbols won't be removed
        predetermined_function_addrs = called_function_addrs | self._function_addresses_from_symbols

        removed_functions_a = self._process_irrational_functions(
            tmp_functions, predetermined_function_addrs, blockaddr_to_function
        )
        removed_functions_b, adjusted_cfgnodes = self._process_irrational_function_starts(
            tmp_functions, predetermined_function_addrs, blockaddr_to_function
        )
        self._process_jump_table_targeted_functions(
            tmp_functions,
            predetermined_function_addrs,
            blockaddr_to_function,
        )
        removed_functions = removed_functions_a | removed_functions_b

        # Remove all nodes that are adjusted
        function_nodes.difference_update(adjusted_cfgnodes)
        for n in self.graph.nodes():
            if n.addr in tmp_functions or n.addr in removed_functions:
                function_nodes.add(n)

        # traverse the graph starting from each node, not following call edges
        # it's important that we traverse all functions in order so that we have a greater chance to come across
        # rational functions before its irrational counterparts (e.g. due to failed jump table resolution)

        min_stage_2_progress = 50.0
        max_stage_2_progress = 90.0
        nodes_count = len(function_nodes)
        for i, fn in enumerate(sorted(function_nodes, key=lambda n: n.addr)):
            if self._low_priority:
                self._release_gil(i, 800, 0.000001)

            if self._show_progressbar or self._progress_callback:
                progress = min_stage_2_progress + (max_stage_2_progress - min_stage_2_progress) * (
                    i * 1.0 / nodes_count
                )
                self._update_progress(progress)

            self._graph_bfs_custom(
                self.graph,
                [fn],
                self._graph_traversal_handler,
                blockaddr_to_function,
                tmp_functions,
                traversed_cfg_nodes,
            )

        # Don't forget those small function chunks that are not called by anything.
        # There might be references to them from data, or simply references that we cannot find via static analysis

        secondary_function_nodes = set()
        # add all function chunks ("functions" that are not called from anywhere)
        for func_addr in tmp_functions:
            node = self.model.get_any_node(func_addr)
            if node is None:
                continue
            if node.addr not in blockaddr_to_function:
                secondary_function_nodes.add(node)

        missing_cfg_nodes = set(self.graph.nodes()) - traversed_cfg_nodes
        missing_cfg_nodes = {node for node in missing_cfg_nodes if node.function_address is not None}
        if missing_cfg_nodes:
            l.debug("%d CFGNodes are missing in the first traversal.", len(missing_cfg_nodes))
            secondary_function_nodes |= missing_cfg_nodes

        min_stage_3_progress = 90.0
        max_stage_3_progress = 99.9

        nodes_count = len(secondary_function_nodes)
        for i, fn in enumerate(sorted(secondary_function_nodes, key=lambda n: n.addr)):
            if self._show_progressbar or self._progress_callback:
                progress = min_stage_3_progress + (max_stage_3_progress - min_stage_3_progress) * (
                    i * 1.0 / nodes_count
                )
                self._update_progress(progress)

            self._graph_bfs_custom(
                self.graph, [fn], self._graph_traversal_handler, blockaddr_to_function, tmp_functions
            )

        to_remove = set()

        # Remove all stubs after PLT entries
        if not is_arm_arch(self.project.arch):
            to_remove |= self._remove_dummy_plt_stubs(self.kb.functions)

        # remove empty functions
        for func in self.kb.functions.values():
            if func.startpoint is None:
                to_remove.add(func.addr)

        for addr in to_remove:
            del self.kb.functions[addr]

        # Update CFGNode.function_address
        for node in self._nodes.values():
            if node.addr in blockaddr_to_function:
                node.function_address = blockaddr_to_function[node.addr].addr

        # Update function.info
        for func in self.kb.functions.values():
            if func.addr in tmp_functions:
                func.info = tmp_functions[func.addr].info

    def _remove_dummy_plt_stubs(self, functions):
        def _is_function_a_plt_stub(arch_, func):
            if len(func.block_addrs_set) != 1:
                # multiple blocks? no idea what this is...
                return False
            block = next(func.blocks)
            if self._is_noop_block(arch_, block):
                # alignments
                return False

            # TODO: We may want to add support for filtering dummy PLT stubs for other architectures, but I haven't
            # TODO: seen any need for those.
            return not (
                arch_.name in {"X86", "AMD64"}
                and len(block.vex.instruction_addresses) == 2
                and block.vex.jumpkind == "Ijk_Boring"
            )

        to_remove = set()

        met_plts = False
        non_plt_funcs = 0
        sorted_func_addrs = sorted(functions.keys())
        arch = self.project.arch

        # we assume all PLT entries are all located at the same region. the moment we come across the end of it, we
        # stop looping.
        for fn_addr in sorted_func_addrs:
            fn = functions.get_by_addr(fn_addr)
            addr = fn.addr - (fn.addr % 16)
            if (
                addr != fn.addr
                and addr in functions
                and functions[addr].is_plt
                and not _is_function_a_plt_stub(arch, fn)
            ):
                to_remove.add(fn.addr)
                continue

            if fn.is_plt:
                met_plts = True
                non_plt_funcs = 0
            if met_plts and not fn.is_plt:
                non_plt_funcs += 1
            if non_plt_funcs >= 2:
                break

        return to_remove

    def _process_irrational_functions(self, functions, predetermined_function_addrs, blockaddr_to_function):
        """
        When force_complete_scan is enabled, for unresolveable indirect jumps, angr will find jump targets and mark
        them as individual functions. For example, usually the following pattern is seen:

        sub_0x400010:
            push ebp
            mov esp, ebp
            ...
            cmp eax, 10
            ja end
            mov eax, jumptable[eax]
            jmp eax

        sub_0x400080:
            # do something here
            jmp end

        end (0x400e00):
            pop ebp
            ret

        In the example above, `process_irrational_functions` will remove function 0x400080, and merge it with function
        0x400010.

        :param angr.knowledge_plugins.FunctionManager functions: all functions that angr recovers, including those ones
            that are misidentified as functions.
        :param dict blockaddr_to_function: A mapping between block addresses and Function instances.
        :return: A set of addresses of all removed functions
        :rtype: set
        """

        functions_to_remove = {}

        all_func_addrs = sorted(set(functions.keys()))

        for func_pos, (func_addr, function) in enumerate(functions.items()):
            if func_addr in functions_to_remove:
                continue

            # check all blocks and see if any block ends with an indirect jump and is not resolved
            has_unresolved_jumps = False
            # the functions to merge with must be locating between the unresolved basic block address and the endpoint
            # of the current function
            max_unresolved_jump_addr = 0
            for block_addr in function.block_addrs_set:
                if (
                    block_addr in self.indirect_jumps
                    and self.indirect_jumps[block_addr].jumpkind == "Ijk_Boring"
                    and not self.indirect_jumps[block_addr].resolved_targets
                ):
                    # it's not resolved
                    # we should also make sure it's a jump, not a call
                    has_unresolved_jumps = True
                    max_unresolved_jump_addr = max(max_unresolved_jump_addr, block_addr)

            if not has_unresolved_jumps:
                continue

            if function.startpoint is None:
                continue

            startpoint_addr = function.startpoint.addr
            if not function.endpoints:
                # Function should have at least one endpoint
                continue
            endpoint_addr = max(a.addr for a in function.endpoints)
            the_endpoint = next(a for a in function.endpoints if a.addr == endpoint_addr)
            endpoint_addr += the_endpoint.size

            # sanity check: startpoint of the function should be greater than its endpoint
            if startpoint_addr >= endpoint_addr:
                continue
            if max_unresolved_jump_addr <= startpoint_addr or max_unresolved_jump_addr >= endpoint_addr:
                continue

            # scan forward from the endpoint to include any function-tail jumps
            # Here is an example:
            # loc_8049562:
            #       mov eax, ebp
            #       add esp, 3ch
            #       ...
            #       ret
            # loc_804956c:
            #       mov ebp, 3
            #       jmp loc_8049562
            # loc_8049573:
            #       mov ebp, 4
            #       jmp loc_8049562
            #
            last_addr = endpoint_addr
            while True:
                try:
                    # do not follow hooked addresses (such as SimProcedures)
                    if self.project.is_hooked(last_addr):
                        break

                    next_block = self._lift(last_addr)
                    next_block_irsb = next_block.vex_nostmt
                    if next_block_irsb.jumpkind not in ("Ijk_Boring", "Ijk_InvalICache"):
                        break
                    if not isinstance(next_block_irsb.next, pyvex.IRExpr.Const):
                        break
                    suc_addr = next_block_irsb.next.con.value
                    if (
                        max(startpoint_addr, the_endpoint.addr - 0x40)
                        <= suc_addr
                        < the_endpoint.addr + the_endpoint.size
                    ):
                        # increment the endpoint_addr
                        endpoint_addr = next_block.addr + next_block.size
                    else:
                        break

                    last_addr = next_block.addr + next_block.size

                except (SimTranslationError, SimMemoryError, SimIRSBError, SimEngineError):
                    break

            # find all functions that are between [ startpoint, endpoint ]

            should_merge = True
            functions_to_merge = set()
            i = func_pos + 1
            while i < len(all_func_addrs):
                f_addr = all_func_addrs[i]
                i += 1
                f = functions[f_addr]
                if f_addr == func_addr:
                    continue
                if max_unresolved_jump_addr < f_addr < endpoint_addr and all(
                    max_unresolved_jump_addr < b_addr < endpoint_addr for b_addr in f.block_addrs
                ):
                    if f_addr in functions_to_remove:
                        # this function has already been merged with other functions before... it cannot be merged with
                        # this function anymore
                        should_merge = False
                        break
                    if f_addr in predetermined_function_addrs:
                        # this function is a legit one. it shouldn't be removed/merged
                        should_merge = False
                        break
                    functions_to_merge.add(f_addr)

            if not should_merge:
                # we shouldn't merge...
                continue

            for f_addr in functions_to_merge:
                functions_to_remove[f_addr] = func_addr

        # merge all functions
        for to_remove, merge_with in functions_to_remove.items():
            func_merge_with = self._addr_to_function(merge_with, blockaddr_to_function, functions)

            for block_addr in functions[to_remove].block_addrs:
                blockaddr_to_function[block_addr] = func_merge_with

            del functions[to_remove]

        return set(functions_to_remove.keys())

    def _process_irrational_function_starts(self, functions, predetermined_function_addrs, blockaddr_to_function):
        """
        Functions that are identified via function prologues can be starting after the actual beginning of the function.
        For example, the following function (with an incorrect start) might exist after a CFG recovery:

        sub_8049f70:
          push    esi

        sub_8049f71:
          sub     esp, 0A8h
          mov     esi, [esp+0ACh+arg_0]
          mov     [esp+0ACh+var_88], 0

        If the following conditions are met, we will remove the second function and merge it into the first function:
        - The second function is not called by other code.
        - The first function has only one jumpout site, which points to the second function.

        :param FunctionManager functions:   All functions that angr recovers.
        :return:                            A set of addresses of all removed functions.
        :rtype:                             set
        """

        addrs = sorted(
            k for k in functions if not self.project.is_hooked(k) and not self.project.simos.is_syscall_addr(k)
        )
        functions_to_remove = set()
        adjusted_cfgnodes = set()

        for addr_0, addr_1 in zip(addrs[:-1], addrs[1:]):
            if addr_1 in predetermined_function_addrs:
                continue
            if addr_0 in functions_to_remove:
                continue

            func_0 = functions[addr_0]

            if len(func_0.block_addrs_set) >= 1:
                if len(func_0.jumpout_sites) != 1:
                    continue
                block_node = func_0.jumpout_sites[0]
                if block_node is None:
                    continue
                if block_node.size == 0:
                    # skip empty blocks (that are usually caused by lifting failures)
                    continue
                block = func_0.get_block(block_node.addr, block_node.size)
                if block.vex.jumpkind not in ("Ijk_Boring", "Ijk_InvalICache"):
                    continue
                # Skip alignment blocks
                if self._is_noop_block(self.project.arch, block):
                    continue

                # does the first block transition to the next function?
                transition_found = False
                out_edges = list(func_0.transition_graph.out_edges(block_node, data=True))
                for _, dst_node, data in out_edges:
                    if (
                        dst_node.addr == addr_1
                        and data.get("type", None) == "transition"
                        and data.get("outside", False) is True
                    ):
                        transition_found = True
                        break

                if not transition_found:
                    continue

                cfgnode_0 = self.model.get_any_node(block_node.addr)
                cfgnode_1 = self.model.get_any_node(addr_1)

                if cfgnode_0 is None or cfgnode_1 is None:
                    continue

                # who's jumping to or calling cfgnode_1?
                cfgnode_1_preds = self.model.get_predecessors_and_jumpkinds(cfgnode_1, excluding_fakeret=True)
                func_1 = functions[addr_1]
                abort = False
                for pred, jumpkind in cfgnode_1_preds:
                    if pred.addr in func_0.block_addrs_set and jumpkind == "Ijk_Boring":
                        # this is the transition from function 0
                        continue
                    if pred.addr in func_1.block_addrs_set:
                        # this is a transition from function 1 itself
                        continue
                    # found an unexpected edge. give up
                    abort = True
                    break
                if abort:
                    continue

                # Merge block addr_0 and block addr_1
                l.debug("Merging function %#x into %#x.", addr_1, addr_0)

                cfgnode_1_merged = False
                # we only merge two CFG nodes if the first one does not end with a branch instruction
                if (
                    len(func_0.block_addrs_set) == 1
                    and len(out_edges) == 1
                    and out_edges[0][0].addr == cfgnode_0.addr
                    and out_edges[0][0].size == cfgnode_0.size
                    and self.project.factory.block(cfgnode_0.addr, strict_block_end=True).size > cfgnode_0.size
                ):
                    cfgnode_1_merged = True
                    self._merge_cfgnodes(cfgnode_0, cfgnode_1)
                    adjusted_cfgnodes.add(cfgnode_0)
                    adjusted_cfgnodes.add(cfgnode_1)

                # Merge it
                func_1 = functions[addr_1]
                for block_addr in func_1.block_addrs:
                    if block_addr == addr_1 and cfgnode_1_merged:
                        # Skip addr_1 (since it has been merged to the preceding block)
                        continue
                    merge_with = self._addr_to_function(addr_0, blockaddr_to_function, functions)
                    blockaddr_to_function[block_addr] = merge_with

                functions_to_remove.add(addr_1)

        for to_remove in functions_to_remove:
            del functions[to_remove]

        return functions_to_remove, adjusted_cfgnodes

    def _process_jump_table_targeted_functions(
        self, functions, predetermined_function_addrs, blockaddr_to_function
    ) -> set[int]:
        """
        Sometimes compilers will optimize "cold" code regions, make them separate functions, mark them as cold, which
        conflicts with how angr handles jumps to these functions (because they weren't functions to start with). Here
        is an example (in function version_etc_arn() from gllib)::

        switch (n_authors) {
          case 0:
            abort();
          case 1:
            ...
        }

        GCC may decide to move the `abort();` block under case 0 into a separate function (usually named
        "version_etc_arn_cold") and mark it as "cold." When loading function hints from eh frame is enabled, this
        function will be identified, and the recovered switch-case structure will have a jump to a function. It's
        usually not a problem until we need to decompile this function, where (at least for now) angr decompiler
        requires all switch-case entry blocks must belong to the same function.

        The temporary solution is identifying functions that (a) have no call predecessors, and (b) are used as
        jump targets for identified jump tables. Remove these functions so that they can be treated as part of the
        source function where the corresponding jump table belongs.
        """

        jumptable_entries: set[int] = set()
        for jt in self.model.jump_tables.values():
            assert jt.jumptable_entries is not None
            jumptable_entries |= set(jt.jumptable_entries)

        if not jumptable_entries:
            return set()

        functions_to_remove = set()

        for func_addr in functions:
            if func_addr in predetermined_function_addrs:
                continue
            if func_addr in jumptable_entries:
                # is there any call edge pointing to it?
                func_node = self.get_any_node(func_addr)
                if func_node is not None:
                    in_edges = self.graph.in_edges(func_node, data=True)
                    has_transition_pred = None
                    has_non_transition_pred = None
                    for _, _, data in in_edges:
                        if data.get("jumpkind", None) == "Ijk_Boring":
                            has_transition_pred = True
                        else:
                            has_non_transition_pred = True
                    if has_transition_pred is True and not has_non_transition_pred:
                        # all predecessors are transition-only
                        # remove this function
                        functions_to_remove.add(func_addr)

        for to_remove in functions_to_remove:
            del functions[to_remove]
            if to_remove in blockaddr_to_function:
                del blockaddr_to_function[to_remove]

        return functions_to_remove

    def _addr_to_function(self, addr, blockaddr_to_function, known_functions):
        """
        Convert an address to a Function object, and store the mapping in a dict. If the block is known to be part of a
        function, just return that function.

        :param int addr: Address to convert
        :param dict blockaddr_to_function: A mapping between block addresses to Function instances.
        :param angr.knowledge_plugins.FunctionManager known_functions: Recovered functions.
        :return: a Function object
        :rtype: angr.knowledge.Function
        """

        if addr in blockaddr_to_function:
            f = blockaddr_to_function[addr]
        else:
            is_syscall = self.project.simos.is_syscall_addr(addr)

            n = self.model.get_any_node(addr, is_syscall=is_syscall)
            node = addr if n is None else self._to_snippet(n)

            if isinstance(addr, SootAddressDescriptor):
                addr = addr.method

            self.kb.functions._add_node(addr, node, syscall=is_syscall)
            f = self.kb.functions.function(addr=addr)
            assert f is not None

            blockaddr_to_function[addr] = f

            function_is_returning = False
            if addr in known_functions and known_functions.function(addr).returning:
                f.returning = True
                function_is_returning = True

            if not function_is_returning and self._updated_nonreturning_functions is not None:
                # We will rerun function feature analysis on this function later. Add it to
                # self._updated_nonreturning_functions so it can be picked up by function feature analysis later.
                self._updated_nonreturning_functions.add(addr)

        return f

    def _is_tail_call_optimization(
        self,
        g: networkx.DiGraph[CFGNode],
        src_addr,
        dst_addr,
        src_function,
        all_edges: list[tuple[CFGNode, CFGNode, Any]],
        known_functions,
        blockaddr_to_function,
    ):
        """
        If source and destination belong to the same function, and the following criteria apply:
        - source node has only one default exit
        - destination is not one of the known functions
        - destination does not belong to another function, or destination belongs to the same function that
          source belongs to
        - at the end of the block, the SP offset is 0
        - for all other edges that are pointing to the destination node, their source nodes must only have one default
          exit, too

        :return:    True if it is a tail-call optimization. False otherwise.
        :rtype:     bool
        """

        def _has_more_than_one_exit(node_):
            # Do not consider FakeRets as counting as multiple exits here.
            out_edges = [e for e in g.out_edges(node_) if g.get_edge_data(*e)["jumpkind"] != "Ijk_FakeRet"]
            return len(out_edges) > 1

        if len(src_function.block_addrs_set) > 10:
            # ignore functions unless they are extremely small
            return False

        if len(all_edges) == 1 and dst_addr != src_addr:
            the_edge = next(iter(all_edges))
            _, dst, data = the_edge
            if data.get("stmt_idx", None) != DEFAULT_STATEMENT:
                return False

            # relift the source node to make sure it's not a fall-through target
            full_src_node = self.project.factory.block(src_addr)
            if full_src_node.size >= VEX_IRSB_MAX_SIZE or full_src_node.instructions >= VEX_IRSB_MAX_INST:
                # we are probably hitting the max-block limit in VEX
                return False
            if full_src_node.addr <= dst_addr < full_src_node.addr + full_src_node.size:
                return False

            dst_in_edges = g.in_edges(dst, data=True)
            if len(dst_in_edges) > 1:
                # there are other edges going to the destination node. check all edges to make sure all source nodes
                # only have one default exit
                if any(data.get("stmt_idx", None) != DEFAULT_STATEMENT for _, _, data in dst_in_edges):
                    # some nodes are jumping to the destination node via non-default edges. skip.
                    return False
                if any(_has_more_than_one_exit(src_) for src_, _, _ in dst_in_edges):
                    # at least one source node has more than just the default exit. skip.
                    return False

            candidate = False
            if dst_addr in known_functions:
                # dst_addr cannot be the same as src_function.addr. Pass
                pass
            elif dst_addr in blockaddr_to_function:
                # it seems that we already know where this function should belong to. Pass.
                dst_func = blockaddr_to_function[dst_addr]
                if dst_func is src_function:
                    # they belong to the same function right now, but they'd better not
                    candidate = True
                    # treat it as a tail-call optimization
            else:
                # we don't know where it belongs to
                # treat it as a tail-call optimization
                candidate = True

            if candidate:
                regs = {self.project.arch.sp_offset}
                if hasattr(self.project.arch, "bp_offset") and self.project.arch.bp_offset is not None:
                    regs.add(self.project.arch.bp_offset)
                sptracker = self.project.analyses[StackPointerTracker].prep()(
                    src_function, regs, track_memory=self._sp_tracking_track_memory
                )
                sp_delta = sptracker.offset_after_block(src_addr, self.project.arch.sp_offset)
                if sp_delta == 0:
                    return True

        return False

    def _graph_bfs_custom(self, g, starts, callback, blockaddr_to_function, known_functions, traversed_cfg_nodes=None):
        """
        A customized control flow graph BFS implementation with the following rules:
        - Call edges are not followed.
        - Syscall edges are not followed.

        :param networkx.DiGraph g: The graph.
        :param list starts: A collection of beginning nodes to start graph traversal.
        :param func callback: Callback function for each edge and node.
        :param dict blockaddr_to_function: A mapping between block addresses to Function instances.
        :param angr.knowledge_plugins.FunctionManager known_functions: Already recovered functions.
        :param set traversed_cfg_nodes: A set of CFGNodes that are traversed before.
        :return: None
        """

        stack = OrderedSet(starts)
        traversed = set() if traversed_cfg_nodes is None else traversed_cfg_nodes

        while stack:
            n: CFGNode = stack.pop(last=False)

            if n in traversed:
                continue

            traversed.add(n)

            if n.has_return:
                callback(g, n, None, {"jumpkind": "Ijk_Ret"}, blockaddr_to_function, known_functions, None)
            # NOTE: A block that has_return CAN have successors that aren't the return.
            # This is particularly the case for ARM conditional instructions.  Yes, conditional rets are a thing.

            if g.out_degree(n) == 0:
                # it's a single node
                callback(g, n, None, None, blockaddr_to_function, known_functions, None)

            else:
                all_out_edges = g.out_edges(n, data=True)
                for src, dst, data in all_out_edges:
                    callback(g, src, dst, data, blockaddr_to_function, known_functions, all_out_edges)

                    jumpkind = data.get("jumpkind", "")
                    if (not (jumpkind in ("Ijk_Call", "Ijk_Ret") or jumpkind.startswith("Ijk_Sys"))) and (
                        dst not in stack and dst not in traversed
                    ):
                        stack.add(dst)

    def _graph_traversal_handler(self, g, src, dst, data, blockaddr_to_function, known_functions, all_edges):
        """
        Graph traversal handler. It takes in a node or an edge, and create new functions or add nodes to existing
        functions accordingly. Oh, it also create edges on the transition map of functions.

        :param g:           The control flow graph that is currently being traversed.
        :param CFGNode src: Beginning of the edge, or a single node when dst is None.
        :param CFGNode dst: Destination of the edge. For processing a single node, `dst` is None.
        :param dict data: Edge data in the CFG. 'jumpkind' should be there if it's not None.
        :param dict blockaddr_to_function: A mapping between block addresses to Function instances.
        :param angr.knowledge_plugins.FunctionManager known_functions: Already recovered functions.
        :param list or None all_edges: All edges going out from src.
        :return: None
        """

        src_addr = src.addr
        src_function = self._addr_to_function(src_addr, blockaddr_to_function, known_functions)

        if src_addr not in src_function.block_addrs_set:
            n = self.model.get_any_node(src_addr)
            node = src_addr if n is None else self._to_snippet(n)
            self.kb.functions._add_node(src_function.addr, node)

        if data is None:
            # it's a single node only
            return

        jumpkind = data["jumpkind"]

        if jumpkind == "Ijk_Ret":
            n = self.model.get_any_node(src_addr)
            from_node = src_addr if n is None else self._to_snippet(n)
            self.kb.functions._add_return_from(src_function.addr, from_node, None)

        if dst is None:
            return

        dst_addr = dst.addr

        # get instruction address and statement index
        ins_addr = data.get("ins_addr", None)
        stmt_idx = data.get("stmt_idx", None)

        if jumpkind == "Ijk_Call" or jumpkind.startswith("Ijk_Sys"):
            is_syscall = jumpkind.startswith("Ijk_Sys")

            # It must be calling a function
            dst_function = self._addr_to_function(dst_addr, blockaddr_to_function, known_functions)

            n = self.model.get_any_node(src_addr)
            if n is None:
                src_snippet = self._to_snippet(addr=src_addr, base_state=self._base_state)
            else:
                src_snippet = self._to_snippet(cfg_node=n)

            # HACK: FIXME: We need a better way of representing unresolved calls and whether they return.
            # For now, assume UnresolvedTarget returns if we're calling to it

            # If the function doesn't return, don't add a fakeret!
            if not all_edges or (dst_function.returning is False and dst_function.name != "UnresolvableCallTarget"):
                fakeret_node = None
            else:
                fakeret_node = self._one_fakeret_node(all_edges)

            fakeret_snippet = None if fakeret_node is None else self._to_snippet(cfg_node=fakeret_node)

            if isinstance(dst_addr, SootAddressDescriptor):
                dst_addr = dst_addr.method

            self.kb.functions._add_call_to(
                src_function.addr,
                src_snippet,
                dst_addr,
                fakeret_snippet,
                syscall=is_syscall,
                ins_addr=ins_addr,
                stmt_idx=stmt_idx,
            )

            if dst_function.returning and fakeret_node is not None:
                returning_target = src.addr + src.size
                if returning_target not in blockaddr_to_function:
                    if returning_target not in known_functions:
                        blockaddr_to_function[returning_target] = src_function
                    else:
                        self._addr_to_function(returning_target, blockaddr_to_function, known_functions)

                to_outside = blockaddr_to_function[returning_target] is not src_function

                n = self.model.get_any_node(returning_target)
                if n is None:
                    try:
                        returning_snippet = self._to_snippet(addr=returning_target, base_state=self._base_state)
                    except SimEngineError:
                        # it may not exist
                        returning_snippet = None
                else:
                    returning_snippet = self._to_snippet(cfg_node=n)

                if returning_snippet is not None:
                    self.kb.functions._add_fakeret_to(
                        src_function.addr, src_snippet, returning_snippet, confirmed=True, to_outside=to_outside
                    )

        elif jumpkind in ("Ijk_Boring", "Ijk_InvalICache", "Ijk_Exception"):
            # convert src_addr and dst_addr to CodeNodes
            n = self.model.get_any_node(src_addr)
            src_node = src_addr if n is None else self._to_snippet(cfg_node=n)

            n = self.model.get_any_node(dst_addr)
            dst_node = dst_addr if n is None else self._to_snippet(cfg_node=n)

            if self._skip_unmapped_addrs:
                # pre-check: if source and destination do not belong to the same section, it must be jumping to another
                # function
                belong_to_same_section = self._addrs_belong_to_same_section(src_addr, dst_addr)
                if not belong_to_same_section:
                    _ = self._addr_to_function(dst_addr, blockaddr_to_function, known_functions)

            if self._detect_tail_calls and self._is_tail_call_optimization(
                g, src_addr, dst_addr, src_function, all_edges, known_functions, blockaddr_to_function
            ):
                l.debug("Possible tail-call optimization detected at function %#x.", dst_addr)
                # it's (probably) a tail-call optimization. we should make the destination node a new function
                # instead.
                blockaddr_to_function.pop(dst_addr, None)
                _ = self._addr_to_function(dst_addr, blockaddr_to_function, known_functions)
                self.kb.functions._add_outside_transition_to(
                    src_function.addr, src_node, dst_node, to_function_addr=dst_addr
                )
                self._tail_calls.add(dst_addr)

            # is it a jump to another function?
            if isinstance(dst_addr, SootAddressDescriptor):
                is_known_function_addr = dst_addr.method in known_functions and dst_addr.method.addr == dst_addr
            else:
                is_known_function_addr = dst_addr in known_functions

            if (is_known_function_addr and dst_addr != src_function.addr) or (
                dst_addr in blockaddr_to_function and blockaddr_to_function[dst_addr] is not src_function
            ):
                # yes it is
                dst_function_addr = (
                    blockaddr_to_function[dst_addr].addr if dst_addr in blockaddr_to_function else dst_addr
                )

                self.kb.functions._add_outside_transition_to(
                    src_function.addr,
                    src_node,
                    dst_node,
                    ins_addr=ins_addr,
                    stmt_idx=stmt_idx,
                    to_function_addr=dst_function_addr,
                    is_exception=jumpkind == "Ijk_Exception",
                )

                _ = self._addr_to_function(dst_addr, blockaddr_to_function, known_functions)
            else:
                # no it's not
                # add the transition code

                if dst_addr not in blockaddr_to_function:
                    blockaddr_to_function[dst_addr] = src_function

                self.kb.functions._add_transition_to(
                    src_function.addr,
                    src_node,
                    dst_node,
                    ins_addr=ins_addr,
                    stmt_idx=stmt_idx,
                    is_exception=jumpkind == "Ijk_Exception",
                )

        elif jumpkind == "Ijk_FakeRet":
            # convert src_addr and dst_addr to CodeNodes
            n = self.model.get_any_node(src_addr)
            src_node = src_addr if n is None else self._to_snippet(n)

            n = self.model.get_any_node(dst_addr)
            dst_node = dst_addr if n is None else self._to_snippet(n)

            if dst_addr not in blockaddr_to_function:
                if isinstance(dst_addr, SootAddressDescriptor):
                    if dst_addr.method not in known_functions:
                        blockaddr_to_function[dst_addr] = src_function
                        target_function = src_function
                    else:
                        target_function = self._addr_to_function(dst_addr, blockaddr_to_function, known_functions)
                else:
                    if dst_addr not in known_functions:
                        blockaddr_to_function[dst_addr] = src_function
                        target_function = src_function
                    else:
                        target_function = self._addr_to_function(dst_addr, blockaddr_to_function, known_functions)
            else:
                target_function = blockaddr_to_function[dst_addr]

            # Figure out if the function called (not the function returned to) returns.
            # We may have determined that this does not happen, since the time this path
            # was scheduled for exploration
            called_function = None
            called_function_addr = None
            # Try to find the call that this fakeret goes with
            for _, d, e in all_edges:
                if e["jumpkind"] == "Ijk_Call" and d.addr in blockaddr_to_function:
                    called_function = blockaddr_to_function[d.addr]
                    called_function_addr = d.addr
                    break
            # We may have since figured out that the called function doesn't ret.
            # It's important to assume that all unresolved targets do return
            if called_function is not None and called_function.returning is False:
                return

            to_outside = target_function is not src_function

            confirmed = called_function is None or called_function.returning is True
            self.kb.functions._add_fakeret_to(
                src_function.addr,
                src_node,
                dst_node,
                confirmed=confirmed,
                to_outside=to_outside,
                to_function_addr=called_function_addr,
            )

        else:
            l.debug("Ignored jumpkind %s", jumpkind)

    #
    # Other functions
    #

    @staticmethod
    def _is_noop_block(arch: archinfo.Arch, block):
        """
        Check if the block is a no-op block by checking VEX statements.

        :param arch:    An architecture descriptor.
        :param block: The VEX block instance.
        :return: True if the entire block is a single-byte or multi-byte nop instruction, False otherwise.
        :rtype: bool
        """

        if arch.name == "X86" or arch.name == "AMD64":
            if set(block.bytes) == {"b\x90"}:
                return True
        elif arch.name == "MIPS32":
            if arch.memory_endness == "Iend_BE":
                MIPS32_BE_NOOPS = {
                    b"\x00\x20\x08\x25",  # move $at, $at
                }
                insns = {block.bytes[i : i + 4] for i in range(0, block.size, 4)}
                if MIPS32_BE_NOOPS.issuperset(insns):
                    return True

        elif is_arm_arch(arch):
            if block.addr & 1 == 0:
                # ARM mode
                if arch.memory_endness == archinfo.Endness.LE:
                    ARM_NOOPS = {
                        b"\x00\x00\x00\x00",  # andeq r0, r0, r0
                        b"\x00\x00\xa0\xe1",  # mov r0, r0
                    }
                else:  # if arch.memory_endness == archinfo.Endness.BE:
                    ARM_NOOPS = {
                        b"\x00\x00\x00\x00",  # andeq r0, r0, r0
                        b"\xe1\xa0\x00\x00",  # mov r0, r0
                    }
                insns = {block.bytes[i : i + 4] for i in range(0, block.size, 4)}
                if ARM_NOOPS.issuperset(insns):
                    return True

            else:
                # THUMB mode, 2-byte instructions
                if arch.memory_endness == archinfo.Endness.LE:
                    THUMB_NOOPS = {
                        b"\xc0\x46",  # mov r8, r8
                        b"\xb0\x00",  # add sp, #0
                        b"\x00\xbf",  # nop
                    }
                else:
                    THUMB_NOOPS = {
                        b"\x46\xc0",  # mov r8, r8
                        b"\x00\xb0",  # add sp, #0
                        b"\xbf\x00",  # nop
                    }
                insns = {block.bytes[i : i + 2] for i in range(0, block.size, 2)}
                if THUMB_NOOPS.issuperset(insns):
                    return True

        # Fallback
        # the block is a noop block if it only has IMark statements **and** it jumps to its immediate successor. VEX
        # will generate such blocks when opt_level==1 and cross_insn_opt is True
        fallthrough_addr = block.addr + block.size
        next_ = block.vex.next
        if (
            isinstance(next_, pyvex.IRExpr.Const)
            and next_.con.value == fallthrough_addr
            and all((type(stmt) is pyvex.IRStmt.IMark) for stmt in block.vex.statements)
        ):
            return True

        # the block is a noop block if it only has IMark statements and IP-setting statements that set the IP to the
        # next location. VEX will generate such blocks when opt_level==1 and cross_insn_opt is False
        ip_offset = arch.ip_offset
        if (
            all(
                (type(stmt) is pyvex.IRStmt.IMark or (type(stmt) is pyvex.IRStmt.Put and stmt.offset == ip_offset))
                for stmt in block.vex.statements
            )
            and block.vex.statements
        ):
            last_stmt = block.vex.statements[-1]
            if (
                isinstance(last_stmt, pyvex.IRStmt.IMark)
                and isinstance(next_, pyvex.IRExpr.Const)
                and next_.con.value == fallthrough_addr
            ):
                return True
        return False

    @staticmethod
    def _is_noop_insn(insn):
        """
        Check if the instruction does nothing.

        :param insn: The capstone insn object.
        :return: True if the instruction does no-op, False otherwise.
        """

        insn_name = insn.insn_name()

        if insn_name == "nop":
            # nops
            return True
        if insn_name == "lea":
            # lea reg, [reg + 0]
            op0, op1 = insn.operands
            # reg and mem
            if op0.type == 1 and op1.type == 3 and op0.reg == op1.mem.base and op1.mem.index == 0 and op1.mem.disp == 0:
                return True
        elif insn_name == "mov":
            if len(insn.operands) > 2:
                # mov reg_a, imm1, shift imm2
                # This is not a NOP
                return False
            # mov reg_a, reg_a
            op0, op1 = insn.operands
            # reg and reg
            if op0.type == 1 and op1.type == 1 and op0.reg == op1.reg:
                return True
        elif insn_name in {"ud0", "ud1", "ud2"}:
            return True

        # add more types of no-op instructions here :-)

        return False

    @classmethod
    def _get_nop_length(cls, insns):
        """
        Calculate the total size of leading nop instructions.

        :param insns: A list of capstone insn objects.
        :return: Number of bytes of leading nop instructions.
        :rtype: int
        """

        nop_length = 0

        if insns and cls._is_noop_insn(insns[0]):
            # see where those nop instructions terminate
            for insn in insns:
                if cls._is_noop_insn(insn):
                    nop_length += insn.size
                else:
                    break

        return nop_length

    @staticmethod
    def _one_fakeret_node(all_edges):
        """
        Pick the first Ijk_FakeRet edge from all_edges, and return the destination node.

        :param list all_edges: A list of networkx.Graph edges with data.
        :return:               The first FakeRet node, or None if nothing is found.
        :rtype:                CFGNode or None
        """

        for _, dst, data in all_edges:
            if data.get("jumpkind", None) == "Ijk_FakeRet":
                return dst
        return None

    def _lift(self, addr, *args, opt_level=1, cross_insn_opt=False, **kwargs):
        """
        Lift a basic block of code. Will use the base state as a source of bytes if possible.
        """
        if "backup_state" not in kwargs:
            kwargs["backup_state"] = self._base_state
        return self.project.factory.block(addr, *args, opt_level=opt_level, cross_insn_opt=cross_insn_opt, **kwargs)

    #
    # Indirect jumps processing
    #

    def _resolve_indirect_jump_timelessly(self, addr, block, func_addr, jumpkind):
        """
        Attempt to quickly resolve an indirect jump.

        :param int addr:        Basic block address of this indirect jump.
        :param block:           The basic block. The type is determined by the backend being used. It's pyvex.IRSB if
                                pyvex is used as the backend.
        :param int func_addr:   Address of the function that this indirect jump belongs to.
        :param str jumpkind:    The jumpkind.
        :return:                A tuple of a boolean indicating whether the resolution is successful or not, and a list
                                of resolved targets (ints).
        :rtype:                 tuple
        """

        # pre-check: if re-lifting the block with full optimization (cross-instruction-optimization enabled) gives us
        # a constant next expression, we don't need to resolve it
        try:
            relifted = self.project.factory.block(block.addr, size=block.size, opt_level=1, cross_insn_opt=True).vex
        except SimError:
            return False, []
        if isinstance(relifted.next, pyvex.IRExpr.Const):
            # yes!
            return True, [relifted.next.con.value]

        if block.statements is None:
            # make sure there are statements
            block = self.project.factory.block(block.addr, size=block.size).vex

        for res in self.timeless_indirect_jump_resolvers:
            if res.filter(self, addr, func_addr, block, jumpkind):
                r, resolved_targets = res.resolve(self, addr, func_addr, block, jumpkind)
                if r:
                    return True, resolved_targets
        return False, []

    def _indirect_jump_resolved(self, jump, jump_addr, resolved_by, targets):
        """
        Called when an indirect jump is successfully resolved.

        :param IndirectJump jump:                   The resolved indirect jump, or None if an IndirectJump instance is
                                                    not available.
        :param int jump_addr:                       Address of the resolved indirect jump.
        :param IndirectJumpResolver resolved_by:    The resolver used to resolve this indirect jump.
        :param list targets:                        List of indirect jump targets.
        :param CFGJob job:                          The job at the start of the block containing the indirect jump.

        :return: None
        """

        addr = jump.addr if jump is not None else jump_addr
        l.debug(
            "The indirect jump at %#x is successfully resolved by %s. It has %d targets.",
            addr,
            resolved_by,
            len(targets),
        )
        self.kb.indirect_jumps.update_resolved_addrs(addr, targets)

    def _indirect_jump_unresolved(self, jump):
        """
        Called when we cannot resolve an indirect jump.

        :param IndirectJump jump: The unresolved indirect jump.

        :return: None
        """

        l.debug("Failed to resolve the indirect jump at %#x.", jump.addr)
        # tell KnowledgeBase that it's not resolved
        # TODO: self.kb._unresolved_indirect_jumps is not processed during normalization. Fix it.
        self.kb.unresolved_indirect_jumps.add(jump.addr)

    def _indirect_jump_encountered(
        self,
        addr: int,
        cfg_node: CFGNode,
        irsb: pyvex.IRSB,
        func_addr: int,
        stmt_idx: int | str = DEFAULT_STATEMENT,
    ) -> tuple[bool, set[int], IndirectJump | None]:
        """
        Called when we encounter an indirect jump. We will try to resolve this indirect jump using timeless (fast)
        indirect jump resolvers. If it cannot be resolved, we will see if this indirect jump has been resolved before.

        :param addr:        Address of the block containing the indirect jump.
        :param cfg_node:    The CFGNode instance of the block that contains the indirect jump.
        :param irsb:        The IRSB instance of the block that contains the indirect jump. It must be lifted with
                            cross-instruction optimization disabled (cross_insn_opt=True when opt_level=1, or
                            opt_level=0).
        :param func_addr:   Address of the current function.
        :param stmt_idx:    ID of the source statement.

        :return:    A 3-tuple of (whether it is resolved or not, all resolved targets, an IndirectJump object
                    if there is one or None otherwise)
        """

        jumpkind = irsb.jumpkind
        l.debug("IRSB %#x has an indirect jump (%s) as its default exit.", addr, jumpkind)

        # try resolving it fast
        resolved, resolved_targets = self._resolve_indirect_jump_timelessly(addr, irsb, func_addr, jumpkind)
        if resolved:
            l.debug(
                "Indirect jump at block %#x is resolved by a timeless indirect jump resolver. %d targets found.",
                addr,
                len(resolved_targets),
            )
            return True, set(resolved_targets), None

        l.debug("Indirect jump at block %#x cannot be resolved by a timeless indirect jump resolver.", addr)

        # Add it to our set. Will process it later if user allows.
        # Create an IndirectJump instance
        if addr not in self.indirect_jumps:
            if self.project.arch.branch_delay_slot:
                if len(cfg_node.instruction_addrs) < 2:
                    # sanity check
                    # decoding failed when decoding the second instruction (or even the first instruction)
                    return False, set(), None
                ins_addr = cfg_node.instruction_addrs[-2]
            elif cfg_node.instruction_addrs:
                ins_addr = cfg_node.instruction_addrs[-1]
            else:
                # fallback
                ins_addr = addr
            assert jumpkind is not None
            ij = IndirectJump(addr, ins_addr, func_addr, jumpkind, stmt_idx, resolved_targets=[])
            self.indirect_jumps[addr] = ij
            resolved = False
        else:
            ij: IndirectJump = self.indirect_jumps[addr]
            resolved = len(ij.resolved_targets) > 0

        return resolved, ij.resolved_targets, ij

    def _process_unresolved_indirect_jumps(self):
        """
        Resolve all unresolved indirect jumps found in previous scanning.

        Currently we support resolving the following types of indirect jumps:
        - Ijk_Call: indirect calls where the function address is passed in from a proceeding basic block
        - Ijk_Boring: jump tables
        - For an up-to-date list, see analyses/cfg/indirect_jump_resolvers

        :return:    A set of concrete indirect jump targets (ints).
        :rtype:     set
        """

        l.info("%d indirect jumps to resolve.", len(self._indirect_jumps_to_resolve))

        all_targets = set()
        idx: int
        jump: IndirectJump
        for idx, jump in enumerate(self._indirect_jumps_to_resolve):
            if self._low_priority:
                self._release_gil(idx, 50, 0.000001)
            all_targets |= self._process_one_indirect_jump(jump)

        self._indirect_jumps_to_resolve.clear()

        return all_targets

    def _process_one_indirect_jump(self, jump: IndirectJump, func_graph_complete: bool = True) -> set:
        """
        Resolve a given indirect jump.

        :param jump:                The IndirectJump instance.
        :param func_graph_complete: True if the function graph is complete at this point (except for this indirect jump
                                    and all nodes that it dominates). Indirect jump resolvers may use the current
                                    function graph to perform sanity checks. CFGEmulated sets func_graph_complete to
                                    False while CFGFast sets it to True (because in CFGFast, indirect jumps are always
                                    resolved after direct jump jobs are processed).
        :return:                    A set of resolved indirect jump targets (ints).
        """

        resolved = False
        resolved_by = None
        targets = None

        block = self._lift(jump.addr)

        for resolver in self.indirect_jump_resolvers:
            resolver.base_state = self._base_state

            if not resolver.filter(self, jump.addr, jump.func_addr, block, jump.jumpkind):
                continue

            resolved, targets = resolver.resolve(
                self, jump.addr, jump.func_addr, block, jump.jumpkind, func_graph_complete=func_graph_complete
            )
            if resolved:
                resolved_by = resolver
                break

        if resolved:
            self._indirect_jump_resolved(jump, jump.addr, resolved_by, targets)
        else:
            self._indirect_jump_unresolved(jump)

        return set() if targets is None else set(targets)
