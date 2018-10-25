
import itertools
import logging
import struct
from collections import defaultdict

import cffi
import networkx

import pyvex
from claripy.utils.orderedset import OrderedSet
from cle import ELF, PE, Blob, TLSObject, MachO, ExternObject, KernelObject

from ...misc.ux import deprecated
from ... import SIM_PROCEDURES
from ...errors import AngrCFGError, SimTranslationError, SimMemoryError, SimIRSBError, SimEngineError,\
    AngrUnsupportedSyscallError, SimError
from ...codenode import HookNode, BlockNode
from ...knowledge_plugins import FunctionManager, Function
from .. import Analysis
from .cfg_node import CFGNode, CFGNodeA
from .indirect_jump_resolvers.default_resolvers import default_indirect_jump_resolvers

l = logging.getLogger("angr.analyses.cfg.cfg_base")


class IndirectJump(object):

    __slots__ = [ "addr", "ins_addr", "func_addr", "jumpkind", "stmt_idx", "resolved_targets", "jumptable",
                  "jumptable_addr", "jumptable_entries",
                  ]

    def __init__(self, addr, ins_addr, func_addr, jumpkind, stmt_idx, resolved_targets=None, jumptable=False,
                 jumptable_addr=None, jumptable_entries=None):
        self.addr = addr
        self.ins_addr = ins_addr
        self.func_addr = func_addr
        self.jumpkind = jumpkind
        self.stmt_idx = stmt_idx
        self.resolved_targets = set() if resolved_targets is None else set(resolved_targets)
        self.jumptable = jumptable
        self.jumptable_addr = jumptable_addr
        self.jumptable_entries = jumptable_entries

    def __repr__(self):

        status = ""
        if self.jumptable:
            status = "jumptable"
            if self.jumptable_addr is not None:
                status += "@%#08x" % self.jumptable_addr
            if self.jumptable_entries is not None:
                status += " with %d entries" % len(self.jumptable_entries)

        return "<IndirectJump %#08x - ins %#08x%s>" % (self.addr, self.ins_addr, " " + status if status else "")


class CFGBase(Analysis):
    """
    The base class for control flow graphs.
    """

    tag = None

    def __init__(self, sort, context_sensitivity_level, normalize=False, binary=None, force_segment=False, iropt_level=None, base_state=None,
                 resolve_indirect_jumps=True, indirect_jump_resolvers=None, indirect_jump_target_limit=100000):
        """
        :param str sort:                            'fast' or 'emulated'.
        :param int context_sensitivity_level:       The level of context-sensitivity of this CFG (see documentation for
                                                    further details). It ranges from 0 to infinity.
        :param bool normalize:                      Whether the CFG as well as all Function graphs should be normalized.
        :param cle.backends.Backend binary:         The binary to recover CFG on. By default the main binary is used.
        :param bool force_segment:                  Force CFGFast to rely on binary segments instead of sections.
        :param int iropt_level:                     The optimization level of VEX IR (0, 1, 2). The default level will
                                                    be used if `iropt_level` is None.
        :param angr.SimState base_state:            A state to use as a backer for all memory loads.
        :param bool resolve_indirect_jumps:         Whether to try to resolve indirect jumps. This is necessary to resolve jump
                                                    targets from jump tables, etc.
        :param list indirect_jump_resolvers:        A custom list of indirect jump resolvers. If this list is None or empty,
                                                    default indirect jump resolvers specific to this architecture and binary
                                                    types will be loaded.
        :param int indirect_jump_target_limit:      Maximum indirect jump targets to be recovered.

        :return: None
        """

        self.sort = sort
        self._context_sensitivity_level=context_sensitivity_level

        # Sanity checks
        if context_sensitivity_level < 0:
            raise ValueError("Unsupported context sensitivity level %d" % context_sensitivity_level)

        self._binary = binary if binary is not None else self.project.loader.main_object
        self._force_segment = force_segment
        self._iropt_level = iropt_level
        self._base_state = base_state

        # Initialization
        self._graph = None
        self._edge_map = None
        self._loop_back_edges = None
        self._overlapped_loop_headers = None
        self._thumb_addrs = set()

        # Traverse all the IRSBs, and put the corresponding CFGNode objects to a dict
        # CFGNodes dict indexed by block ID
        self._nodes = None
        # Lists of CFGNodes indexed by addresses of each block
        self._nodes_by_addr = None

        # Store all the functions analyzed before the set is cleared
        # Used for performance optimization
        self._updated_nonreturning_functions = None

        self._normalize = normalize
        # Flag, whether the CFG has been normalized or not
        self._normalized = False

        # IndirectJump object that describe all indirect exits found in the binary
        # stores as a map between addresses and IndirectJump objects
        self.indirect_jumps = {}
        self._indirect_jumps_to_resolve = set()

        # Indirect jump resolvers
        self._indirect_jump_target_limit = indirect_jump_target_limit
        self._resolve_indirect_jumps = resolve_indirect_jumps
        self.timeless_indirect_jump_resolvers = [ ]
        self.indirect_jump_resolvers = [ ]
        if not indirect_jump_resolvers:
            indirect_jump_resolvers = default_indirect_jump_resolvers(self._binary, self.project)
        if self._resolve_indirect_jumps and indirect_jump_resolvers:
            # split them into different groups for the sake of speed
            for ijr in indirect_jump_resolvers:
                if ijr.timeless:
                    self.timeless_indirect_jump_resolvers.append(ijr)
                else:
                    self.indirect_jump_resolvers.append(ijr)

        l.info("Loaded %d indirect jump resolvers (%d timeless, %d generic).",
               len(self.timeless_indirect_jump_resolvers) + len(self.indirect_jump_resolvers),
               len(self.timeless_indirect_jump_resolvers),
               len(self.indirect_jump_resolvers)
               )

        # Get all executable memory regions
        self._exec_mem_regions = self._executable_memory_regions(None, self._force_segment)
        self._exec_mem_region_size = sum([(end - start) for start, end in self._exec_mem_regions])

        # initialize an UnresolvableTarget SimProcedure
        # but we do not want to hook the same symbol multiple times
        ut_addr = self.project.loader.extern_object.get_pseudo_addr('UnresolvableTarget')
        if not self.project.is_hooked(ut_addr):
            self.project.hook(ut_addr, SIM_PROCEDURES['stubs']['UnresolvableTarget']())
        self._unresolvable_target_addr = ut_addr

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

        self._ffi = cffi.FFI()

    def __contains__(self, cfg_node):
        return cfg_node in self._graph

    @property
    def normalized(self):
        return self._normalized

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

    def _initialize_cfg(self):
        """
        Re-create the DiGraph
        """
        self._graph = networkx.DiGraph()

        self.kb.functions = FunctionManager(self.kb)

        self._jobs_to_analyze_per_function = defaultdict(set)
        self._completed_functions = set()

    def _post_analysis(self):

        if self._normalize:

            if not self._normalized:
                self.normalize()

            # Call normalize() on each function
            for f in self.kb.functions.values():
                if not self.project.is_hooked(f.addr):
                    f.normalize()

    def make_copy(self, copy_to):
        """
        Copy self attributes to the new object.

        :param CFGBase copy_to: The target to copy to.
        :return: None
        """

        copy_to._normalized = self._normalized

    # pylint: disable=no-self-use
    def copy(self):
        raise NotImplementedError()

    def output(self):
        raise NotImplementedError()

    def generate_index(self):
        """
        Generate an index of all nodes in the graph in order to speed up get_any_node() with anyaddr=True.

        :return: None
        """

        raise NotImplementedError("I'm too lazy to implement it right now")

    @deprecated(replacement='nodes()')
    def get_bbl_dict(self):
        return self._nodes

    def get_predecessors(self, cfgnode, excluding_fakeret=True, jumpkind=None):
        """
        Get predecessors of a node in the control flow graph.

        :param CFGNode cfgnode:             The node.
        :param bool excluding_fakeret:      True if you want to exclude all predecessors that is connected to the node
                                            with a fakeret edge.
        :param str or None jumpkind:        Only return predecessors with the specified jumpkind. This argument will be
                                            ignored if set to None.
        :return:                            A list of predecessors
        :rtype:                             list
        """

        if excluding_fakeret and jumpkind == 'Ijk_FakeRet':
            return [ ]

        if not excluding_fakeret and jumpkind is None:
            # fast path
            if cfgnode in self._graph:
                return list(self._graph.predecessors(cfgnode))
            return [ ]

        predecessors = []
        for pred, _, data in self._graph.in_edges([cfgnode], data=True):
            jk = data['jumpkind']
            if jumpkind is not None:
                if jk == jumpkind:
                    predecessors.append(pred)
            elif excluding_fakeret:
                if jk != 'Ijk_FakeRet':
                    predecessors.append(pred)
            else:
                predecessors.append(pred)
        return predecessors

    def get_successors(self, basic_block, excluding_fakeret=True, jumpkind=None):
        """
        Get successors of a node in the control flow graph.

        :param CFGNode basic_block:             The node.
        :param bool excluding_fakeret:      True if you want to exclude all successors that is connected to the node
                                            with a fakeret edge.
        :param str or None jumpkind:        Only return successors with the specified jumpkind. This argument will be
                                            ignored if set to None.
        :return:                            A list of successors
        :rtype:                             list
        """

        if jumpkind is not None:
            if excluding_fakeret and jumpkind == 'Ijk_FakeRet':
                return [ ]

        if not excluding_fakeret and jumpkind is None:
            # fast path
            if basic_block in self._graph:
                return list(self._graph.successors(basic_block))
            return [ ]

        successors = []
        for _, suc, data in self._graph.out_edges([basic_block], data=True):
            jk = data['jumpkind']
            if jumpkind is not None:
                if jumpkind == jk:
                    successors.append(suc)
            elif excluding_fakeret:
                if jk != 'Ijk_FakeRet':
                    successors.append(suc)
            else:
                successors.append(suc)
        return successors

    def get_successors_and_jumpkind(self, basic_block, excluding_fakeret=True):
        successors = []
        for _, suc, data in self._graph.out_edges([basic_block], data=True):
            if not excluding_fakeret or data['jumpkind'] != 'Ijk_FakeRet':
                successors.append((suc, data['jumpkind']))
        return successors

    def get_all_predecessors(self, cfgnode):
        """
        Get all predecessors of a specific node on the control flow graph.

        :param CFGNode cfgnode: The CFGNode object
        :return: A list of predecessors in the CFG
        :rtype: list
        """

        return list(networkx.dfs_predecessors(self._graph, cfgnode))

    def get_all_successors(self, basic_block):
        return list(networkx.dfs_successors(self._graph, basic_block))

    def get_node(self, block_id):
        """
        Get a single node from node key.

        :param BlockID block_id: Block ID of the node.
        :return:                 The CFGNode
        :rtype:                  CFGNode
        """
        if block_id in self._nodes:
            return self._nodes[block_id]
        return None

    def get_any_node(self, addr, is_syscall=None, anyaddr=False):
        """
        Get an arbitrary CFGNode (without considering their contexts) from our graph.

        :param int addr:        Address of the beginning of the basic block. Set anyaddr to True to support arbitrary
                                address.
        :param bool is_syscall: Whether you want to get the syscall node or any other node. This is due to the fact that
                                syscall SimProcedures have the same address as the targer it returns to.
                                None means get either, True means get a syscall node, False means get something that isn't
                                a syscall node.
        :param bool anyaddr:    If anyaddr is True, then addr doesn't have to be the beginning address of a basic
                                block. By default the entire graph.nodes() will be iterated, and the first node
                                containing the specific address is returned, which is slow. If you need to do many such
                                queries, you may first call `generate_index()` to create some indices that may speed up the
                                query.
        :return: A CFGNode if there is any that satisfies given conditions, or None otherwise
        """

        # fastpath: directly look in the nodes list
        if not anyaddr and self._nodes_by_addr and \
                addr in self._nodes_by_addr and self._nodes_by_addr[addr]:
            return self._nodes_by_addr[addr][0]

        # slower path
        #if self._node_lookup_index is not None:
        #    pass

        # the slowest path
        # try to show a warning first
        # TODO: re-enable it once the segment tree is implemented
        #if self._node_lookup_index_warned == False:
        #    l.warning('Calling get_any_node() with anyaddr=True is slow on large programs. '
        #              'For better performance, you may first call generate_index() to generate some indices that may '
        #              'speed the node lookup.')
        #    self._node_lookup_index_warned = True

        for n in self.graph.nodes():
            if self.tag == "CFGEmulated":
                cond = n.looping_times == 0
            else:
                cond = True
            if anyaddr and n.size is not None:
                cond = cond and (addr >= n.addr and addr < n.addr + n.size)
            else:
                cond = cond and (addr == n.addr)
            if cond:
                if is_syscall is None:
                    return n
                if n.is_syscall == is_syscall:
                    return n

        return None

    def irsb_from_node(self, cfg_node):  # pylint:disable=unused-argument
        """
        Create an IRSB from a CFGNode object.
        """
        raise DeprecationWarning('"irsb_from_node()" is deprecated since SimIRSB does not exist anymore.')

    def get_any_irsb(self, addr):  # pylint:disable=unused-argument
        """
        Returns an IRSB of a certain address. If there are many IRSBs with the same address in CFG, return an arbitrary
        one.
        You should never assume this method returns a specific IRSB.

        :param int addr: Address of the IRSB to get.
        :return:         An arbitrary IRSB located at `addr`.
        :rtype:          IRSB
        """
        raise DeprecationWarning('"get_any_irsb()" is deprecated since SimIRSB does not exist anymore.')

    def get_all_nodes(self, addr, is_syscall=None, anyaddr=False):
        """
        Get all CFGNodes whose address is the specified one.

        :param addr:       Address of the node
        :param is_syscall: True returns the syscall node, False returns the normal CFGNode, None returns both
        :return:           all CFGNodes
        """
        results = [ ]

        for cfg_node in self._graph.nodes():
            if cfg_node.addr == addr or (anyaddr and
                                         cfg_node.size is not None and
                                         cfg_node.addr <= addr < (cfg_node.addr + cfg_node.size)
                                         ):
                if is_syscall and cfg_node.is_syscall:
                    results.append(cfg_node)
                elif is_syscall is False and not cfg_node.is_syscall:
                    results.append(cfg_node)
                else:
                    results.append(cfg_node)

        return results

    def nodes(self):
        """
        An iterator of all nodes in the graph.

        :return: The iterator.
        :rtype: iterator
        """

        return self._graph.nodes()

    @deprecated(replacement='nodes')
    def nodes_iter(self):
        """
        (Decrepated) An iterator of all nodes in the graph. Will be removed in the future.

        :return: The iterator.
        :rtype: iterator
        """

        return self.nodes()

    def get_all_irsbs(self, addr):  # pylint:disable=unused-argument
        """
        Returns all IRSBs of a certain address, without considering contexts.
        """
        raise DeprecationWarning('"get_all_irsbs()" is deprecated since SimIRSB does not exist anymore.')

    def get_loop_back_edges(self):
        return self._loop_back_edges

    def get_branching_nodes(self):
        """
        Returns all nodes that has an out degree >= 2
        """
        nodes = set()
        for n in self._graph.nodes():
            if self._graph.out_degree(n) >= 2:
                nodes.add(n)
        return nodes

    def get_exit_stmt_idx(self, src_block, dst_block):
        """
        Get the corresponding exit statement ID for control flow to reach destination block from source block. The exit
        statement ID was put on the edge when creating the CFG.
        Note that there must be a direct edge between the two blocks, otherwise an exception will be raised.

        :return: The exit statement ID
        """

        if not self.graph.has_edge(src_block, dst_block):
            raise AngrCFGError('Edge (%s, %s) does not exist in CFG' % (src_block, dst_block))

        return self.graph[src_block][dst_block]['stmt_idx']

    @property
    def graph(self):
        return self._graph

    def remove_edge(self, block_from, block_to):
        edge = (block_from, block_to)

        if edge in self._graph:
            self._graph.remove_edge(*edge)

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
        else:
            addr = addr
            size = size
            thumb = thumb

        if addr is None:
            raise ValueError('_to_snippet(): Either cfg_node or addr must be provided.')

        if self.project.is_hooked(addr) and jumpkind != 'Ijk_NoHook':
            hooker = self.project._sim_procedures[addr]
            size = hooker.kwargs.get('length', 0)
            return HookNode(addr, size, type(hooker))

        if cfg_node is not None:
            return BlockNode(addr, size, thumb=thumb, bytestr=cfg_node.byte_string)  # pylint: disable=no-member
        else:
            return self.project.factory.snippet(addr, size=size, jumpkind=jumpkind, thumb=thumb,
                                                backup_state=base_state)

    def is_thumb_addr(self, addr):
        return addr in self._thumb_addrs

    def _arm_thumb_filter_jump_successors(self, addr, successors, get_ins_addr, get_exit_stmt_idx):
        """
        Filter successors for THUMB mode basic blocks, and remove those successors that won't be taken normally.

        :param int addr: Address of the basic block / SimIRSB.
        :param list successors: A list of successors.
        :param func get_ins_addr: A callable that returns the source instruction address for a successor.
        :param func get_exit_stmt_idx: A callable that returns the source statement ID for a successor.
        :return: A new list of successors after filtering.
        :rtype: list
        """

        if not successors:
            return [ ]

        it_counter = 0
        conc_temps = {}
        can_produce_exits = set()
        bb = self._lift(addr, thumb=True, opt_level=0)

        for stmt in bb.vex.statements:
            if stmt.tag == 'Ist_IMark':
                if it_counter > 0:
                    it_counter -= 1
                    can_produce_exits.add(stmt.addr + stmt.delta)
            elif stmt.tag == 'Ist_WrTmp':
                val = stmt.data
                if val.tag == 'Iex_Const':
                    conc_temps[stmt.tmp] = val.con.value
            elif stmt.tag == 'Ist_Put':
                if stmt.offset == self.project.arch.registers['itstate'][0]:
                    val = stmt.data
                    if val.tag == 'Iex_RdTmp':
                        if val.tmp in conc_temps:
                            # We found an IT instruction!!
                            # Determine how many instructions are conditional
                            it_counter = 0
                            itstate = conc_temps[val.tmp]
                            while itstate != 0:
                                it_counter += 1
                                itstate >>= 8

        if it_counter != 0:
            l.debug('Basic block ends before calculated IT block (%#x)', addr)

        THUMB_BRANCH_INSTRUCTIONS = ('beq', 'bne', 'bcs', 'bhs', 'bcc', 'blo', 'bmi', 'bpl', 'bvs',
                                     'bvc', 'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble', 'cbz', 'cbnz')
        for cs_insn in bb.capstone.insns:
            if cs_insn.mnemonic.split('.')[0] in THUMB_BRANCH_INSTRUCTIONS:
                can_produce_exits.add(cs_insn.address)

        successors_filtered = [suc for suc in successors
                               if get_ins_addr(suc) in can_produce_exits or get_exit_stmt_idx(suc) == 'default']

        return successors_filtered

    def _is_region_extremely_sparse(self, start, end, base_state=None):
        """
        Check whether the given memory region is extremely sparse, i.e., all bytes are the same value.

        :param int start: The beginning of the region.
        :param int end:   The end of the region.
        :param base_state: The base state (optional).
        :return:           True if the region is extremely sparse, False otherwise.
        :rtype:            bool
        """

        all_bytes = None

        if base_state is not None:
            all_bytes = base_state.memory.load(start, end - start + 1)
            try:
                all_bytes = base_state.solver.eval(all_bytes, cast_to=bytes)
            except SimError:
                all_bytes = None

        size = end - start + 1

        if all_bytes is None:
            # load from the binary
            all_bytes = self._fast_memory_load_bytes(start, size)

        if all_bytes is None:
            return True

        if len(all_bytes) < size:
            l.warning("_is_region_extremely_sparse: The given region %#x-%#x is not a continuous memory region in the "
                      "memory space. Only the first %d bytes (%#x-%#x) are processed.", start, end, len(all_bytes),
                      start, start + len(all_bytes) - 1)

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
            if section.name in {'.textbss'}:
                return True

        return False

    def _executable_memory_regions(self, binary=None, force_segment=False):
        """
        Get all executable memory regions from the binaries

        :param binary: Binary object to collect regions from. If None, regions from all project binary objects are used.
        :param bool force_segment: Rely on binary segments instead of sections.
        :return: A sorted list of tuples (beginning_address, end_address)
        """

        if binary is None:
            binaries = self.project.loader.all_objects
        else:
            binaries = [ binary ]

        memory_regions = [ ]

        for b in binaries:
            if isinstance(b, ELF):
                # If we have sections, we get result from sections
                if not force_segment and b.sections:
                    # Get all executable sections
                    for section in b.sections:
                        if section.is_executable:
                            tpl = (section.min_addr, section.max_addr)
                            memory_regions.append(tpl)

                else:
                    # Get all executable segments
                    for segment in b.segments:
                        if segment.is_executable:
                            tpl = (segment.min_addr, segment.max_addr)
                            memory_regions.append(tpl)

            elif isinstance(b, PE):
                for section in b.sections:
                    if section.is_executable:
                        tpl = (section.min_addr, section.max_addr)
                        memory_regions.append(tpl)

            elif isinstance(b, MachO):
                if b.segments:
                    # Get all executable segments
                    for seg in b.segments:
                        if seg.is_executable:
                            # Take all sections from this segment (MachO style)
                            for section in seg.sections:
                                tpl = (section.min_addr, section.max_addr)
                                memory_regions.append(tpl)

            elif isinstance(b, Blob):
                # a blob is entirely executable
                tpl = (b.min_addr, b.max_addr)
                memory_regions.append(tpl)

            elif isinstance(b, (ExternObject, KernelObject, TLSObject)):
                pass

            else:
                l.warning('Unsupported object format "%s". Treat it as an executable.', b.__class__.__name__)

                tpl = (b.min_addr, b.max_addr)
                memory_regions.append(tpl)

        if not memory_regions:
            memory_regions = [(start, start + len(backer)) for start, backer in self.project.loader.memory.backers()]

        memory_regions = sorted(memory_regions, key=lambda x: x[0])

        return memory_regions

    def _addr_in_exec_memory_regions(self, addr):
        """
        Test if the address belongs to an executable memory region.

        :param int addr: The address to test
        :return: True if the address belongs to an exectubale memory region, False otherwise
        :rtype: bool
        """

        for start, end in self._exec_mem_regions:
            if start <= addr < end:
                return True
        return False

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
            if obj_b is None:
                return True
            return False

        src_section = obj.find_section_containing(addr_a)
        if src_section is None:
            # test if addr_b also does not belong to any section
            dst_section = obj.find_section_containing(addr_b)
            if dst_section is None:
                return True
            return False

        return src_section.contains_addr(addr_b)

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

    def _fast_memory_load_pointer(self, addr):
        """
        Perform a fast memory loading of a pointer.

        :param int addr: Address to read from.
        :return:         A pointer or None if the address does not exist.
        :rtype:          int
        """

        try:
            return self.project.loader.memory.unpack_word(addr)
        except KeyError:
            return None

    #
    # Analyze function features
    #

    def _analyze_function_features(self):
        """
        For each function in the function_manager, try to determine if it returns or not. A function does not return if
        it calls another function that is known to be not returning, and this function does not have other exits.

        We might as well analyze other features of functions in the future.

        A function does not return if
        a) it is a SimProcedure that has NO_RET being True,
        or
        b) it is completely recovered (i.e. every block of this function has been recovered, and no future block will
           be added to it), and it does not have a ret or any equivalent instruction.

        A function returns if any of its block contains a ret instruction or any equivalence.
        """

        changes = {
            'functions_return': [],
            'functions_do_not_return': []
        }

        if self._updated_nonreturning_functions is not None:
            all_func_addrs = self._updated_nonreturning_functions
            caller_func_addrs = set()

            for func_addr in self._updated_nonreturning_functions:
                if func_addr not in self.kb.functions.callgraph:
                    continue
                callers = self.kb.functions.callgraph.predecessors(func_addr)
                for f in callers:
                    caller_func_addrs.add(f)

            # Add callers
            all_func_addrs |= caller_func_addrs
            # Convert addresses to objects
            all_functions = [ self.kb.functions.get_by_addr(f) for f in all_func_addrs
                              if self.kb.functions.contains_addr(f) ]

        else:
            all_functions = self.kb.functions.values()

        # pylint: disable=too-many-nested-blocks
        for func in all_functions:  # type: angr.knowledge.Function

            if func.returning is not None:
                # It has been determined before. Skip it
                continue

            # If there is at least one return site, then this function is definitely returning
            if func.has_return:
                changes['functions_return'].append(func)
                func.returning = True
                self._add_returning_function(func.addr)
                continue

            # This function does not have endpoints. It's either because it does not return, or we haven't analyzed all
            # blocks of it.

            if not func.block_addrs_set:
                # the function is empty. skip
                continue

            # Let's first see if it's a known SimProcedure that does not return
            if self.project.is_hooked(func.addr):
                procedure = self.project.hooked_by(func.addr)
            else:
                try:
                    procedure = self.project.simos.syscall_from_addr(func.addr, allow_unsupported=False)
                except AngrUnsupportedSyscallError:
                    procedure = None

            if procedure is not None and hasattr(procedure, 'NO_RET'):
                if procedure.NO_RET:
                    func.returning = False
                    changes['functions_do_not_return'].append(func)
                else:
                    func.returning = True
                    self._add_returning_function(func.addr)
                    changes['functions_return'].append(func)
                continue

            # did we finish analyzing this function?
            if func.addr not in self._completed_functions:
                continue

            if not func.block_addrs_set:
                # there is no block inside this function
                # it might happen if the function has been incorrectly identified as part of another function
                # the error will be corrected during post-processing. In fact at this moment we cannot say anything
                # about whether this function returns or not. We always assume it returns.
                func.returning = True
                self._add_returning_function(func.addr)
                changes['functions_return'].append(func)
                continue

            bail_out = False

            # if this function has jump-out sites or ret-out sites, it returns as long as any of the target function
            # returns
            for goout_site, type_ in [ (site, 'jumpout') for site in func.jumpout_sites ] + \
                    [ (site, 'retout') for site in func.retout_sites ]:

                if func.returning:
                    # if there are multiple jump out sites and we have determined the "returning status" from one of
                    # the jump out sites, we can exit the loop early
                    break

                # determine where it jumps/returns to
                goout_site_successors = goout_site.successors()
                if not goout_site_successors:
                    # not sure where it jumps to. bail out
                    bail_out = True
                    continue

                # for retout sites, determine what function it calls
                if type_ == 'retout':
                    # see whether the function being called returns or not
                    func_successors = [ succ for succ in goout_site_successors if isinstance(succ, Function) ]
                    if func_successors and all(func_successor.returning in (None, False)
                                               for func_successor in func_successors):
                        # the returning of all possible function calls are undermined, or they do not return
                        # ignore this site
                        continue

                if type_ == 'retout':
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
                    func.returning = True
                    self._add_returning_function(func.addr)
                    changes['functions_return'].append(func)
                    bail_out = True
                elif target_func.returning is None:
                    # the returning status of at least one of the target functions is not decided yet.
                    bail_out = True

            if bail_out:
                # bail out
                continue

            # well this function does not return then
            func.returning = False
            changes['functions_do_not_return'].append(func)

        return changes

    def _iteratively_analyze_function_features(self):
        """
        Iteratively analyze function features until a fixed point is reached.

        :return: the "changes" dict
        :rtype:  dict
        """

        changes = {
            'functions_do_not_return': set(),
            'functions_return': set()
        }

        while True:
            new_changes = self._analyze_function_features()

            changes['functions_do_not_return'] |= set(new_changes['functions_do_not_return'])
            changes['functions_return'] |= set(new_changes['functions_return'])

            if not new_changes['functions_do_not_return'] and not new_changes['functions_return']:
                # a fixed point is reached
                break

        return changes

    def _real_address(self, arch, addr):
        """
        Obtain the real address of an instruction. ARM architectures are supported.

        :param Arch arch:   The Arch object.
        :param int addr:    The instruction address.
        :return:            The real address of an instruction.
        :rtype:             int
        """

        return ((addr >> 1) << 1) if arch.name in ('ARMEL', 'ARMHF') else addr

    def normalize(self):
        """
        Normalize the CFG, making sure that there are no overlapping basic blocks.

        Note that this method will not alter transition graphs of each function in self.kb.functions. You may call
        normalize() on each Function object to normalize their transition graphs.

        :return: None
        """

        graph = self.graph

        smallest_nodes = { }  # indexed by end address of the node
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
            smallest_node = all_nodes[0] # take the one that has the highest address
            other_nodes = all_nodes[1:]

            self._normalize_core(graph, callstack_key, smallest_node, other_nodes, smallest_nodes,
                                 end_addresses_to_nodes
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
                for k in sorted_smallest_nodes.keys():
                    sorted_smallest_nodes[k] = sorted(sorted_smallest_nodes[k], key=lambda node: node.addr)

                for callstack_key, lst in sorted_smallest_nodes.items():
                    lst_len = len(lst)
                    for i, node in enumerate(lst):
                        if i == lst_len - 1:
                            break
                        next_node = lst[i + 1]
                        if node.addr <= next_node.addr < node.addr + node.size:
                            # umm, those nodes are overlapping, but they must have different end addresses
                            nodekey_a = node.addr + node.size, callstack_key
                            nodekey_b = next_node.addr + next_node.size, callstack_key

                            if nodekey_a in smallest_nodes and nodekey_b in smallest_nodes:
                                # misuse end_addresses_to_nodes
                                end_addresses_to_nodes[(node.addr + node.size, callstack_key)].add(node)
                                end_addresses_to_nodes[(node.addr + node.size, callstack_key)].add(next_node)

                            smallest_nodes.pop(nodekey_a, None)
                            smallest_nodes.pop(nodekey_b, None)

        self._normalized = True

    def _normalize_core(self, graph, callstack_key, smallest_node, other_nodes, smallest_nodes, end_addresses_to_nodes):

        # Break other nodes
        for n in other_nodes:
            new_size = smallest_node.addr - n.addr
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
            if new_node is None:
                if key in smallest_nodes and smallest_nodes[key].addr == n.addr:
                    new_node = smallest_nodes[key]

            if new_node is None:
                # Create a new one
                if self.tag == "CFGFast":
                    new_node = CFGNode(n.addr, new_size, self,
                                       function_address=n.function_address, block_id=n.block_id,
                                       instruction_addrs=tuple([i for i in n.instruction_addrs
                                                          if n.addr <= i <= n.addr + new_size
                                                          ]),
                                       thumb=n.thumb
                                       )
                elif self.tag == "CFGEmulated":
                    new_node = CFGNodeA(n.addr, new_size, self, callstack_key=callstack_key,
                                        function_address=n.function_address, block_id=n.block_id,
                                        instruction_addrs=tuple([i for i in n.instruction_addrs
                                                           if n.addr <= i <= n.addr + new_size
                                                           ]),
                                        thumb=n.thumb
                                        )
                else:
                    raise ValueError("Unknown tag %s." % self.tag)

                # Copy instruction addresses
                new_node.instruction_addrs = [ins_addr for ins_addr in n.instruction_addrs
                                              if ins_addr < n.addr + new_size]
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

            for _, d, data in original_successors:
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
            self._nodes[n.block_id] = new_node
            if n in self._nodes_by_addr[n.addr]:
                self._nodes_by_addr[n.addr] = [node for node in self._nodes_by_addr[n.addr] if node is not n]
                self._nodes_by_addr[n.addr].append(new_node)

            for p, _, data in original_predecessors:
                # Consider the following case: two basic blocks ending at the same position, where A is larger, and
                # B is smaller. Suppose there is an edge going from the end of A to A itself, and apparently there
                # is another edge from B to A as well. After splitting A into A' and B, we DO NOT want to add A back
                # in, otherwise there will be an edge from A to A`, while A should totally be got rid of in the new
                # graph.
                if p not in other_nodes:
                    graph.add_edge(p, new_node, **data)

            # We should find the correct successor
            new_successors = [i for i in [smallest_node] + other_nodes
                              if i.addr == smallest_node.addr]
            if new_successors:
                new_successor = new_successors[0]
                graph.add_edge(new_node, new_successor, jumpkind='Ijk_Boring')
            else:
                # We gotta create a new one
                l.error('normalize(): Please report it to Fish.')

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

        self._jobs_to_analyze_per_function[func_addr].remove(job)

    def _get_finished_functions(self):
        """
        Obtain all functions of which we have finished analyzing. As _jobs_to_analyze_per_function is a defaultdict(),
        if a function address shows up in it with an empty job list, we consider we have exhausted all jobs of this
        function (both current jobs and pending jobs), thus the analysis of this function is done.

        :return: a list of function addresses of that we have finished analysis.
        :rtype:  list
        """

        finished_func_addrs = [ ]
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
            self._completed_functions.add(func_addr)
        self._cleanup_analysis_jobs(finished_func_addrs=finished)

    #
    # Function identification and such
    #

    def _add_returning_function(self, func_addr):
        pass

    def remove_function_alignments(self):
        """
        Remove all function alignments.

        :return: None
        """

        # This function requires Capstone engine support
        if not self.project.arch.capstone_support:
            return

        for func_addr in self.kb.functions.keys():
            function = self.kb.functions[func_addr]
            if function.is_simprocedure or function.is_syscall:
                continue
            if len(function.block_addrs_set) == 1:
                block = next((b for b in function.blocks), None)
                if block is None:
                    continue
                if all(self._is_noop_insn(insn) for insn in block.capstone.insns):
                    # remove this function
                    l.debug('Function chunk %#x is used as function alignments. Removing it.', func_addr)
                    del self.kb.functions[func_addr]

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

        # Clear old functions dict
        self.kb.functions.clear()

        blockaddr_to_function = { }
        traversed_cfg_nodes = set()

        function_nodes = set()

        # Find nodes for beginnings of all functions
        for _, dst, data in self.graph.edges(data=True):
            jumpkind = data.get('jumpkind', "")
            if jumpkind == 'Ijk_Call' or jumpkind.startswith('Ijk_Sys'):
                function_nodes.add(dst)

        entry_node = self.get_any_node(self._binary.entry)
        if entry_node is not None:
            function_nodes.add(entry_node)

        # aggressively remove and merge functions
        # For any function, if there is a call to it, it won't be removed
        called_function_addrs = set([n.addr for n in function_nodes])

        removed_functions_a = self._process_irrational_functions(tmp_functions,
                                                                 called_function_addrs,
                                                                 blockaddr_to_function
                                                                 )
        removed_functions_b = self._process_irrational_function_starts(tmp_functions,
                                                                       called_function_addrs,
                                                                       blockaddr_to_function
                                                                       )
        removed_functions = removed_functions_a | removed_functions_b

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

            if self._show_progressbar or self._progress_callback:
                progress = min_stage_2_progress + (max_stage_2_progress - min_stage_2_progress) * (i * 1.0 / nodes_count)
                self._update_progress(progress)

            self._graph_bfs_custom(self.graph, [ fn ], self._graph_traversal_handler, blockaddr_to_function,
                                   tmp_functions, traversed_cfg_nodes
                                   )

        # Don't forget those small function chunks that are not called by anything.
        # There might be references to them from data, or simply references that we cannot find via static analysis

        secondary_function_nodes = set()
        # add all function chunks ("functions" that are not called from anywhere)
        for func_addr in tmp_functions:
            node = self.get_any_node(func_addr)
            if node is None:
                continue
            if node.addr not in blockaddr_to_function:
                secondary_function_nodes.add(node)

        missing_cfg_nodes = set(self.graph.nodes()) - traversed_cfg_nodes
        missing_cfg_nodes = { node for node in missing_cfg_nodes if node.function_address is not None }
        if missing_cfg_nodes:
            l.debug('%d CFGNodes are missing in the first traversal.', len(missing_cfg_nodes))
            secondary_function_nodes |=  missing_cfg_nodes

        min_stage_3_progress = 90.0
        max_stage_3_progress = 99.9

        nodes_count = len(secondary_function_nodes)
        for i, fn in enumerate(sorted(secondary_function_nodes, key=lambda n: n.addr)):

            if self._show_progressbar or self._progress_callback:
                progress = min_stage_3_progress + (max_stage_3_progress - min_stage_3_progress) * (i * 1.0 / nodes_count)
                self._update_progress(progress)

            self._graph_bfs_custom(self.graph, [fn], self._graph_traversal_handler, blockaddr_to_function,
                                   tmp_functions
                                   )

        to_remove = set()

        # Remove all stubs after PLT entries
        if self.project.arch.name not in {'ARMEL', 'ARMHF'}:
            for fn in self.kb.functions.values():
                addr = fn.addr - (fn.addr % 16)
                if addr != fn.addr and addr in self.kb.functions and self.kb.functions[addr].is_plt:
                    to_remove.add(fn.addr)

        # remove empty functions
        for function in self.kb.functions.values():
            if function.startpoint is None:
                to_remove.add(function.addr)

        for addr in to_remove:
            del self.kb.functions[addr]

        # Update CFGNode.function_address
        for node in self._nodes.values():
            if node.addr in blockaddr_to_function:
                node.function_address = blockaddr_to_function[node.addr].addr

    def _process_irrational_functions(self, functions, predetermined_function_addrs, blockaddr_to_function):
        """
        For unresolveable indirect jumps, angr marks those jump targets as individual functions. For example, usually
        the following pattern is seen:

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

        functions_to_remove = { }

        functions_can_be_removed = set(functions.keys()) - set(predetermined_function_addrs)

        for func_addr, function in functions.items():

            if func_addr in functions_to_remove:
                continue

            # check all blocks and see if any block ends with an indirect jump and is not resolved
            has_unresolved_jumps = False
            # the functions to merge with must be locating between the unresolved basic block address and the endpoint
            # of the current function
            max_unresolved_jump_addr = 0
            for block_addr in function.block_addrs_set:
                if block_addr in self.indirect_jumps and \
                        self.indirect_jumps[block_addr].jumpkind == 'Ijk_Boring' and \
                        not self.indirect_jumps[block_addr].resolved_targets:
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
            endpoint_addr = max([ a.addr for a in function.endpoints ])
            the_endpoint = next(a for a in function.endpoints if a.addr == endpoint_addr)
            endpoint_addr += the_endpoint.size

            # sanity check: startpoint of the function should be greater than its endpoint
            if startpoint_addr >= endpoint_addr:
                continue
            if max_unresolved_jump_addr <= startpoint_addr or max_unresolved_jump_addr >= endpoint_addr:
                continue

            # scan forward from the endpoint to include any function tail jumps
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
            tmp_state = self.project.factory.blank_state(mode='fastpath')
            while True:
                try:
                    # using successors is slow, but acceptable since we won't be creating millions of blocks here...
                    tmp_state.ip = last_addr
                    b = self.project.factory.successors(tmp_state, jumpkind='Ijk_Boring')
                    if len(b.successors) != 1:
                        break
                    if b.successors[0].history.jumpkind not in ('Ijk_Boring', 'Ijk_InvalICache'):
                        break
                    if b.successors[0].ip.symbolic:
                        break
                    suc_addr = b.successors[0].ip._model_concrete
                    if max(startpoint_addr, the_endpoint.addr - 0x40) <= suc_addr < the_endpoint.addr + the_endpoint.size:
                        # increment the endpoint_addr
                        endpoint_addr = b.addr + b.artifacts['irsb_size']
                    else:
                        break

                    last_addr = b.addr + b.artifacts['irsb_size']

                except (SimTranslationError, SimMemoryError, SimIRSBError, SimEngineError):
                    break

            # find all functions that are between [ startpoint, endpoint ]

            should_merge = True
            functions_to_merge = set()
            for f_addr in functions_can_be_removed:
                f = functions[f_addr]
                if f_addr == func_addr:
                    continue
                if max_unresolved_jump_addr < f_addr < endpoint_addr and \
                        all([max_unresolved_jump_addr < b_addr < endpoint_addr for b_addr in f.block_addrs]):
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

        addrs = sorted(functions.keys())
        functions_to_remove = set()

        for addr_0, addr_1 in zip(addrs[:-1], addrs[1:]):

            if addr_1 in predetermined_function_addrs:
                continue
            if self.project.is_hooked(addr_0) or self.project.is_hooked(addr_1):
                continue

            func_0 = functions[addr_0]

            if len(func_0.block_addrs) == 1:
                block = next(func_0.blocks)
                if block.vex.jumpkind not in ('Ijk_Boring', 'Ijk_InvalICache'):
                    continue
                # Skip alignment blocks
                if self._is_noop_block(self.project.arch, block):
                    continue

                target = block.vex.next
                if type(target) is pyvex.IRExpr.Const:  # pylint: disable=unidiomatic-typecheck
                    target_addr = target.con.value
                elif type(target) in (pyvex.IRConst.U32, pyvex.IRConst.U64):  # pylint: disable=unidiomatic-typecheck
                    target_addr = target.value
                elif type(target) is int:  # pylint: disable=unidiomatic-typecheck
                    target_addr = target
                else:
                    continue

                if target_addr != addr_1:
                    continue

                l.debug("Merging function %#x into %#x.", addr_1, addr_0)

                # Merge it
                func_1 = functions[addr_1]
                for block_addr in func_1.block_addrs:
                    merge_with = self._addr_to_function(addr_0, blockaddr_to_function, functions)
                    blockaddr_to_function[block_addr] = merge_with

                functions_to_remove.add(addr_1)

        for to_remove in functions_to_remove:
            del functions[to_remove]

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

            n = self.get_any_node(addr, is_syscall=is_syscall)
            if n is None: node = addr
            else: node = self._to_snippet(n)

            self.kb.functions._add_node(addr, node, syscall=is_syscall)
            f = self.kb.functions.function(addr=addr)

            blockaddr_to_function[addr] = f

            function_is_returning = False
            if addr in known_functions:
                if known_functions.function(addr).returning:
                    f.returning = True
                    function_is_returning = True

            if not function_is_returning:
                # We will rerun function feature analysis on this function later. Add it to
                # self._updated_nonreturning_functions so it can be picked up by function feature analysis later.
                if self._updated_nonreturning_functions is not None:
                    self._updated_nonreturning_functions.add(addr)

        return f

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
            n = stack.pop(last=False)  # type: CFGNode

            if n in traversed:
                continue

            traversed.add(n)

            if n.has_return:
                callback(n, None, {'jumpkind': 'Ijk_Ret'}, blockaddr_to_function, known_functions, None)
            # NOTE: A block that has_return CAN have successors that aren't the return.
            # This is particularly the case for ARM conditional instructions.  Yes, conditional rets are a thing.

            if g.out_degree(n) == 0:
                # it's a single node
                callback(n, None, None, blockaddr_to_function, known_functions, None)

            else:
                all_out_edges = g.out_edges(n, data=True)
                for src, dst, data in all_out_edges:
                    callback(src, dst, data, blockaddr_to_function, known_functions, all_out_edges)

                    jumpkind = data.get('jumpkind', "")
                    if not (jumpkind == 'Ijk_Call' or jumpkind.startswith('Ijk_Sys')):
                        # Only follow none call edges
                        if dst not in stack and dst not in traversed:
                            stack.add(dst)

    def _graph_traversal_handler(self, src, dst, data, blockaddr_to_function, known_functions, all_edges):
        """
        Graph traversal handler. It takes in a node or an edge, and create new functions or add nodes to existing
        functions accordingly. Oh, it also create edges on the transition map of functions.

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
            n = self.get_any_node(src_addr)
            if n is None: node = src_addr
            else: node = self._to_snippet(n)
            self.kb.functions._add_node(src_function.addr, node)

        if data is None:
            # it's a single node only
            return

        jumpkind = data['jumpkind']

        if jumpkind == 'Ijk_Ret':
            n = self.get_any_node(src_addr)
            if n is None: from_node = src_addr
            else: from_node = self._to_snippet(n)
            self.kb.functions._add_return_from(src_function.addr, from_node, None)

        if dst is None:
            return

        dst_addr = dst.addr

        # get instruction address and statement index
        ins_addr = data.get('ins_addr', None)
        stmt_idx = data.get('stmt_idx', None)

        if jumpkind == 'Ijk_Call' or jumpkind.startswith('Ijk_Sys'):

            is_syscall = jumpkind.startswith('Ijk_Sys')

            # It must be calling a function
            dst_function = self._addr_to_function(dst_addr, blockaddr_to_function, known_functions)

            n = self.get_any_node(src_addr)
            if n is None: src_snippet = self._to_snippet(addr=src_addr, base_state=self._base_state)
            else:
                src_snippet = self._to_snippet(cfg_node=n)

            # HACK: FIXME: We need a better way of representing unresolved calls and whether they return.
            # For now, assume UnresolvedTarget returns if we're calling to it

            # If the function doesn't return, don't add a fakeret!
            if not all_edges or (dst_function.returning is False and not dst_function.name == b'UnresolvableTarget'):
                fakeret_node = None
            else:
                fakeret_node = self._one_fakeret_node(all_edges)

            if fakeret_node is None:
                fakeret_snippet = None
            else:
                fakeret_snippet = self._to_snippet(cfg_node=fakeret_node)

            self.kb.functions._add_call_to(src_function.addr, src_snippet, dst_addr, fakeret_snippet, syscall=is_syscall,
                                           ins_addr=ins_addr, stmt_idx=stmt_idx)

            if dst_function.returning:
                returning_target = src.addr + src.size
                if returning_target not in blockaddr_to_function:
                    if returning_target not in known_functions:
                        blockaddr_to_function[returning_target] = src_function
                    else:
                        self._addr_to_function(returning_target, blockaddr_to_function, known_functions)

                to_outside = not blockaddr_to_function[returning_target] is src_function

                n = self.get_any_node(returning_target)
                if n is None:
                    returning_snippet = self._to_snippet(addr=returning_target, base_state=self._base_state)
                else:
                    returning_snippet = self._to_snippet(cfg_node=n)

                self.kb.functions._add_fakeret_to(src_function.addr, src_snippet, returning_snippet, confirmed=True,
                                                  to_outside=to_outside
                                                  )

        elif jumpkind in ('Ijk_Boring', 'Ijk_InvalICache'):

            # convert src_addr and dst_addr to CodeNodes
            n = self.get_any_node(src_addr)
            if n is None: src_node = src_addr
            else: src_node = self._to_snippet(cfg_node=n)

            n = self.get_any_node(dst_addr)
            if n is None: dst_node = dst_addr
            else: dst_node = self._to_snippet(cfg_node=n)

            # pre-check: if source and destination do not belong to the same section, it must be jumping to another
            # function
            if not self._addrs_belong_to_same_section(src_addr, dst_addr):
                _ = self._addr_to_function(dst_addr, blockaddr_to_function, known_functions)

            # is it a jump to another function?
            if dst_addr in known_functions or (
                dst_addr in blockaddr_to_function and blockaddr_to_function[dst_addr] is not src_function
            ):
                # yes it is
                dst_function_addr = blockaddr_to_function[dst_addr].addr if dst_addr in blockaddr_to_function else \
                    dst_addr

                self.kb.functions._add_outside_transition_to(src_function.addr, src_node, dst_node,
                                                             to_function_addr=dst_function_addr
                                                             )

                _ = self._addr_to_function(dst_addr, blockaddr_to_function, known_functions)
            else:
                # no it's not
                # add the transition code

                if dst_addr not in blockaddr_to_function:
                    blockaddr_to_function[dst_addr] = src_function

                self.kb.functions._add_transition_to(src_function.addr, src_node, dst_node, ins_addr=ins_addr,
                                                     stmt_idx=stmt_idx
                                                     )

        elif jumpkind == 'Ijk_FakeRet':

            # convert src_addr and dst_addr to CodeNodes
            n = self.get_any_node(src_addr)
            if n is None:
                src_node = src_addr
            else:
                src_node = self._to_snippet(n)

            n = self.get_any_node(dst_addr)
            if n is None:
                dst_node = dst_addr
            else:
                dst_node = self._to_snippet(n)


            if dst_addr not in blockaddr_to_function:
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
            # Try to find the call that this fakeret goes with
            for _, d, e in all_edges:
                if e['jumpkind'] == 'Ijk_Call':
                    if d.addr in blockaddr_to_function:
                        called_function = blockaddr_to_function[d.addr]
                        break
            # We may have since figured out that the called function doesn't ret.
            # It's important to assume that all unresolved targets do return
            # FIXME: Remove the last check after we split UnresolvableTarget into UnresolvableJump and UnresolvableCall.
            if called_function is not None and \
                    called_function.returning is False and \
                    (not called_function.is_simprocedure or called_function.name not in ('UnresolvableTarget',)):
                return

            to_outside = not target_function is src_function

            # FIXME: Not sure we should confirm this fakeret or not.
            self.kb.functions._add_fakeret_to(src_function.addr, src_node, dst_node, confirmed=True,
                                              to_outside=to_outside, to_function_addr=target_function.addr
                                              )

        else:
            l.debug('Ignored jumpkind %s', jumpkind)

    #
    # Other functions
    #

    @staticmethod
    def _is_noop_block(arch, block):
        """
        Check if the block is a no-op block by checking VEX statements.

        :param block: The VEX block instance.
        :return: True if the entire block is a single-byte or multi-byte nop instruction, False otherwise.
        :rtype: bool
        """

        if arch.name == "MIPS32":
            if arch.memory_endness == "Iend_BE":
                MIPS32_BE_NOOPS = {
                    b"\x00\x20\x08\x25",  # move $at, $at
                }
                insns = set(block.bytes[i:i+4] for i in range(0, block.size, 4))
                if MIPS32_BE_NOOPS.issuperset(insns):
                    return True

        # Fallback
        # the block is a noop block if it only has IMark statements

        if all((type(stmt) is pyvex.IRStmt.IMark) for stmt in block.vex.statements):
            return True
        return False


    @staticmethod
    def _is_noop_insn(insn):
        """
        Check if the instruction does nothing.

        :param insn: The capstone insn object.
        :return: True if the instruction does no-op, False otherwise.
        """

        if insn.insn_name() == 'nop':
            # nops
            return True
        if insn.insn_name() == 'lea':
            # lea reg, [reg + 0]
            op0, op1 = insn.operands
            if op0.type == 1 and op1.type == 3:
                # reg and mem
                if op0.reg == op1.mem.base and op1.mem.index == 0 and op1.mem.disp == 0:
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
            if data.get('jumpkind', None) == 'Ijk_FakeRet':
                return dst
        return None

    def _lift(self, *args, **kwargs):
        """
        Lift a basic block of code. Will use the base state as a source of bytes if possible.
        """
        if 'backup_state' not in kwargs:
            kwargs['backup_state'] = self._base_state
        return self.project.factory.block(*args, **kwargs)

    #
    # Indirect jumps processing
    #
    def _resolve_indirect_jump_timelessly(self, addr, block, func_addr, jumpkind):
        """
        Checks if MIPS32 and calls MIPS32 check, otherwise false

        :param int addr: irsb address
        :param pyvex.IRSB block: irsb
        :param int func_addr: Function address
        :return: If it was resolved and targets alongside it
        :rtype: tuple
        """

        if block.statements is None:
            block = self.project.factory.block(block.addr, size=block.size).vex

        for res in self.timeless_indirect_jump_resolvers:
            if res.filter(self, addr, func_addr, block, jumpkind):
                r, resolved_targets = res.resolve(self, addr, func_addr, block, jumpkind)
                if r:
                    return True, resolved_targets
        return False, [ ]

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
        l.debug('The indirect jump at %#x is successfully resolved by %s. It has %d targets.', addr, resolved_by, len(targets))
        self.kb.resolved_indirect_jumps.add(addr)

    def _indirect_jump_unresolved(self, jump):
        """
        Called when we cannot resolve an indirect jump.

        :param IndirectJump jump: The unresolved indirect jump.

        :return: None
        """

        l.debug('Failed to resolve the indirect jump at %#x.', jump.addr)
        # tell KnowledgeBase that it's not resolved
        # TODO: self.kb._unresolved_indirect_jumps is not processed during normalization. Fix it.
        self.kb.unresolved_indirect_jumps.add(jump.addr)

    def _indirect_jump_encountered(self, addr, cfg_node, irsb, func_addr, stmt_idx='default'):
        """
        Called when we encounter an indirect jump. We will try to resolve this indirect jump using timeless (fast)
        indirect jump resolvers. If it cannot be resolved, we will see if this indirect jump has been resolved before.

        :param int addr:                Address of the block containing the indirect jump.
        :param cfg_node:                The CFGNode instance of the block that contains the indirect jump.
        :param pyvex.IRSB irsb:         The IRSB instance of the block that contains the indirect jump.
        :param int func_addr:           Address of the current function.
        :param int or str stmt_idx:     ID of the source statement.

        :return:    A 3-tuple of (whether it is resolved or not, all resolved targets, an IndirectJump object
                    if there is one or None otherwise)
        :rtype:     tuple
        """

        jumpkind = irsb.jumpkind
        l.debug('(%s) IRSB %#x has an indirect jump as its default exit.', jumpkind, addr)

        # try resolving it fast
        resolved, resolved_targets = self._resolve_indirect_jump_timelessly(addr, irsb, func_addr, jumpkind)
        if resolved:
            return True, resolved_targets, None

        # Add it to our set. Will process it later if user allows.
        # Create an IndirectJump instance
        if addr not in self.indirect_jumps:
            if self.project.arch.branch_delay_slot:
                ins_addr = cfg_node.instruction_addrs[-2]
            else:
                ins_addr = cfg_node.instruction_addrs[-1]
            ij = IndirectJump(addr, ins_addr, func_addr, jumpkind, stmt_idx, resolved_targets=[])
            self.indirect_jumps[addr] = ij
            resolved = False
        else:
            ij = self.indirect_jumps[addr]  # type: IndirectJump
            resolved = len(ij.resolved_targets) > 0

        return resolved, ij.resolved_targets, ij

    def _process_unresolved_indirect_jumps(self):
        """
        Resolve all unresolved indirect jumps found in previous scanning.

        Currently we support resolving the following types of indirect jumps:
        - Ijk_Call (disabled now): indirect calls where the function address is passed in from a proceeding basic block
        - Ijk_Boring: jump tables
        - For an up-to-date list, see analyses/cfg/indirect_jump_resolvers

        :return:    A set of concrete indirect jump targets (ints).
        :rtype:     set
        """

        l.info("%d indirect jumps to resolve.", len(self._indirect_jumps_to_resolve))

        all_targets = set()
        for jump in self._indirect_jumps_to_resolve:  # type: IndirectJump
            all_targets |= self._process_one_indirect_jump(jump)

        self._indirect_jumps_to_resolve.clear()

        return all_targets

    def _process_one_indirect_jump(self, jump):
        """
        Resolve a given indirect jump.

        :param IndirectJump jump:  The IndirectJump instance.
        :return:        A set of resolved indirect jump targets (ints).
        """

        resolved = False
        resolved_by = None
        targets = None

        block = self._lift(jump.addr, opt_level=1)

        for resolver in self.indirect_jump_resolvers:
            resolver.base_state = self._base_state

            if not resolver.filter(self, jump.addr, jump.func_addr, block, jump.jumpkind):
                continue

            resolved, targets = resolver.resolve(self, jump.addr, jump.func_addr, block, jump.jumpkind)
            if resolved:
                resolved_by = resolver
                break

        if resolved:
            self._indirect_jump_resolved(jump, jump.addr, resolved_by, targets)
        else:
            self._indirect_jump_unresolved(jump)

        return set() if targets is None else set(targets)
