# pylint:disable=super-init-not-called
from __future__ import annotations

import contextlib
import itertools
import os
from collections import defaultdict
from collections.abc import Iterable

import networkx

from angr.codenode import BlockNode, CodeNode, FuncNode, HookNode
from angr.errors import AngrValueError, SimEngineError, SimMemoryError

from .function import Function, FunctionInfo, dirty_func


class SootFunction(Function):
    """
    A representation of a Soot function. Soot addresses are SootMethodDescriptors, which the Rust-backed
    FunctionGraph cannot hold, so this class keeps the transition graph and its block maps in networkx and Python
    dicts. The graph methods below are the pre-FunctionGraph implementations of the same methods on Function.

    Unlike Function, its transition_graph and graph are plain mutable networkx graphs: normalize(), copy() and the
    graph methods below edit them in place, and pysoot is not available to exercise a read-only rewrite of them.
    """

    __slots__ = (
        "_addr_to_block_node",
        "_block_sizes",
        "_call_sites",
        "_callout_sites",
        "_endpoints",
        "_jumpout_sites",
        "_local_block_addrs",
        "_local_blocks",
        "_ret_sites",
        "_retout_sites",
        "startpoint",
        "transition_graph",
    )

    def __init__(self, function_manager, addr, name=None, syscall=None):
        """
        Function constructor for Soot

        :param addr:            The address of the function.
        :param name:            (Optional) The name of the function.
        :param syscall:         (Optional) Whether this function is a syscall or not.
        """
        self.transition_graph = networkx.DiGraph()
        self._local_transition_graph = None
        # The Shimple CFG is already normalized.
        self.normalized = True

        # block nodes at whose ends the function returns
        self._ret_sites = set()
        # block nodes at whose ends the function jumps out to another function (jumps outside)
        self._jumpout_sites = set()
        # block nodes at whose ends the function calls out to another non-returning function
        self._callout_sites = set()
        # block nodes that ends the function by returning out to another function (returns outside). This is rare.
        self._retout_sites = set()
        # block nodes (basic block nodes) at whose ends the function terminates
        # in theory, if everything works fine, endpoints == ret_sites | jumpout_sites | callout_sites
        self._endpoints = defaultdict(set)
        self.previous_names = []

        self._call_sites = {}
        self.addr = addr
        self._function_manager = function_manager
        self._is_syscall = syscall
        self._from_signature = None

        self._project = project = self._function_manager._kb._project

        self._is_plt = False
        self._is_simprocedure = False

        if project.is_hooked(addr):
            self._is_simprocedure = True

        binary_name = None
        if self._is_simprocedure:
            hooker = project.hooked_by(addr)
            if hooker is not None:
                binary_name = hooker.library_name

        if binary_name is None and self.binary is not None:
            binary_name = os.path.basename(self.binary.binary)

        self._name = addr.__repr__()
        self.binary_name = binary_name

        # Stack offsets of those arguments passed in stack variables
        self._argument_stack_variables = []

        # These properties are set by VariableManager
        self.bp_on_stack = False
        self.retaddr_on_stack = False

        self.sp_delta = 0

        # Calling convention
        self._calling_convention = None

        # Function prototype
        self._prototype = None

        # Whether this function returns or not. `None` means it's not determined yet
        self._returning = None

        self._is_alignment = None

        # Determine returning status for SimProcedures and Syscalls
        hooker = None
        if self.is_simprocedure:
            hooker = project.hooked_by(addr)
        if hooker and hasattr(hooker, "NO_RET"):
            self.returning = not hooker.NO_RET

        # startpoint can always be None if this CFGNode is a syscall node
        self.startpoint = None

        self._addr_to_block_node = {}  # map addresses to nodes
        self._block_sizes = {}  # map addresses to block sizes
        self._local_blocks = {}  # a dict of all blocks inside the function
        self._local_block_addrs = set()  # a set of addresses of all blocks inside the function

        self._info = FunctionInfo(self)
        self._dirty = False
        self.tags = ()  # store function tags. can be set manually by performing CodeTagging analysis.

    def normalize(self):
        # The Shimple CFG is already normalized.
        pass

    def _register_node(self, is_local: bool, node, update_func_block_count: bool = True):  # pylint:disable=unused-argument
        if is_local and self._local_blocks.get(node.addr) == node:
            return self._local_blocks[node.addr]

        if node not in self.transition_graph:
            self.transition_graph.add_node(node)
        node.set_owner(self)
        if node.addr not in self or self._block_sizes[node.addr] == 0:
            self._block_sizes[node.addr] = node.size
        if node.addr == self.addr.addr and (self.startpoint is None or not self.startpoint.is_hook):
            self.startpoint = node
        if is_local:
            self._local_blocks[node.addr] = node
            self._local_block_addrs.add(node.addr)
        # add BlockNodes to the addr_to_block_node cache if not already there
        if isinstance(node, BlockNode) and node.addr not in self._addr_to_block_node:
            self._addr_to_block_node[node.addr] = node
        return node

    @property
    def blocks(self):
        """
        An iterator of all local blocks in the current function.

        :return: angr.lifter.Block instances.
        """

        for block_addr, block in self._local_blocks.items():
            with contextlib.suppress(SimEngineError, SimMemoryError):
                yield self.get_block(
                    block_addr, size=block.size, byte_string=block.bytestr if isinstance(block, BlockNode) else None
                )

    @property
    def code_nodes(self) -> dict[int, CodeNode]:
        return self._local_blocks

    @property
    def cyclomatic_complexity(self):
        """
        The cyclomatic complexity of the function.

        Cyclomatic complexity is a software metric used to indicate the complexity of a program.
        It is a quantitative measure of the number of linearly independent paths through a program's source code.
        It is computed using the formula: M = E - N + 2P, where
        E = the number of edges in the graph,
        N = the number of nodes in the graph,
        P = the number of connected components.

        The cyclomatic complexity value is lazily computed and cached for future use.
        Initially this value is None until it is computed for the first time

        :return: The cyclomatic complexity of the function.
        :rtype: int
        """
        if self._cyclomatic_complexity is None:
            self._cyclomatic_complexity = (
                self.transition_graph.number_of_edges() - self.transition_graph.number_of_nodes() + 2
            )
        return self._cyclomatic_complexity

    @property
    def block_addrs(self):
        """
        An iterator of all local block addresses in the current function.

        :return: block addresses.
        """

        return self._local_blocks.keys()

    @property
    def block_addrs_set(self):
        """
        Return a set of block addresses for a better performance of inclusion tests.

        :return: A set of block addresses.
        :rtype: set
        """

        return self._local_block_addrs

    def get_block(self, addr: int, size: int | None = None, byte_string: bytes | None = None):
        """
        Getting a block out of the current function.

        :param int addr:    The address of the block.
        :param int size:    The size of the block. This is optional. If not provided, angr will load
        :param byte_string:
        :return:
        """
        if size is None and addr in self.block_addrs:
            # we know the size
            size = self._block_sizes[addr]

        assert self.project is not None
        block = self.project.factory.block(addr, size=size, byte_string=byte_string)
        if size is None:
            # update block_size dict
            self._block_sizes[addr] = block.size
        return block

    def get_block_size(self, addr: int) -> int | None:
        return self._block_sizes.get(addr, None)

    @property
    def nodes(self) -> Iterable[CodeNode]:
        return self.transition_graph.nodes()

    def get_node(self, addr) -> BlockNode | None:
        return self._addr_to_block_node.get(addr, None)

    def __contains__(self, val):
        if isinstance(val, int):
            return val in self._block_sizes
        return False

    def __getstate__(self):
        # self._local_transition_graph is a cache. don't pickle it
        d = {
            k: getattr(self, k) for k in Function.__slots__ + self.__slots__ if k != "__weakref__" and hasattr(self, k)
        }
        d["_local_transition_graph"] = None
        d["_project"] = None
        d["_function_manager"] = None
        return d

    @property
    def endpoints(self):
        return list(itertools.chain(*self._endpoints.values()))

    @property
    def endpoints_with_type(self):
        return self._endpoints

    @property
    def ret_sites(self):
        return list(self._ret_sites)

    @property
    def jumpout_sites(self):
        return list(self._jumpout_sites)

    @property
    def retout_sites(self):
        return list(self._retout_sites)

    @property
    def callout_sites(self):
        return list(self._callout_sites)

    @property
    def size(self):
        return sum(self._block_sizes[addr] for addr in self._local_blocks)

    @dirty_func
    def add_jumpout_site(self, node: CodeNode):
        """
        Add a custom jumpout site.

        :param node:    The address of the basic block that control flow leaves during this transition.
        :return:        None
        """

        node = self._register_node(True, node)
        self._jumpout_sites.add(node)
        self._add_endpoint(node, "transition")

    @dirty_func
    def add_retout_site(self, node: CodeNode):
        """
        Add a custom retout site.

        Retout (returning to outside of the function) sites are very rare. It mostly occurs during CFG recovery when we
        incorrectly identify the beginning of a function in the first iteration, and then correctly identify that
        function later in the same iteration (function alignments can lead to this bizarre case). We will mark all edges
        going out of the header of that function as a outside edge, because all successors now belong to the
        incorrectly-identified function. This identification error will be fixed in the second iteration of CFG
        recovery. However, we still want to keep track of jumpouts/retouts during the first iteration so other logic in
        CFG recovery still work.

        :param node: The address of the basic block that control flow leaves the current function after a call.
        :return:     None
        """

        node = self._register_node(True, node)
        self._retout_sites.add(node)
        self._add_endpoint(node, "return")

    @dirty_func
    def _clear_transition_graph(self):
        self._block_sizes = {}
        self._addr_to_block_node = {}
        self._local_blocks = {}
        self._local_block_addrs = set()
        self.startpoint = None
        self.transition_graph = networkx.classes.digraph.DiGraph()
        self._local_transition_graph = None

        self._ret_sites = set()
        self._jumpout_sites = set()
        self._callout_sites = set()
        self._retout_sites = set()
        self._endpoints = defaultdict(set)
        self._call_sites = {}

    @dirty_func
    def _confirm_fakeret(self, src, dst):
        if src not in self.transition_graph or dst not in self.transition_graph[src]:
            raise AngrValueError(f"FakeRet edge ({src}, {dst}) is not in transition graph.")

        data = self.transition_graph[src][dst]

        if "type" not in data or data["type"] != "fake_return":
            raise AngrValueError(f"Edge ({src}, {dst}) is not a FakeRet edge")

        # it's confirmed. register the node if needed
        if "outside" not in data or data["outside"] is False:
            dst = self._register_node(True, dst)

        self.transition_graph[src][dst]["confirmed"] = True

    @dirty_func
    def _transit_to(
        self,
        from_node: CodeNode,
        to_node,
        outside=False,
        ins_addr=None,
        stmt_idx=None,
        is_exception=False,
        update_func_block_count: bool = True,
    ):
        """
        Registers an edge between basic blocks in this function's transition graph.
        Arguments are CodeNode objects.

        :param from_node            The address of the basic block that control
                                    flow leaves during this transition.
        :param to_node              The address of the basic block that control
                                    flow enters during this transition.
        :param bool outside:        If this is a transition to another function, e.g. tail call optimization
        :return: None
        """

        if outside:
            from_node = self._register_node(True, from_node, update_func_block_count=update_func_block_count)
            if to_node is not None:
                to_node = self._register_node(False, to_node, update_func_block_count=update_func_block_count)

            self._jumpout_sites.add(from_node)
        else:
            from_node = self._register_node(True, from_node, update_func_block_count=update_func_block_count)
            if to_node is not None:
                to_node = self._register_node(True, to_node, update_func_block_count=update_func_block_count)

        type_ = "transition" if not is_exception else "exception"
        if to_node is not None:
            self.transition_graph.add_edge(
                from_node, to_node, type=type_, outside=outside, ins_addr=ins_addr, stmt_idx=stmt_idx
            )

        if outside:
            # this node is an endpoint of the current function
            self._add_endpoint(from_node, type_)

        # clear the cache
        self._local_transition_graph = None

    @dirty_func
    def _call_to(
        self,
        from_node,
        to_func: FuncNode | HookNode,
        ret_node,
        stmt_idx=None,
        ins_addr=None,
        return_to_outside=False,
        syscall: bool = False,
        update_func_block_count: bool = True,
    ):
        """
        Registers an edge between the caller basic block and callee function.

        :param from_addr:   The basic block that control flow leaves during the transition.
        :type  from_addr:   angr.knowledge.CodeNode
        :param to_func:     The function that we are calling, represented as a FuncNode.
        :param ret_node     The basic block that control flow should return to after the
                            function call.
        :type  to_func:     angr.knowledge.CodeNode or None
        :param stmt_idx:    Statement ID of this call.
        :type  stmt_idx:    int, str or None
        :param ins_addr:    Instruction address of this call.
        :type  ins_addr:    int or None
        """

        from_node = self._register_node(True, from_node, update_func_block_count=update_func_block_count)

        self.transition_graph.add_edge(
            from_node, to_func, type="syscall" if syscall else "call", stmt_idx=stmt_idx, ins_addr=ins_addr
        )
        if ret_node is not None and not syscall:
            ret_node = self._register_node(
                return_to_outside is False, ret_node, update_func_block_count=update_func_block_count
            )
            self._fakeret_to(
                from_node, ret_node, to_outside=return_to_outside, update_func_block_count=update_func_block_count
            )

        self._local_transition_graph = None

    @dirty_func
    def _fakeret_to(self, from_node, to_node, confirmed=None, to_outside=False, update_func_block_count: bool = True):
        from_node = self._register_node(True, from_node, update_func_block_count=update_func_block_count)
        if confirmed:
            to_node = self._register_node(not to_outside, to_node, update_func_block_count=update_func_block_count)

        if confirmed is None:
            self.transition_graph.add_edge(from_node, to_node, type="fake_return", outside=to_outside)
        else:
            self.transition_graph.add_edge(
                from_node, to_node, type="fake_return", confirmed=confirmed, outside=to_outside
            )

        self._local_transition_graph = None

    @dirty_func
    def _remove_fakeret(self, from_node, to_node):
        self.transition_graph.remove_edge(from_node, to_node)

        self._local_transition_graph = None

    @dirty_func
    def _return_from_call(
        self, from_func: FuncNode | HookNode, to_node, to_outside=False, confirm_fakeret: bool = True
    ):
        self.transition_graph.add_edge(from_func, to_node, type="return", outside=to_outside)
        if confirm_fakeret:
            for _, _, data in self.transition_graph.in_edges(to_node, data=True):
                if "type" in data and data["type"] == "fake_return":
                    data["confirmed"] = True

        self._local_transition_graph = None

    def update_func_block_count(self) -> None:
        """Update the cached block count of this function in the function manager."""
        if self._function_manager is not None:
            self._function_manager.set_func_block_count(self.addr, len(self._local_block_addrs))

    @dirty_func
    def _update_addr_to_block_cache(self, node: BlockNode):
        if node.addr not in self._addr_to_block_node:
            self._addr_to_block_node[node.addr] = node

    @dirty_func
    def _add_return_site(self, return_site: CodeNode):
        """
        Registers a basic block as a site for control flow to return from this function.

        :param return_site:     The block node that ends with a return.
        """
        return_site = self._register_node(True, return_site)

        self._ret_sites.add(return_site)
        # A return site must be an endpoint of the function - you cannot continue execution of the current function
        # after returning
        self._add_endpoint(return_site, "return")

    @dirty_func
    def _add_call_site(self, call_site_addr, call_target_addr, retn_addr):
        """
        Registers a basic block as calling a function and returning somewhere.

        :param call_site_addr:       The address of a basic block that ends in a call.
        :param call_target_addr:     The address of the target of said call.
        :param retn_addr:            The address that said call will return to.
        """
        self._call_sites[call_site_addr] = (call_target_addr, retn_addr)

    @dirty_func
    def _add_endpoint(self, endpoint_node, sort):
        """
        Registers an endpoint with a type of `sort`. The type can be one of the following:
        - call: calling a function that does not return
        - return: returning from the current function
        - transition: a jump/branch targeting a different function

        It is possible for a block to act as two different sorts of endpoints. For example, consider the following
        block:

        .text:0000000000024350                 mov     eax, 1
        .text:0000000000024355                 lock xadd [rdi+4], eax
        .text:000000000002435A                 retn

        VEX code:
           00 | ------ IMark(0x424350, 5, 0) ------
           01 | PUT(rax) = 0x0000000000000001
           02 | PUT(rip) = 0x0000000000424355
           03 | ------ IMark(0x424355, 5, 0) ------
           04 | t11 = GET:I64(rdi)
           05 | t10 = Add64(t11,0x0000000000000004)
           06 | t0 = LDle:I32(t10)
           07 | t2 = Add32(t0,0x00000001)
           08 | t(4,4294967295) = CASle(t10 :: (t0,None)->(t2,None))
           09 | t14 = CasCmpNE32(t4,t0)
           10 | if (t14) { PUT(rip) = 0x424355; Ijk_Boring }
           11 | PUT(cc_op) = 0x0000000000000003
           12 | t15 = 32Uto64(t0)
           13 | PUT(cc_dep1) = t15
           14 | PUT(cc_dep2) = 0x0000000000000001
           15 | t17 = 32Uto64(t0)
           16 | PUT(rax) = t17
           17 | PUT(rip) = 0x000000000042435a
           18 | ------ IMark(0x42435a, 1, 0) ------
           19 | t6 = GET:I64(rsp)
           20 | t7 = LDle:I64(t6)
           21 | t8 = Add64(t6,0x0000000000000008)
           22 | PUT(rsp) = t8
           23 | t18 = Sub64(t8,0x0000000000000080)
           24 | ====== AbiHint(0xt18, 128, t7) ======
           NEXT: PUT(rip) = t7; Ijk_Ret

        This block acts as both a return endpoint and a transition endpoint (transitioning to 0x424355).

        :param endpoint_node:       The endpoint node.
        :param sort:                Type of the endpoint.
        :return:                    None
        """

        self._endpoints[sort].add(endpoint_node)

    def mark_nonreturning_calls_endpoints(self):
        """
        Iterate through all call edges in transition graph. For each call a non-returning function, mark the source
        basic block as an endpoint.

        This method should only be executed once all functions are recovered and analyzed by CFG recovery, so we know
        whether each function returns or not.

        :return: None
        """

        assert self._function_manager is not None

        for src, dst, data in self.transition_graph.edges(data=True):
            if "type" in data and data["type"] == "call":
                func_addr = dst.addr
                if self._function_manager.contains_addr(func_addr) and self._function_manager.is_func_nonreturning(
                    func_addr
                ):
                    # the target function does not return
                    the_node = self.get_node(src.addr)
                    if the_node is not None:
                        self._callout_sites.add(the_node)
                        self._add_endpoint(the_node, "call")
                        self.mark_dirty()

    def get_call_sites(self) -> Iterable[int]:
        """
        Gets a list of all the basic blocks that end in calls.

        :return:                    A view of the addresses of the blocks that end in calls.
        """
        return self._call_sites.keys()

    def get_call_target(self, callsite_addr):
        """
        Get the target of a call.

        :param callsite_addr:       The address of a basic block that ends in a call.
        :return:                    The target of said call, or None if callsite_addr is not a
                                    callsite.
        """
        if callsite_addr in self._call_sites:
            return self._call_sites[callsite_addr][0]
        return None

    def get_call_return(self, callsite_addr):
        """
        Get the hypothetical return address of a call.

        :param callsite_addr:       The address of the basic block that ends in a call.
        :return:                    The likely return target of said call, or None if callsite_addr
                                    is not a callsite.
        """
        if callsite_addr in self._call_sites:
            return self._call_sites[callsite_addr][1]
        return None

    @property
    def graph(self) -> networkx.DiGraph[CodeNode]:
        """
        Get a local transition graph. A local transition graph is a transition graph that only contains nodes that
        belong to the current function. All edges, except for the edges going out from the current function or coming
        from outside the current function, are included.

        The generated graph is cached in self._local_transition_graph.

        :return:    A local transition graph.
        :rtype:     networkx.DiGraph
        """

        if self._local_transition_graph is not None:
            return self._local_transition_graph

        g = networkx.classes.digraph.DiGraph()
        if self.startpoint is not None:
            g.add_node(self.startpoint)
        for block in self._local_blocks.values():
            g.add_node(block)
        for src, dst, data in self.transition_graph.edges(data=True):
            if "type" in data and (
                (data["type"] in ("transition", "exception") and ("outside" not in data or data["outside"] is False))
                or (data["type"] == "fake_return" and ("outside" not in data or data["outside"] is False))
            ):
                g.add_edge(src, dst, **data)

        self._local_transition_graph = g

        return g

    def subgraph(self, ins_addrs):
        """
        Generate a sub control flow graph of instruction addresses based on self.graph

        :param iterable ins_addrs: A collection of instruction addresses that should be included in the subgraph.
        :return networkx.DiGraph: A subgraph.
        """

        # find all basic blocks that include those instructions
        blocks = []
        block_addr_to_insns = {}

        for b in self._local_blocks.values():
            # TODO: should I call get_blocks?
            block = self.get_block(b.addr, size=b.size, byte_string=b.bytestr)
            common_insns = set(block.instruction_addrs).intersection(ins_addrs)
            if common_insns:
                blocks.append(b)
                block_addr_to_insns[b.addr] = sorted(common_insns)

        # subgraph = networkx.subgraph(self.graph, blocks)
        subgraph = self.graph.subgraph(blocks).copy()
        assert isinstance(subgraph, networkx.DiGraph)
        g = networkx.classes.digraph.DiGraph()

        for n in subgraph.nodes():
            insns = block_addr_to_insns[n.addr]

            in_edges = subgraph.in_edges(n)
            # out_edges = subgraph.out_edges(n)
            # the first instruction address should be included
            if len(in_edges) > 1 and n.addr not in insns:
                insns = [n.addr, *insns]

            for src, _ in in_edges:
                last_instr = block_addr_to_insns[src.addr][-1]
                g.add_edge(last_instr, insns[0])

            for i in range(len(insns) - 1):
                g.add_edge(insns[i], insns[i + 1])

        return g

    def dbg_print(self):
        """
        Returns a representation of the list of basic blocks in this function.
        """
        return "[{}]".format(", ".join((f"{n.addr:#08x}") for n in self.transition_graph.nodes()))

    @property
    def has_return(self):
        return len(self._ret_sites) > 0

    def holes(self, min_size: int = 8) -> int:
        """
        Find the number of non-consecutive areas in the function that are at least `min_size` bytes large.
        """

        block_addrs = sorted(self._local_block_addrs)
        if not block_addrs:
            return 0
        holes = 0
        for i, addr in enumerate(block_addrs):
            if i == len(block_addrs) - 1:
                break
            next_addr = block_addrs[i + 1]
            if next_addr > addr + self._block_sizes[addr] and next_addr - (addr + self._block_sizes[addr]) >= min_size:
                holes += 1
        return holes

    def copy(self):
        func = SootFunction(self._function_manager, self.addr, name=self.name, syscall=self.is_syscall)
        func.transition_graph = networkx.DiGraph(self.transition_graph)
        func.normalized = self.normalized
        func._ret_sites = self._ret_sites.copy()
        func._jumpout_sites = self._jumpout_sites.copy()
        func._retout_sites = self._retout_sites.copy()
        func._endpoints = self._endpoints.copy()
        func._call_sites = self._call_sites.copy()
        func._project = self._project
        func.previous_names = list(self.previous_names)
        func._is_plt = self.is_plt
        func._is_simprocedure = self.is_simprocedure
        func.binary_name = self.binary_name
        func.bp_on_stack = self.bp_on_stack
        func.retaddr_on_stack = self.retaddr_on_stack
        func.sp_delta = self.sp_delta
        func._calling_convention = self.calling_convention
        func.prototype = self.prototype
        func._returning = self._returning
        func._is_alignment = self.is_alignment
        func.startpoint = self.startpoint
        func._addr_to_block_node = self._addr_to_block_node.copy()
        func._block_sizes = self._block_sizes.copy()
        func._local_blocks = self._local_blocks.copy()
        func._local_block_addrs = self._local_block_addrs.copy()
        func._info = self.info.copy(func)
        func.tags = self.tags
        func._dirty = self._dirty

        return func

    def outgoing_function_targets(self) -> list:
        targets = []
        for node in self.transition_graph:
            if isinstance(node, HookNode) and node.addr == self.addr:
                # the start node of a hooked function, not a callee
                continue
            if isinstance(node, (HookNode, FuncNode)) or any(
                data.get("type") == "transition" and data.get("outside") is True
                for _, _, data in self.transition_graph.in_edges(node, data=True)
            ):
                targets.append(node.addr)
        return targets

    def _successors_of(self, node) -> list:
        return list(self.transition_graph.successors(node))

    def _predecessors_of(self, node) -> list:
        return list(self.transition_graph.predecessors(node))

    def _remove_edge(self, from_node, to_node) -> None:
        self.transition_graph.remove_edge(from_node, to_node)
        self._local_transition_graph = None

    # compatibility
    _get_block = get_block
