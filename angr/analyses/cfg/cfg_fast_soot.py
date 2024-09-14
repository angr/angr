from __future__ import annotations
import logging

from collections import defaultdict

from sortedcontainers import SortedDict
from copy import copy

from archinfo.arch_soot import SootMethodDescriptor, SootAddressDescriptor

from ...utils.constants import DEFAULT_STATEMENT
from ...errors import AngrCFGError, SimMemoryError, SimEngineError
from ...codenode import HookNode, SootBlockNode
from ...knowledge_plugins.cfg import CFGNode
from .. import register_analysis
from .cfg_fast import CFGFast, CFGJob, PendingJobs, FunctionTransitionEdge

l = logging.getLogger(name=__name__)

try:
    from pysoot.sootir.soot_value import SootLocal
    from pysoot.sootir.soot_statement import IfStmt, InvokeStmt, GotoStmt, AssignStmt
    from pysoot.sootir.soot_expr import (
        SootStaticInvokeExpr,
        SootInvokeExpr,
    )

    PYSOOT_INSTALLED = True
except ImportError:
    PYSOOT_INSTALLED = False


class CFGFastSoot(CFGFast):
    def __init__(self, support_jni=False, **kwargs):
        if not PYSOOT_INSTALLED:
            raise ImportError("Please install PySoot before analyzing Java byte code.")

        if self.project.arch.name != "Soot":
            raise AngrCFGError("CFGFastSoot only supports analyzing Soot programs.")

        self._soot_class_hierarchy = self.project.analyses.SootClassHierarchy()
        self.support_jni = support_jni
        super().__init__(regions=SortedDict({}), **kwargs)

        self._changed_functions = None
        self._total_methods = None

    def _pre_analysis(self):
        # Call _initialize_cfg() before self.functions is used.
        self._initialize_cfg()

        # Initialize variables used during analysis
        self._pending_jobs = PendingJobs(self.functions, self._deregister_analysis_job)
        self._traced_addresses = set()
        self._changed_functions = set()
        self._updated_nonreturning_functions = set()

        self._function_returns = defaultdict(set)

        entry: SootAddressDescriptor = self.project.entry
        entry_func = entry.method

        obj = self.project.loader.main_object

        if entry_func is not None:
            method_inst = obj.get_soot_method(
                entry_func.name, class_name=entry_func.class_name, params=entry_func.params
            )
        else:
            l.warning("The entry method is unknown. Try to find a main method.")
            method_inst = next(obj.main_methods, None)
            if method_inst is not None:
                entry_func = SootMethodDescriptor(method_inst.class_name, method_inst.name, method_inst.params)
            else:
                l.warning("Cannot find any main methods. Start from the first method of the first class.")
                for cls in obj.classes.values():
                    method_inst = next(iter(cls.methods), None)
                    if method_inst is not None:
                        break
                if method_inst is not None:
                    entry_func = SootMethodDescriptor(method_inst.class_name, method_inst.name, method_inst.params)
                else:
                    raise AngrCFGError("There is no method in the Jar file.")

        # project.entry is a method
        # we should get the first block
        if method_inst.blocks:
            block_idx = method_inst.blocks[0].idx
            self._insert_job(CFGJob(SootAddressDescriptor(entry_func, block_idx, 0), entry_func, "Ijk_Boring"))

        total_methods = 0

        # add all other methods as well
        for cls in self.project.loader.main_object.classes.values():
            for method in cls.methods:
                total_methods += 1
                if method.blocks:
                    method_des = SootMethodDescriptor(cls.name, method.name, method.params)
                    # TODO shouldn't this be idx?
                    block_idx = method.blocks[0].label
                    self._insert_job(CFGJob(SootAddressDescriptor(method_des, block_idx, 0), method_des, "Ijk_Boring"))

        self._total_methods = total_methods

    def _pre_job_handling(self, job):
        if (self._show_progressbar or self._progress_callback) and self._total_methods:
            percentage = len(self.functions) * 100.0 / self._total_methods
            self._update_progress(percentage)

    def normalize(self):
        # The Shimple CFG is already normalized.
        pass

    def _pop_pending_job(self, returning=True):
        # We are assuming all functions must return
        return self._pending_jobs.pop_job(returning=True)

    def _generate_cfgnode(self, cfg_job, current_function_addr):
        addr = cfg_job.addr

        try:
            cfg_node = self.model.get_node(addr)
            if cfg_node is not None:
                soot_block = cfg_node.soot_block
            else:
                soot_block = self.project.factory.block(addr).soot

                soot_block_size = self._soot_block_size(soot_block, addr.stmt_idx)

                cfg_node = CFGNode(
                    addr,
                    soot_block_size,
                    self.model,
                    function_address=current_function_addr,
                    block_id=addr,
                    soot_block=soot_block,
                )
            return addr, current_function_addr, cfg_node, soot_block

        except (SimMemoryError, SimEngineError):
            return None, None, None, None

    def _block_get_successors(self, addr, function_addr, block, cfg_node):
        if block is None:
            # this block is not included in the artifacts...
            return []

        return self._soot_get_successors(addr, function_addr, block, cfg_node)

    def _soot_get_successors(self, addr, function_id, block, cfg_node):  # pylint:disable=unused-argument
        # soot method
        method = self.project.loader.main_object.get_soot_method(function_id)

        # native method has no soot block
        if self.support_jni and block is None:
            return self._native_method_successors(addr, method)

        block_id = block.idx

        if addr.stmt_idx is None:
            addr = SootAddressDescriptor(addr.method, block_id, 0)

        successors = []

        has_default_exit = True

        next_stmt_id = block.label + len(block.statements)
        last_stmt_id = method.blocks[-1].label + len(method.blocks[-1].statements) - 1

        if next_stmt_id >= last_stmt_id:
            # there should not be a default exit going to the next block
            has_default_exit = False

        # scan through block statements, looking for those that generate new exits
        for stmt in block.statements[addr.stmt_idx - block.label :]:
            if isinstance(stmt, IfStmt):
                succ = (
                    stmt.label,
                    addr,
                    SootAddressDescriptor(function_id, method.block_by_label[stmt.target].idx, stmt.target),
                    "Ijk_Boring",
                )
                successors.append(succ)

            elif isinstance(stmt, InvokeStmt):
                invoke_expr = stmt.invoke_expr

                # add special successors
                if self.support_jni:
                    succs = self._special_invoke_successors(stmt, addr, block)
                    if succs:
                        successors.extend(succs)

                succs = self._soot_create_invoke_successors(stmt, addr, invoke_expr)
                if succs:
                    successors.extend(succs)
                    has_default_exit = False
                    break

            elif isinstance(stmt, GotoStmt):
                target = stmt.target
                succ = (
                    stmt.label,
                    addr,
                    SootAddressDescriptor(function_id, method.block_by_label[target].idx, target),
                    "Ijk_Boring",
                )
                successors.append(succ)

                # blocks ending with a GoTo should not have a default exit
                has_default_exit = False
                break

            elif isinstance(stmt, AssignStmt):
                expr = stmt.right_op

                if isinstance(expr, SootInvokeExpr):
                    succs = self._special_invoke_successors(stmt, addr, block)
                    if succs:
                        successors.extend(succs)

                    succs = self._soot_create_invoke_successors(stmt, addr, expr)
                    if succs:
                        successors.extend(succs)
                        has_default_exit = False
                        break

        if has_default_exit:
            successors.append(
                (
                    DEFAULT_STATEMENT,
                    addr,
                    SootAddressDescriptor(function_id, method.block_by_label[next_stmt_id].idx, next_stmt_id),
                    "Ijk_Boring",
                )
            )

        return successors

    def _native_method_successors(self, addr, method):
        class_name = "nativemethod"
        # e.g., Java_com_example_nativemedia_NativeMedia_shutdown
        method_name = "Java_" + method.class_name.replace(".", "_") + "_" + method.name
        params = method.params
        dummy_expr = SootStaticInvokeExpr("void", class_name, method_name, params, {"jni"})
        dummy_stmt = InvokeStmt(0, 0, dummy_expr)
        return self._soot_create_invoke_successors(dummy_stmt, addr, dummy_expr)

    def _special_invoke_successors(self, stmt, addr, block):
        invoke_expr = stmt.invoke_expr if isinstance(stmt, InvokeStmt) else stmt.right_op
        succs = None

        # add <clinit>
        # many class using jni are loading the library in static method
        if invoke_expr.method_name == "<init>":
            clinit_invoke_expr = copy(invoke_expr)
            clinit_invoke_expr.method_name = "<clinit>"
            succs = self._soot_create_invoke_successors(stmt, addr, clinit_invoke_expr)

        # convert 'System.loadLibrary' to JNI_OnLoad of library name
        # format: <libname>.JNI_OnLoad(java.lang.String)
        elif invoke_expr.class_name == "System" and invoke_expr.method_name == "loadLibrary":
            # Todo: restrictly set condition System.loadlibrary
            try:
                native_lib_name = invoke_expr.args[0].value.replace('"', "").replace("'", "")
                invoke_expr.class_name = native_lib_name
            except AttributeError:
                pass
            invoke_expr.method_name = "JNI_OnLoad"
            succs = self._soot_create_invoke_successors(stmt, addr, invoke_expr)

        # add thread.start()
        # it may occur that block is NoneType when thread call native method.
        # so only use on support_jni condition
        # format: <classname>.run()
        elif invoke_expr.class_name == "java.lang.Thread" and invoke_expr.method_name == "start":
            # Runnable arg case
            if invoke_expr.base.type == "java.lang.Thread":
                thread_class_name = None
                args = []
                for before_stmt in block.statements[: block.statements.index(stmt)]:
                    if isinstance(before_stmt, InvokeStmt):
                        args.extend(before_stmt.invoke_expr.args)

                # match arg.name == base.name
                for name in [arg.name for arg in args if isinstance(arg, SootLocal)]:
                    thread_class_name = name if name == invoke_expr.base.name else None

            # Basic case
            else:
                thread_class_name = invoke_expr.base.type

            if thread_class_name is not None:
                thread_invoke_expr = copy(invoke_expr)
                thread_invoke_expr.class_name = thread_class_name
                thread_invoke_expr.method_name = "run"
                succs = self._soot_create_invoke_successors(stmt, addr, thread_invoke_expr)

        return succs

    def _soot_create_invoke_successors(self, stmt, addr, invoke_expr):
        method_class = invoke_expr.class_name
        method_name = invoke_expr.method_name
        method_params = invoke_expr.method_params
        method_desc = SootMethodDescriptor(method_class, method_name, method_params)

        callee_soot_method = self.project.loader.main_object.get_soot_method(method_desc, none_if_missing=True)
        caller_soot_method = self.project.loader.main_object.get_soot_method(addr.method)

        if callee_soot_method is None:
            # this means the called method is external
            return [(stmt.label, addr, SootAddressDescriptor(method_desc, 0, 0), "Ijk_Call")]

        targets = self._soot_class_hierarchy.resolve_invoke(invoke_expr, callee_soot_method, caller_soot_method)

        successors = []
        for target in targets:
            target_desc = SootMethodDescriptor(target.class_name, target.name, target.params)
            successors.append((stmt.label, addr, SootAddressDescriptor(target_desc, 0, 0), "Ijk_Call"))

        return successors

    @staticmethod
    def _loc_to_funcloc(location):
        if isinstance(location, SootAddressDescriptor):
            return location.method
        return location

    def _to_snippet(self, cfg_node=None, addr=None, size=None, thumb=False, jumpkind=None, base_state=None):
        assert thumb is False

        if cfg_node is not None:
            addr = cfg_node.addr
            stmts_count = cfg_node.size
        else:
            addr = addr
            stmts_count = size

        if addr is None:
            raise ValueError("_to_snippet(): Either cfg_node or addr must be provided.")

        if self.project.is_hooked(addr) and jumpkind != "Ijk_NoHook":
            hooker = self.project._sim_procedures[addr]
            size = hooker.kwargs.get("length", 0)
            return HookNode(addr, size, type(hooker))

        soot_block = cfg_node.soot_block if cfg_node is not None else self.project.factory.block(addr).soot

        if soot_block is not None:
            stmts = soot_block.statements
            if stmts_count is None:
                stmts_count = self._soot_block_size(soot_block, addr.stmt_idx)
            stmts = stmts[addr.stmt_idx - soot_block.label : addr.stmt_idx - soot_block.label + stmts_count]
        else:
            stmts = None
            stmts_count = 0

        return SootBlockNode(addr, stmts_count, stmts)

    @staticmethod
    def _soot_block_size(soot_block, start_stmt_idx):
        if soot_block is None:
            return 0

        stmts_count = 0

        for stmt in soot_block.statements[start_stmt_idx - soot_block.label :]:
            stmts_count += 1
            if isinstance(stmt, (InvokeStmt, GotoStmt)):
                break
            if isinstance(stmt, AssignStmt) and isinstance(stmt.right_op, SootInvokeExpr):
                break

        return stmts_count

    def _scan_block(self, cfg_job) -> list[CFGJob]:
        """
        Scan a basic block starting at a specific address

        :param CFGJob cfg_job: The CFGJob instance.
        :return: a list of successors
        :rtype: list
        """

        addr = cfg_job.addr
        current_func_addr = cfg_job.func_addr

        if self._addr_hooked_or_syscall(addr):
            entries = self._scan_procedure(cfg_job, current_func_addr)

        else:
            entries = self._scan_soot_block(cfg_job, current_func_addr)

        return entries

    def _scan_soot_block(self, cfg_job, current_func_addr):
        """
        Generate a list of successors (generating them each as entries) to IRSB.
        Updates previous CFG nodes with edges.

        :param CFGJob cfg_job: The CFGJob instance.
        :param int current_func_addr: Address of the current function
        :return: a list of successors
        :rtype: list
        """

        addr, function_addr, cfg_node, soot_block = self._generate_cfgnode(cfg_job, current_func_addr)

        # Add edges going to this node in function graphs
        cfg_job.apply_function_edges(self, clear=True)

        # function_addr and current_function_addr can be different. e.g. when tracing an optimized tail-call that jumps
        # into another function that has been identified before.

        if cfg_node is None:
            # exceptions occurred, or we cannot get a CFGNode for other reasons
            return []

        self._graph_add_edge(cfg_node, cfg_job.src_node, cfg_job.jumpkind, cfg_job.src_ins_addr, cfg_job.src_stmt_idx)
        self._function_add_node(cfg_node, function_addr)

        # If we have traced it before, don't trace it anymore
        if addr in self._traced_addresses:
            # the address has been traced before
            return []
        # Mark the address as traced
        self._traced_addresses.add(addr)

        # soot_block is only used once per CFGNode. We should be able to clean up the CFGNode here in order to save
        # memory
        cfg_node.soot_block = None

        successors = self._soot_get_successors(addr, current_func_addr, soot_block, cfg_node)

        entries = []

        for suc in successors:
            stmt_idx, stmt_addr, target, jumpkind = suc

            entries += self._create_jobs(
                target, jumpkind, function_addr, soot_block, addr, cfg_node, stmt_addr, stmt_idx
            )

        return entries

    def _create_jobs(
        self, target, jumpkind, current_function_addr, soot_block, addr, cfg_node, stmt_addr, stmt_idx
    ):  # pylint:disable=arguments-differ
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
        :param int stmt_addr:       ID of the source statement.
        :return:                    a list of CFGJobs
        :rtype:                     list
        """

        target_addr = target

        jobs = []

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

        elif target_addr is not None:
            # This is a direct jump with a concrete target.

            # pylint: disable=too-many-nested-blocks
            if jumpkind in ("Ijk_Boring", "Ijk_InvalICache"):
                # it might be a jumpout
                target_func_addr = None
                if target_addr in self._traced_addresses:
                    node = self.get_any_node(target_addr)
                    if node is not None:
                        target_func_addr = node.function_address
                if target_func_addr is None:
                    target_func_addr = current_function_addr

                to_outside = target_func_addr != current_function_addr

                edge = FunctionTransitionEdge(
                    cfg_node,
                    target_addr,
                    current_function_addr,
                    to_outside=to_outside,
                    dst_func_addr=target_func_addr,
                    ins_addr=stmt_addr,
                    stmt_idx=stmt_idx,
                )

                ce = CFGJob(
                    target_addr,
                    target_func_addr,
                    jumpkind,
                    last_addr=addr,
                    src_node=cfg_node,
                    src_ins_addr=stmt_addr,
                    src_stmt_idx=stmt_idx,
                    func_edges=[edge],
                )
                jobs.append(ce)

            elif jumpkind == "Ijk_Call" or jumpkind.startswith("Ijk_Sys"):
                jobs += self._create_job_call(
                    addr,
                    soot_block,
                    cfg_node,
                    stmt_idx,
                    stmt_addr,
                    current_function_addr,
                    target_addr,
                    jumpkind,
                    is_syscall=False,
                )
                self._pending_jobs.add_returning_function(target.method)

            else:
                # TODO: Support more jumpkinds
                l.debug("Unsupported jumpkind %s", jumpkind)

        return jobs

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

        # There are some issues in support_jni environment(e.g. _graph_bfs_custom looping)
        # It handled as passing over for quick fix.
        if self.support_jni:
            return

        tmp_functions = self.kb.functions.copy()

        for function in tmp_functions.values():
            function.mark_nonreturning_calls_endpoints()

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

        entry_node = self.get_any_node(self._binary.entry)
        if entry_node is not None:
            function_nodes.add(entry_node)

        for n in self.graph.nodes():
            funcloc = self._loc_to_funcloc(n.addr)
            if funcloc in tmp_functions:
                function_nodes.add(n)

        # traverse the graph starting from each node, not following call edges
        # it's important that we traverse all functions in order so that we have a greater chance to come across
        # rational functions before its irrational counterparts (e.g. due to failed jump table resolution)

        min_stage_2_progress = 50.0
        max_stage_2_progress = 90.0
        nodes_count = len(function_nodes)
        for i, fn in enumerate(function_nodes):
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
            node = self.get_any_node(func_addr)
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
        for i, fn in enumerate(secondary_function_nodes):
            if self._show_progressbar or self._progress_callback:
                progress = min_stage_3_progress + (max_stage_3_progress - min_stage_3_progress) * (
                    i * 1.0 / nodes_count
                )
                self._update_progress(progress)

            self._graph_bfs_custom(
                self.graph, [fn], self._graph_traversal_handler, blockaddr_to_function, tmp_functions
            )

        to_remove = set()

        # remove empty functions
        for function in self.kb.functions.values():
            if function.startpoint is None:
                to_remove.add(function.addr)

        for addr in to_remove:
            del self.kb.functions[addr]

        # Update CFGNode.function_address
        for node in self.model.nodes():
            if node.addr in blockaddr_to_function:
                node.function_address = blockaddr_to_function[node.addr].addr


register_analysis(CFGFastSoot, "CFGFastSoot")
