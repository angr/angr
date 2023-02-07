import itertools

import networkx

import pyvex

from .errors import AngrBladeError, SimTranslationError
from .knowledge_plugins.cfg import CFGNode
from .utils.constants import DEFAULT_STATEMENT
from .slicer import SimSlicer


class Blade:
    """
    Blade is a light-weight program slicer that works with networkx DiGraph containing CFGNodes.
    It is meant to be used in angr for small or on-the-fly analyses.
    """

    def __init__(
        self,
        graph,
        dst_run,
        dst_stmt_idx,
        direction="backward",
        project=None,
        cfg=None,
        ignore_sp=False,
        ignore_bp=False,
        ignored_regs=None,
        max_level=3,
        base_state=None,
        stop_at_calls=False,
        cross_insn_opt=False,
        max_predecessors: int = 10,
    ):
        """
        :param networkx.DiGraph graph:  A graph representing the control flow graph. Note that it does not take
                                        angr.analyses.CFGEmulated or angr.analyses.CFGFast.
        :param int dst_run:             An address specifying the target SimRun.
        :param int dst_stmt_idx:        The target statement index. -1 means executing until the last statement.
        :param str direction:           'backward' or 'forward' slicing. Forward slicing is not yet supported.
        :param angr.Project project:    The project instance.
        :param angr.analyses.CFGBase cfg: the CFG instance. It will be made mandatory later.
        :param bool ignore_sp:          Whether the stack pointer should be ignored in dependency tracking. Any
                                        dependency from/to stack pointers will be ignored if this options is True.
        :param bool ignore_bp:          Whether the base pointer should be ignored or not.
        :param int  max_level:          The maximum number of blocks that we trace back for.
        :param int stop_at_calls:       Limit slicing within a single function. Do not proceed when encounters a call
                                        edge.
        :return: None
        """

        self._graph = graph
        self._dst_run = dst_run
        self._dst_stmt_idx = dst_stmt_idx
        self._ignore_sp = ignore_sp
        self._ignore_bp = ignore_bp
        self._max_level = max_level
        self._base_state = base_state
        self._stop_at_calls = stop_at_calls
        self._cross_insn_opt = cross_insn_opt
        self._max_predecessors = max_predecessors

        self._slice = networkx.DiGraph()

        self.project = project
        self._cfg = cfg.model
        if self._cfg is None:
            # `cfg` is made optional only for compatibility concern. It will be made a positional parameter later.
            raise AngrBladeError('"cfg" must be specified.')

        if not self._in_graph(self._dst_run):
            raise AngrBladeError("The specified SimRun %s doesn't exist in graph." % self._dst_run)

        self._ignored_regs = set()
        if ignored_regs:
            for r in ignored_regs:
                if isinstance(r, int):
                    self._ignored_regs.add(r)
                else:
                    self._ignored_regs.add(self.project.arch.registers[r][0])

        self._run_cache = {}

        self._traced_runs = set()

        if direction == "backward":
            self._backward_slice()
        elif direction == "forward":
            raise AngrBladeError("Forward slicing is not implemented yet")
        else:
            raise AngrBladeError("Unknown slicing direction %s" % direction)

    #
    # Properties
    #

    @property
    def slice(self):
        return self._slice

    #
    # Public methods
    #

    def dbg_repr(self, arch=None):
        if arch is None and self.project is not None:
            arch = self.project.arch

        s = ""

        block_addrs = {a for a, _ in self.slice.nodes()}

        for block_addr in block_addrs:
            block_str = "       IRSB %#x\n" % block_addr

            block = self.project.factory.block(
                block_addr, cross_insn_opt=self._cross_insn_opt, backup_state=self._base_state
            ).vex

            included_stmts = {stmt for _, stmt in self.slice.nodes() if _ == block_addr}
            default_exit_included = any(stmt == DEFAULT_STATEMENT for _, stmt in self.slice.nodes() if _ == block_addr)

            for i, stmt in enumerate(block.statements):
                if arch is not None:
                    if isinstance(stmt, pyvex.IRStmt.Put):
                        reg_name = arch.translate_register_name(stmt.offset)
                        stmt_str = stmt.__str__(reg_name=reg_name)
                    elif isinstance(stmt, pyvex.IRStmt.WrTmp) and isinstance(stmt.data, pyvex.IRExpr.Get):
                        reg_name = arch.translate_register_name(stmt.data.offset)
                        stmt_str = stmt.__str__(reg_name=reg_name)
                    else:
                        stmt_str = str(stmt)
                else:
                    stmt_str = str(stmt)

                block_str += "%02s %02d | %s\n" % ("+" if i in included_stmts else " ", i, stmt_str)

            block_str += " + " if default_exit_included else "   "
            if isinstance(block.next, pyvex.IRExpr.Const):
                block_str += "Next: %#x\n" % block.next.con.value
            elif isinstance(block.next, pyvex.IRExpr.RdTmp):
                block_str += "Next: t%d\n" % block.next.tmp
            else:
                block_str += "Next: %s\n" % str(block.next)

            s += block_str
            s += "\n"

        return s

    #
    # Private methods
    #

    def _get_irsb(self, v):
        """
        Get the IRSB object from an address, a SimRun, or a CFGNode.
        :param v: Can be one of the following: an address, or a CFGNode.
        :return: The IRSB instance.
        :rtype: pyvex.IRSB
        """

        if isinstance(v, CFGNode):
            v = v.addr

        if type(v) is int:
            # Generate an IRSB from self._project

            if v in self._run_cache:
                return self._run_cache[v]

            if self.project:
                irsb = self.project.factory.block(
                    v, cross_insn_opt=self._cross_insn_opt, backup_state=self._base_state
                ).vex
                self._run_cache[v] = irsb
                return irsb
            else:
                raise AngrBladeError("Project must be specified if you give me all addresses for SimRuns")

        else:
            raise AngrBladeError("Unsupported SimRun argument type %s" % type(v))

    def _get_cfgnode(self, thing):
        """
        Get the CFGNode corresponding to the specific address.

        :param thing: Can be anything that self._normalize() accepts. Usually it's the address of the node
        :return: the CFGNode instance
        :rtype: CFGNode
        """

        return self._cfg.get_any_node(self._get_addr(thing))

    @staticmethod
    def _get_addr(v):
        """
        Get address of the basic block or CFG node specified by v.
        :param v: Can be one of the following: a CFGNode, or an address.
        :return: The address.
        :rtype: int
        """

        if isinstance(v, CFGNode):
            return v.addr
        elif type(v) is int:
            return v
        else:
            raise AngrBladeError("Unsupported SimRun argument type %s" % type(v))

    def _in_graph(self, v):
        return self._get_cfgnode(v) in self._graph

    def _inslice_callback(self, stmt_idx, stmt, infodict):  # pylint:disable=unused-argument
        tpl = (infodict["irsb_addr"], stmt_idx)
        if "prev" in infodict and infodict["prev"]:
            prev = infodict["prev"]
            self._slice.add_edge(tpl, prev)
        else:
            self._slice.add_node(tpl)

        infodict["prev"] = tpl
        infodict["has_statement"] = True

    def _backward_slice(self):
        """
        Backward slicing.

        We support the following IRStmts:
        # WrTmp
        # Put

        We support the following IRExprs:
        # Get
        # RdTmp
        # Const

        :return:
        """

        temps = set()
        regs = set()

        # Retrieve the target: are we slicing from a register(IRStmt.Put), or a temp(IRStmt.WrTmp)?
        try:
            stmts = self._get_irsb(self._dst_run).statements
        except SimTranslationError:
            return

        if self._dst_stmt_idx != -1:
            dst_stmt = stmts[self._dst_stmt_idx]

            if type(dst_stmt) is pyvex.IRStmt.Put:
                regs.add(dst_stmt.offset)
            elif type(dst_stmt) is pyvex.IRStmt.WrTmp:
                temps.add(dst_stmt.tmp)
            else:
                raise AngrBladeError("Incorrect type of the specified target statement. We only support Put and WrTmp.")

            prev = (self._get_addr(self._dst_run), self._dst_stmt_idx)
        else:
            next_expr = self._get_irsb(self._dst_run).next

            if type(next_expr) is pyvex.IRExpr.RdTmp:
                temps.add(next_expr.tmp)
            elif type(next_expr) is pyvex.IRExpr.Const:
                # A const doesn't rely on anything else!
                pass
            else:
                raise AngrBladeError("Unsupported type for irsb.next: %s" % type(next_expr))

            # Then we gotta start from the very last statement!
            self._dst_stmt_idx = len(stmts) - 1

            prev = (self._get_addr(self._dst_run), DEFAULT_STATEMENT)

        if not temps and not regs:
            # no dependency
            return

        slicer = SimSlicer(
            self.project.arch,
            stmts,
            target_tmps=temps,
            target_regs=regs,
            target_stack_offsets=None,
            inslice_callback=self._inslice_callback,
            inslice_callback_infodict={
                "irsb_addr": self._get_irsb(self._dst_run).addr,
                "prev": prev,
            },
        )
        regs = slicer.final_regs
        if self._ignore_sp and self.project.arch.sp_offset in regs:
            regs.remove(self.project.arch.sp_offset)
        if self._ignore_bp and self.project.arch.bp_offset in regs:
            regs.remove(self.project.arch.bp_offset)
        for offset in self._ignored_regs:
            if offset in regs:
                regs.remove(offset)

        stack_offsets = slicer.final_stack_offsets

        prev = slicer.inslice_callback_infodict["prev"]

        if regs or stack_offsets:
            cfgnode = self._get_cfgnode(self._dst_run)
            if cfgnode is not None:
                in_edges = self._graph.in_edges(cfgnode, data=True)

                if len(in_edges) > self._max_predecessors:
                    # take the first N edges
                    in_edges = itertools.islice(in_edges, self._max_predecessors)

                for pred, _, data in in_edges:
                    if "jumpkind" in data:
                        if self._stop_at_calls and data["jumpkind"] in {"Ijk_Call", "Ijk_Ret"}:
                            # Skip calls
                            continue
                    if self.project.is_hooked(pred.addr):
                        # Skip SimProcedures
                        continue
                    self._backward_slice_recursive(
                        self._max_level - 1, pred, regs, stack_offsets, prev, data.get("stmt_idx", None)
                    )

    def _backward_slice_recursive(self, level, run, regs, stack_offsets, prev, exit_stmt_idx):
        if level <= 0:
            return

        temps = set()
        regs = regs.copy()

        irsb_addr = self._get_addr(run)
        stmts = self._get_irsb(run).statements

        if exit_stmt_idx is None or exit_stmt_idx == DEFAULT_STATEMENT:
            # Initialize the temps set with whatever in the `next` attribute of this irsb
            next_expr = self._get_irsb(run).next
            if type(next_expr) is pyvex.IRExpr.RdTmp:
                temps.add(next_expr.tmp)

        # add the default exit into our slice
        self._inslice_callback(DEFAULT_STATEMENT, None, {"irsb_addr": irsb_addr, "prev": prev})
        prev = irsb_addr, DEFAULT_STATEMENT

        # if there are conditional exits, we *always* add them into the slice (so if they should not be taken, we do not
        # lose the condition)
        for stmt_idx_, s_ in enumerate(self._get_irsb(run).statements):
            if type(s_) is not pyvex.IRStmt.Exit:
                continue
            if s_.jumpkind != "Ijk_Boring":
                continue

            if type(s_.guard) is pyvex.IRExpr.RdTmp:
                temps.add(s_.guard.tmp)

            # Put it in our slice
            self._inslice_callback(stmt_idx_, s_, {"irsb_addr": irsb_addr, "prev": prev})
            prev = (irsb_addr, stmt_idx_)

        infodict = {"irsb_addr": irsb_addr, "prev": prev, "has_statement": False}

        slicer = SimSlicer(
            self.project.arch,
            stmts,
            target_tmps=temps,
            target_regs=regs,
            target_stack_offsets=stack_offsets,
            inslice_callback=self._inslice_callback,
            inslice_callback_infodict=infodict,
        )

        if not infodict["has_statement"]:
            # put this block into the slice
            self._inslice_callback(0, None, infodict)

        if run in self._traced_runs:
            return
        self._traced_runs.add(run)

        regs = slicer.final_regs

        if self._ignore_sp and self.project.arch.sp_offset in regs:
            regs.remove(self.project.arch.sp_offset)
        if self._ignore_bp and self.project.arch.bp_offset in regs:
            regs.remove(self.project.arch.bp_offset)

        stack_offsets = slicer.final_stack_offsets

        prev = slicer.inslice_callback_infodict["prev"]

        if regs or stack_offsets:
            next_node = self._get_cfgnode(run)
            if next_node is not None:
                in_edges = self._graph.in_edges(next_node, data=True)

                if len(in_edges) > self._max_predecessors:
                    # take the first N edges
                    in_edges = itertools.islice(in_edges, self._max_predecessors)

                for pred, _, data in in_edges:
                    if "jumpkind" in data:
                        if self._stop_at_calls and data["jumpkind"] in {"Ijk_Call", "Ijk_Ret"}:
                            # skip calls as instructed
                            continue
                    if self.project.is_hooked(pred.addr):
                        # Stop at SimProcedures
                        continue

                    self._backward_slice_recursive(
                        level - 1, pred, regs, stack_offsets, prev, data.get("stmt_idx", None)
                    )
