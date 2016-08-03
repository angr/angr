import networkx

import pyvex
import simuvex

from .knowledge import CodeNode

class Blade(object):
    """
    Blade is a light-weight program slicer that works with networkx DiGraph containing SimIRSBs.
    It is meant to be used in angr for small or on-the-fly analyses.
    """
    def __init__(self, graph, dst_run, dst_stmt_idx, direction='backward', project=None, cfg=None, ignore_sp=False,
                 ignore_bp=False, ignored_regs=None, max_level=3):
        """
        :param networkx.DiGraph graph:  A graph representing the control flow graph. Note that it does not take
                                        angr.analyses.CFGAccurate or angr.analyses.CFGFast.
        :param int dst_run:             An address specifying the target SimRun.
        :param int dst_stmt_idx:        The target statement index. -1 means executing until the last statement.
        :param str direction:           'backward' or 'forward' slicing. Forward slicing is not yet supported.
        :param angr.Project project:    The project instance.
        :param angr.analyses.CFGBase cfg: the CFG instance. It will be made mandatory later.
        :param bool ignore_sp:          Whether the stack pointer should be ignored in dependency tracking. Any
                                        dependency from/to stack pointers will be ignored if this options is True.
        :param bool ignore_bp:          Whether the base pointer should be ignored or not.
        :param int  max_level:          The maximum number of blocks that we trace back for.
        :return: None
        """

        self._graph = graph
        self._dst_run = dst_run
        self._dst_stmt_idx = dst_stmt_idx
        self._ignore_sp = ignore_sp
        self._ignore_bp = ignore_bp
        self._max_level = max_level

        self._slice = networkx.DiGraph()

        self.project = project
        self._cfg = cfg
        if self._cfg is None:
            # `cfg` is made optional only for compatibility concern. It will be made a positional parameter later.
            raise AngrBladeError('"cfg" must be specified.')

        if not self._in_graph(self._dst_run):
            raise AngrBladeError("The specified SimRun %s doesn't exist in graph." % self._dst_run)

        self._ignored_regs = set()
        if ignored_regs:
            for r in ignored_regs:
                if isinstance(r, (int, long)):
                    self._ignored_regs.add(r)
                else:
                    self._ignored_regs.add(self.project.arch.registers[r][0])

        self._run_cache = { }

        self._traced_runs = set()

        if direction == 'backward':
            self._backward_slice()
        elif direction == 'forward':
            raise AngrBladeError('Forward slicing is not implemented yet')
        else:
            raise AngrBladeError("Unknown slicing direction %s", direction)

    #
    # Properties
    #

    @property
    def slice(self):
        return self._slice

    #
    # Public methods
    #

    def dbg_repr(self):
        s = ""

        block_addrs = list(set([ a for a, _ in self.slice.nodes_iter() ]))

        for block_addr in block_addrs:
            block_str = "IRSB %08x\n" % block_addr

            block = self.project.factory.block(block_addr).vex

            included_stmts = set([ stmt for _, stmt in self.slice.nodes_iter() if _ == block_addr ])

            for i, stmt in enumerate(block.statements):
                block_str += "%02s: %s\n" % ("+" if i in included_stmts else "-",
                                   str(stmt)
                                   )

            s += block_str
            s += "\n"

        return s

    #
    # Private methods
    #

    def _get_irsb(self, v):
        """
        Get the IRSB object from an address, a simuvex.SimProcedure, a simuvex.SimIRSB, or a CFGNode.
        :param v: Can be one of the following: an address, a simuvex.SimProcedure, a simuvex.SimIRSB, or a CFGNode.
        :return: The IRSB instance.
        :rtype: pyvex.IRSB
        """

        if isinstance(v, simuvex.SimProcedure):
            raise AngrBladeSimProcError()

        elif isinstance(v, simuvex.SimIRSB):
            v = v.addr

        elif isinstance(v, CFGNode):
            v = v.addr

        if type(v) in (int, long):
            # Generate an IRSB from self._project

            if v in self._run_cache:
                return self._run_cache[v]

            if self.project:
                irsb = self.project.factory.block(v).vex
                self._run_cache[v] = irsb
                return irsb
            else:
                raise AngrBladeError("Project must be specified if you give me all addresses for SimRuns")

        else:
            raise AngrBladeError('Unsupported SimRun argument type %s', type(v))

    def _get_cfgnode(self, thing):
        """
        Get the CFGNode corresponding to the specific address.

        :param thing: Can be anything that self._normalize() accepts. Usually it's the address of the node
        :return: the CFGNode instance
        :rtype: CFGNode
        """

        return self._cfg.get_any_node(self._get_addr(thing))

    def _get_addr(self, v):
        """
        Get address of the basic block or CFG node specified by v.
        :param v: Can be one of the following: a simuvex.SimIRSB, a simuvex.SimProcedure, a CFGNode, or an address.
        :return: The address.
        :rtype: int
        """

        if isinstance(v, simuvex.SimIRSB) or isinstance(v, simuvex.SimProcedure):
            if type(self._graph.nodes()[0]) in (int, long):
                return v.addr
            else:
                return v
        elif isinstance(v, CFGNode):
            return v.addr
        elif type(v) in (int, long):
            return v
        else:
            raise AngrBladeError('Unsupported SimRun argument type %s' % type(v))

    def _in_graph(self, v):
        return self._get_cfgnode(v) in self._graph

    def _inslice_callback(self, stmt_idx, stmt, infodict):
        tpl = (infodict['irsb_addr'], stmt_idx)
        if 'prev' in infodict and infodict['prev']:
            prev = infodict['prev']
            self._slice.add_edge(tpl, prev)
        else:
            self._slice.add_node(tpl)

        infodict['prev'] = tpl

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
        stmts = self._get_irsb(self._dst_run).statements

        if self._dst_stmt_idx != -1:
            dst_stmt = stmts[self._dst_stmt_idx]

            if type(dst_stmt) is pyvex.IRStmt.Put:
                regs.add(dst_stmt.offset)
            elif type(dst_stmt) is pyvex.IRStmt.WrTmp:
                temps.add(dst_stmt.tmp)
            else:
                raise AngrBladeError('Incorrect type of the specified target statement. We only support Put and WrTmp.')

            prev = (self._get_addr(self._dst_run), self._dst_stmt_idx)
        else:

            next_expr = self._get_irsb(self._dst_run).next

            if type(next_expr) is pyvex.IRExpr.RdTmp:
                temps.add(next_expr.tmp)
            elif type(next_expr) is pyvex.IRExpr.Const:
                # A const doesn't rely on anything else!
                pass
            else:
                raise AngrBladeError('Unsupported type for irsb.next: %s' % type(next_expr))

            # Then we gotta start from the very last statement!
            self._dst_stmt_idx = len(stmts) - 1

            prev = (self._get_addr(self._dst_run), 'default')

        slicer = simuvex.SimSlicer(self.project.arch, stmts,
                                   target_tmps=temps,
                                   target_regs=regs,
                                   target_stack_offsets=None,
                                   inslice_callback=self._inslice_callback,
                                   inslice_callback_infodict={
                                       'irsb_addr':  self._get_irsb(self._dst_run)._addr,
                                       'prev': prev,
                                   })
        regs = slicer.final_regs
        if self._ignore_sp and self.project.arch.sp_offset in regs:
            regs.remove(self.project.arch.sp_offset)
        if self._ignore_bp and self.project.arch.bp_offset in regs:
            regs.remove(self.project.arch.bp_offset)
        for offset in self._ignored_regs:
            if offset in regs:
                regs.remove(offset)

        stack_offsets = slicer.final_stack_offsets

        prev = slicer.inslice_callback_infodict['prev']

        if regs or stack_offsets:
            cfgnode = self._get_cfgnode(self._dst_run)
            in_edges = self._graph.in_edges(cfgnode, data=True)

            for pred, _, data in in_edges:
                if pred not in self._traced_runs:
                    self._traced_runs.add(pred)
                    self._backward_slice_recursive(self._max_level - 1, pred, regs, stack_offsets, prev, data.get('stmt_idx', None))

    def _backward_slice_recursive(self, level, run, regs, stack_offsets, prev, exit_stmt_idx):

        if level <= 0:
            return

        temps = set()
        regs = regs.copy()

        stmts = self._get_irsb(run).statements

        if exit_stmt_idx is None or exit_stmt_idx == 'default':
            # Initialize the temps set with whatever in the `next` attribute of this irsb
            next_expr = self._get_irsb(run).next
            if type(next_expr) is pyvex.IRExpr.RdTmp:
                temps.add(next_expr.tmp)

        else:
            exit_stmt = self._get_irsb(run).statements[exit_stmt_idx]

            if type(exit_stmt.guard) is pyvex.IRExpr.RdTmp:
                temps.add(exit_stmt.guard.tmp)

            # Put it in our slice
            irsb_addr = self._get_addr(run)
            self._inslice_callback(exit_stmt_idx, exit_stmt, {'irsb_addr': irsb_addr, 'prev': prev})
            prev = (irsb_addr, exit_stmt_idx)

        slicer = simuvex.SimSlicer(self.project.arch, stmts,
                                   target_tmps=temps,
                                   target_regs=regs,
                                   target_stack_offsets=stack_offsets,
                                   inslice_callback=self._inslice_callback,
                                   inslice_callback_infodict={
                                       'irsb_addr' : self._get_addr(run),
                                       'prev' : prev
                                   })
        regs = slicer.final_regs

        if self._ignore_sp and self.project.arch.sp_offset in regs:
            regs.remove(self.project.arch.sp_offset)
        if self._ignore_bp and self.project.arch.bp_offset in regs:
            regs.remove(self.project.arch.bp_offset)

        stack_offsets = slicer.final_stack_offsets

        prev = slicer.inslice_callback_infodict['prev']

        if regs or stack_offsets:
            in_edges = self._graph.in_edges(self._get_cfgnode(run), data=True)

            for pred, _, data in in_edges:
                if pred not in self._traced_runs:
                    self._traced_runs.add(pred)
                    self._backward_slice_recursive(level - 1, pred, regs, stack_offsets, prev, data.get('stmt_idx', None))

from .errors import AngrBladeError, AngrBladeSimProcError
from .analyses.cfg_node import CFGNode
