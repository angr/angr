import networkx

import pyvex
import simuvex

class Blade(object):
    '''
    Blade is a light-weight program slicer that works with networkx DiGraph containing SimIRSBs.
    It is meant to be used in angr for small or on-the-fly analyses.
    '''
    def __init__(self, graph, dst_run, dst_stmt_idx, direction='backward', project=None):
        self._graph = graph
        self._dst_run = dst_run
        self._dst_stmt_idx = dst_stmt_idx

        self._slice = networkx.DiGraph()

        if not self._in_graph(self._dst_run):
            raise AngrBladeError("The specified SimRun %s doesn't exist in graph.")

        self.project = project

        self._run_cache = { }

        self._traced_runs = set()

        if direction == 'backward':
            self._backward_slice()
        elif direction == 'forward':
            raise AngrBladeError('Forward slicing is not implemented yet')
        else:
            raise AngrBladeError("Unknown slicing direction %s", direction)

    def _get_run(self, v):
        if isinstance(v, simuvex.SimIRSB) or isinstance(v, simuvex.SimProcedure):
            return v

        elif type(v) in (int, long):
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

    def _normalize(self, v):
        if isinstance(v, simuvex.SimIRSB) or isinstance(v, simuvex.SimProcedure):
            if type(self._graph.nodes()[0]) in (int, long):
                return v.addr
            else:
                return v
        elif type(v) in (int, long):
            return v
        else:
            raise AngrBladeError('Unsupported SimRun argument type %s', type(v))

    def _in_graph(self, v):
        return self._normalize(v) in self._graph


    @property
    def slice(self):
        return self._slice

    def _inslice_callback(self, stmt_idx, stmt, infodict):
        tpl = (infodict['irsb_addr'], stmt_idx)
        if 'prev' in infodict and infodict['prev']:
            prev = infodict['prev']
            self._slice.add_edge(tpl, prev)
        else:
            self._slice.add_node(tpl)

        infodict['prev'] = tpl

    def _backward_slice(self):
        '''
        Backward slicing.

        We support the following IRStmts:
        # WrTmp
        # Put

        We support the following IRExprs:
        # Get
        # RdTmp
        # Const

        :return:
        '''

        temps = set()
        regs = set()

        # Retrieve the target: are we slicing from a register(IRStmt.Put), or a temp(IRStmt.WrTmp)?
        stmts = self._get_run(self._dst_run).irsb.statements

        if self._dst_stmt_idx != -1:
            dst_stmt = stmts[self._dst_stmt_idx]

            if type(dst_stmt) is pyvex.IRStmt.Put:
                regs.add(dst_stmt.offset)
            elif type(dst_stmt) is pyvex.IRStmt.WrTmp:
                temps.add(dst_stmt.tmp)
            else:
                raise AngrBladeError('Incorrect type of the specified target statement. We only support Put and WrTmp.')

        else:
            next_expr = self._get_run(self._dst_run).irsb.next

            if type(next_expr) is pyvex.IRExpr.RdTmp:
                temps.add(next_expr.tmp)
            elif type(next_expr) is pyvex.IRExpr.Const:
                # A const doesn't rely on anything else!
                pass
            else:
                raise AngrBladeError('Unsupported type for irsb.next: %s' % type(next_expr))

            # Then we gotta start from the very last statement!
            self._dst_stmt_idx = len(stmts) - 1

        slicer = simuvex.SimSlicer(stmts, temps, regs,
                                   inslice_callback=self._inslice_callback,
                                   inslice_callback_infodict={
                                       'irsb_addr':  self._get_run(self._dst_run).addr
                                   })
        regs = slicer.final_regs

        prev = slicer.inslice_callback_infodict['prev']

        if regs:
            predecessors = self._graph.predecessors(self._normalize(self._dst_run))

            for p in predecessors:
                if p not in self._traced_runs:
                    self._traced_runs.add(p)
                    self._backward_slice_recursive(p, regs, prev)

    def _backward_slice_recursive(self, run, regs, prev):
        temps = set()
        regs = regs.copy()

        stmts = self._get_run(run).irsb.statements

        # Initialize the temps set with whatever in the `next` attribute of this irsb
        next_expr = self._get_run(run).irsb.next
        if type(next_expr) is pyvex.IRExpr.RdTmp:
            temps.add(next_expr.tmp)

        slicer = simuvex.SimSlicer(stmts, temps, regs,
                                   inslice_callback=self._inslice_callback,
                                   inslice_callback_infodict={
                                       'irsb_addr' : self._get_run(run).addr,
                                       'prev' : prev
                                   })
        regs = slicer.final_regs

        prev = slicer.inslice_callback_infodict['prev']

        if regs:
            predecessors = self._graph.predecessors(self._normalize(run))

            for p in predecessors:
                if p not in self._traced_runs:
                    self._traced_runs.add(p)
                    self._backward_slice_recursive(p, regs, prev)

    #
    # Backward slice IRStmt handlers
    #

    def _backward_handler_stmt_WrTmp(self, stmt, temps, regs):
        tmp = stmt.tmp

        if tmp not in temps:
            return False

        temps.remove(tmp)

        self._backward_handler_expr(stmt.data, temps, regs)

        return True

    def _backward_handler_stmt_Put(self, stmt, temps, regs):
        reg = stmt.offset

        if reg in regs:
            regs.remove(reg)

            self._backward_handler_expr(stmt.data, temps, regs)

            return True

        else:
            return False

    #
    # Backward slice IRExpr handlers
    #

    def _backward_handler_expr(self, expr, temps, regs):
        funcname = "_backward_handler_expr_%s" % type(expr).__name__
        in_slice = False
        if hasattr(self, funcname):
            in_slice = getattr(self, funcname)(expr, temps, regs)

        return in_slice

    def _backward_handler_expr_RdTmp(self, expr, temps, regs):
        tmp = expr.tmp

        temps.add(tmp)

    def _backward_handler_expr_Get(self, expr, temps, regs):
        reg = expr.offset

        regs.add(reg)

    def _backward_handler_expr_Load(self, expr, temps, regs):
        addr = expr.addr

        if type(addr) is pyvex.IRExpr.RdTmp:
            # FIXME: Process other types
            self._backward_handler_expr(addr, temps, regs)

from .errors import AngrBladeError
