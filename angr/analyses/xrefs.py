
from collections import defaultdict

import pyvex

from ..engines.light import SimEngineLight, SimEngineLightVEXMixin
from .propagator.vex_vars import VEXTmp
from . import register_analysis
from .analysis import Analysis
from .forward_analysis import FunctionGraphVisitor, SingleNodeGraphVisitor, ForwardAnalysis


class XRefType:
    Offset = 0
    Read = 1
    Write = 2


class XRefsState:
    def __init__(self, arch, xrefs=None):
        self.arch = arch

        self.xrefs = set() if xrefs is None else xrefs

    def add_xref(self, xref_type, from_loc, to_loc):
        self.xrefs.add((xref_type, from_loc, to_loc))

    def copy(self):
        return XRefsState(
            self.arch,
            xrefs=self.xrefs.copy(),
        )

    def merge(self, *others):

        state = self.copy()
        for o in others:
            state.xrefs |= o.xrefs
        return state


class SimEngineXRefsVEX(
    SimEngineLightVEXMixin,
    SimEngineLight,
):
    def __init__(self, replacements=None):
        super().__init__()

        self.replacements = replacements if replacements is not None else { }

    #
    # Statement handlers
    #

    def _handle_Put(self, stmt):
        # if there is a Load, get it executed
        self._expr(stmt.data)

    def _handle_StoreG(self, stmt):
        blockloc = self._codeloc(block_only=True)
        if type(stmt.addr) is pyvex.IRExpr.RdTmp:
            addr_tmp = VEXTmp(stmt.addr.tmp)
            if addr_tmp in self.replacements[blockloc]:
                addr = self.replacements[blockloc][addr_tmp]
                self.state.add_xref(XRefType.Write, self._codeloc(), addr)

    def _handle_LoadG(self, stmt):
        # What are we reading?
        blockloc = self._codeloc(block_only=True)
        if type(stmt.addr) is pyvex.IRExpr.RdTmp:
            addr_tmp = VEXTmp(stmt.addr.tmp)
            if addr_tmp in self.replacements[blockloc]:
                addr = self.replacements[blockloc][addr_tmp]
                self.state.add_xref(XRefType.Read, self._codeloc(), addr)

    #
    # Expression handlers
    #

    def _handle_Get(self, expr):
        return None


class XRefsAnalysis(ForwardAnalysis, Analysis):
    """
    XRefsAnalysis recovers in-depths x-refs (cross-references) in disassembly code.

    Here is an example::

    .text:
    000023C8                 LDR     R2, =time_now
    000023CA                 LDR     R3, [R2]
    000023CC                 ADDS    R3, #1
    000023CE                 STR     R3, [R2]
    000023D0                 BX      LR

    .bss:
    1FFF36F4 time_now        % 4

    You will have the following x-refs for time_now::

    23c8 - offset
    23ca - read access
    23ce - write access
    """
    def __init__(self, func=None, func_graph=None, block=None, max_iterations=1, replacements=None):

        if func is not None:
            if block is not None:
                raise ValueError('You cannot specify both "func" and "block".')
            # traversing a function
            graph_visitor = FunctionGraphVisitor(func, func_graph)
            if replacements is None:
                replacements = self.project.analyses.Propagator(func=func, func_graph=func_graph)
        elif block is not None:
            # traversing a block
            graph_visitor = SingleNodeGraphVisitor(block)
            if replacements is None:
                replacements = self.project.analyses.Propagator(block=block)
        else:
            raise ValueError('Unsupported analysis target.')

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=graph_visitor)

        self._function = func
        self._max_iterations = max_iterations
        self._replacements = replacements

        self._node_iterations = defaultdict(int)
        self._states = {}
        self.replacements = None

        self._engine_vex = SimEngineXRefsVEX(replacements=replacements)
        self._engine_ail = None

        self._analyze()

        #
        # Main analysis routines
        #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        return XRefsState(self.project.arch)

    def _merge_states(self, node, *states):
        return states[0].merge(*states[1:])

    def _run_on_node(self, node, state):

        block = self.project.factory.block(node.addr, node.size, opt_level=0)
        block_key = node.addr
        engine = self._engine_vex

        state = state.copy()
        engine.process(state, block=block, fail_fast=self._fail_fast)

        self._node_iterations[block_key] += 1
        self._states[block_key] = state

        if self._node_iterations[block_key] < self._max_iterations:
            return True, state
        else:
            return False, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass


register_analysis(XRefsAnalysis, "XRefs")
