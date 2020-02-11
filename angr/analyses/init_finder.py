
from collections import defaultdict

import pyvex
import claripy

from ..engines.light import SimEngineLight, SimEngineLightVEXMixin
from . import register_analysis
from .analysis import Analysis
from .forward_analysis import FunctionGraphVisitor, SingleNodeGraphVisitor, ForwardAnalysis
from .propagator.vex_vars import VEXTmp


class SimEngineInitFinderVEX(
    SimEngineLightVEXMixin,
    SimEngineLight,
):
    def __init__(self, project, replacements, overlay):
        super().__init__()
        self.project = project
        self.replacements = replacements
        self.overlay = overlay

    #
    # Statement handlers
    #

    def _handle_WrTmp(self, stmt):
        # Don't do anything since constant propagation has already processed it
        return

    def _handle_Put(self, stmt):
        # Don't do anything since constant propagation has already processed it
        return

    def _handle_Store(self, stmt):
        blockloc = self._codeloc(block_only=True)

        if type(stmt.addr) is pyvex.IRExpr.RdTmp:
            addr_tmp = VEXTmp(stmt.addr.tmp)
            if addr_tmp in self.replacements[blockloc]:
                addr_v = self.replacements[blockloc][addr_tmp]
                if isinstance(addr_v, int):
                    # is it writing to a global, uninitialized region?
                    uninit = False
                    obj = self.project.loader.find_object_containing(addr_v)
                    if obj is not None:
                        section = obj.find_section_containing(addr_v)
                        if section is not None:
                            uninit = section.name in {'.bss', }
                        else:
                            segment = obj.find_segment_containing(addr_v)
                            # TODO: which segments are uninitialized?
                    if uninit:
                        # do we know what it is writing?
                        if isinstance(stmt.data, pyvex.IRExpr.RdTmp):
                            data_v = self._expr(stmt.data)
                            if isinstance(data_v, int):
                                print(hex(addr_v), hex(data_v))
                                data_size = self.tyenv.sizeof(stmt.data.tmp)
                                self.overlay.store(addr_v, claripy.BVV(data_v, data_size),
                                                   endness=self.project.arch.memory_endness
                                                   )

    #
    # Expression handlers
    #

    def _handle_Get(self, expr):
        return None

    def _handle_Load(self, expr):
        return None

    def _handle_RdTmp(self, expr):
        blockloc = self._codeloc(block_only=True)

        tmp = VEXTmp(expr.tmp)
        if tmp in self.replacements[blockloc]:
            return self.replacements[blockloc][tmp]
        return None


class InitializationsFinder(ForwardAnalysis, Analysis):
    """
    Finds possible initializations for global data sections and generate an overlay to be used in other analyses later
    on.
    """

    def __init__(self, func=None, func_graph=None, block=None, max_iterations=1, replacements=None, overlay=None):
        if func is not None:
            if block is not None:
                raise ValueError('You cannot specify both "func" and "block".')
            # traversing a function
            graph_visitor = FunctionGraphVisitor(func, func_graph)
            if replacements is None:
                prop = self.project.analyses.Propagator(func=func, func_graph=func_graph)
                replacements = prop.replacements
        elif block is not None:
            # traversing a block
            graph_visitor = SingleNodeGraphVisitor(block)
            if replacements is None:
                prop = self.project.analyses.Propagator(block=block)
                replacements = prop.replacements
        else:
            raise ValueError('Unsupported analysis target.')

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=graph_visitor)

        self._function = func
        self._max_iterations = max_iterations
        self._replacements = replacements

        self._node_iterations = defaultdict(int)

        self._overlay_state = None
        if overlay is not None:
            self.overlay = overlay
        else:
            self._overlay_state = self.project.factory.blank_state()
            self.overlay = self._overlay_state.memory

        self._engine_vex = SimEngineInitFinderVEX(self.project, replacements, self.overlay)
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
        return None

    def _merge_states(self, node, *states):
        return None

    def _run_on_node(self, node, state):

        block = self.project.factory.block(node.addr, node.size, opt_level=0)
        block_key = node.addr
        engine = self._engine_vex

        engine.process(None, block=block, fail_fast=self._fail_fast)

        self._node_iterations[block_key] += 1

        if self._node_iterations[block_key] < self._max_iterations:
            return True, None
        else:
            return False, None

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass


register_analysis(InitializationsFinder, "InitializationsFinder")
