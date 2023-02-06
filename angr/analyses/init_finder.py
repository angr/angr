from collections import defaultdict

from cle.loader import MetaELF
from cle.backends import Section, Segment
import pyvex
import claripy

from ..engines.light import SimEngineLight, SimEngineLightVEXMixin
from . import register_analysis, PropagatorAnalysis
from .analysis import Analysis
from .forward_analysis import FunctionGraphVisitor, SingleNodeGraphVisitor, ForwardAnalysis
from .propagator.vex_vars import VEXTmp


class SimEngineInitFinderVEX(
    SimEngineLightVEXMixin,
    SimEngineLight,
):
    def __init__(self, project, replacements, overlay, pointers_only=False):
        super().__init__()
        self.project = project
        self.replacements = replacements
        self.overlay = overlay
        self.pointers_only = pointers_only

    #
    # Utils
    #

    @staticmethod
    def is_concrete(expr) -> bool:
        if isinstance(expr, claripy.ast.Base) and expr.op == "BVV":
            return True
        if isinstance(expr, int):
            return True
        return False

    def _is_addr_uninitialized(self, addr):
        # is it writing to a global, uninitialized region?

        if isinstance(addr, claripy.ast.Base):
            addr = addr.args[0]

        obj = self.project.loader.find_object_containing(addr)
        if obj is not None:
            if not obj.has_memory:
                # Objects without memory are definitely uninitialized
                return True
            section: Section = obj.find_section_containing(addr)
            if section is not None:
                return section.name in {
                    ".bss",
                }

            if isinstance(obj, MetaELF):
                # for ELFs, if p_memsz >= p_filesz, the extra bytes are considered NOBITS
                # https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/gjpww/index.html
                segment: Segment = obj.find_segment_containing(addr)
                if segment is not None and segment.memsize > segment.filesize:
                    return segment.vaddr + segment.filesize <= addr < segment.vaddr + segment.memsize
        return False

    def _is_pointer(self, addr):
        if isinstance(addr, claripy.ast.Base):
            addr = addr.args[0]

        if isinstance(addr, int):
            if addr > 0x400:
                return self.project.loader.find_object_containing(addr) is not None
        return False

    #
    # Statement handlers
    #

    def _handle_function(self, *args, **kwargs):
        pass

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
                if self.is_concrete(addr_v) and self._is_addr_uninitialized(addr_v):
                    # do we know what it is writing?
                    if isinstance(stmt.data, pyvex.IRExpr.RdTmp):
                        data_v = self._expr(stmt.data)
                        if self.is_concrete(data_v):
                            if isinstance(data_v, int):
                                data_size = self.tyenv.sizeof(stmt.data.tmp)
                                data_v = claripy.BVV(data_v, data_size)
                            if not self.pointers_only or self._is_pointer(data_v):
                                self.overlay.store(addr_v, data_v, endness=self.project.arch.memory_endness)

    def _handle_StoreG(self, stmt):
        blockloc = self._codeloc(block_only=True)
        repl = self.replacements[blockloc]

        if type(stmt.guard) is pyvex.IRExpr.RdTmp:
            # check if guard is true
            tmp = VEXTmp(stmt.guard.tmp)
            if tmp not in repl or repl[tmp] is not True:
                return
        if type(stmt.addr) is pyvex.IRExpr.RdTmp:
            tmp = VEXTmp(stmt.addr.tmp)
            if tmp not in repl:
                return
            addr_v = repl[tmp]
        else:
            return

        if not (self.is_concrete(addr_v) and self._is_addr_uninitialized(addr_v)):
            return

        if type(stmt.data) is pyvex.IRExpr.RdTmp:
            data_v = self._expr(stmt.data)
        else:
            return

        if self.is_concrete(data_v):
            if isinstance(data_v, int):
                data_size = self.tyenv.sizeof(stmt.data.tmp)
                data_v = claripy.BVV(data_v, data_size)

            if not self.pointers_only or self._is_pointer(data_v):
                self.overlay.store(addr_v, data_v, endness=self.project.arch.memory_endness)

    #
    # Expression handlers
    #

    def _handle_Get(self, expr):
        return None

    def _handle_Load(self, expr):
        return None

    def _handle_LoadG(self, stmt):
        return None

    def _handle_RdTmp(self, expr):
        blockloc = self._codeloc(block_only=True)

        tmp = VEXTmp(expr.tmp)
        if tmp in self.replacements[blockloc]:
            return self.replacements[blockloc][tmp]
        return None


class InitializationFinder(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
    """
    Finds possible initializations for global data sections and generate an overlay to be used in other analyses later
    on.
    """

    def __init__(
        self,
        func=None,
        func_graph=None,
        block=None,
        max_iterations=1,
        replacements=None,
        overlay=None,
        pointers_only=False,
    ):
        self.pointers_only = pointers_only
        if func is not None:
            if block is not None:
                raise ValueError('You cannot specify both "func" and "block".')
            # traversing a function
            graph_visitor = FunctionGraphVisitor(func, func_graph)
            if replacements is None:
                prop = self.project.analyses[PropagatorAnalysis].prep()(
                    func=func, func_graph=func_graph, base_state=self.project.factory.blank_state()
                )
                replacements = prop.replacements
        elif block is not None:
            # traversing a block
            graph_visitor = SingleNodeGraphVisitor(block)
            if replacements is None:
                prop = self.project.analyses[PropagatorAnalysis].prep()(
                    block=block, base_state=self.project.factory.blank_state()
                )
                replacements = prop.replacements
        else:
            raise ValueError("Unsupported analysis target.")

        ForwardAnalysis.__init__(
            self, order_jobs=True, allow_merging=True, allow_widening=False, graph_visitor=graph_visitor
        )

        self._function = func
        self._max_iterations = max_iterations
        self._replacements = replacements

        self._node_iterations = defaultdict(int)

        self.overlay_state = None
        if overlay is not None:
            self.overlay = overlay
        else:
            self.overlay_state = self.project.factory.blank_state()
            self.overlay = self.overlay_state.memory

        self._engine_vex = SimEngineInitFinderVEX(
            self.project, replacements, self.overlay, pointers_only=self.pointers_only
        )
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
        block = self.project.factory.block(node.addr, node.size, opt_level=1, cross_insn_opt=False)
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


register_analysis(InitializationFinder, "InitializationFinder")
register_analysis(InitializationFinder, "InitFinder")
