from __future__ import annotations
from collections import defaultdict

import claripy
import pyvex

from angr.analyses import visitors, ForwardAnalysis
from ..knowledge_plugins.xrefs import XRef, XRefType
from ..knowledge_plugins.functions.function import Function
from ..engines.light import SimEngineLight, SimEngineLightVEXMixin
from .propagator.vex_vars import VEXTmp
from .propagator.values import Top
from . import register_analysis, PropagatorAnalysis
from .analysis import Analysis


class SimEngineXRefsVEX(
    SimEngineLightVEXMixin,
    SimEngineLight,
):
    """
    The VEX engine class for XRefs analysis.
    """

    def __init__(self, xref_manager, project=None, replacements=None):
        super().__init__()
        self.project = project
        self.xref_manager = xref_manager
        self.replacements = replacements if replacements is not None else {}

    def add_xref(self, xref_type, from_loc, to_loc):
        self.xref_manager.add_xref(
            XRef(
                ins_addr=from_loc.ins_addr,
                block_addr=from_loc.block_addr,
                stmt_idx=from_loc.stmt_idx,
                dst=to_loc,
                xref_type=xref_type,
            )
        )

    @staticmethod
    def extract_value_if_concrete(expr) -> int | None:
        """
        Extract the concrete value from expr if it is a concrete claripy AST.

        :param expr:    A claripy AST.
        :return:        A concrete value or None if nothing concrete can be extracted.
        """

        if isinstance(expr, claripy.ast.Base) and expr.op == "BVV":
            return expr.args[0]
        return None

    #
    # Statement handlers
    #

    def _handle_WrTmp(self, stmt):
        # Don't execute the tmp write since it has been done during constant propagation
        self._expr(stmt.data)
        if type(stmt.data) is pyvex.IRExpr.Load:
            self._handle_data_offset_refs(stmt.tmp)

    def _handle_Put(self, stmt):
        # if there is a Load, get it executed
        self._expr(stmt.data)

    def _handle_Store(self, stmt):
        if isinstance(stmt.addr, pyvex.IRExpr.RdTmp):
            addr_tmp = VEXTmp(stmt.addr.tmp)
            blockloc = self._codeloc(block_only=True)
            if addr_tmp in self.replacements[blockloc] and not isinstance(self.replacements[blockloc][addr_tmp], Top):
                addr = self.replacements[blockloc][addr_tmp]
                addr_v = self.extract_value_if_concrete(addr)
                if addr_v is not None:
                    self.add_xref(XRefType.Write, self._codeloc(), addr_v)
        elif isinstance(stmt.addr, pyvex.IRExpr.Const):
            addr = stmt.addr.con.value
            self.add_xref(XRefType.Write, self._codeloc(), addr)

    def _handle_StoreG(self, stmt):
        blockloc = self._codeloc(block_only=True)
        if type(stmt.addr) is pyvex.IRExpr.RdTmp:
            addr_tmp = VEXTmp(stmt.addr.tmp)
            if addr_tmp in self.replacements[blockloc] and not isinstance(self.replacements[blockloc][addr_tmp], Top):
                addr = self.replacements[blockloc][addr_tmp]
                addr_v = self.extract_value_if_concrete(addr)
                if addr_v is not None:
                    self.add_xref(XRefType.Write, self._codeloc(), addr_v)

    def _handle_LoadG(self, stmt):
        # What are we reading?
        blockloc = self._codeloc(block_only=True)
        if type(stmt.addr) is pyvex.IRExpr.RdTmp:
            addr_tmp = VEXTmp(stmt.addr.tmp)
            if addr_tmp in self.replacements[blockloc] and not isinstance(self.replacements[blockloc][addr_tmp], Top):
                addr = self.replacements[blockloc][addr_tmp]
                addr_v = self.extract_value_if_concrete(addr)
                if addr_v is not None:
                    self.add_xref(XRefType.Read, self._codeloc(), addr_v)
        self._handle_data_offset_refs(stmt.dst)

    def _handle_LLSC(self, stmt: pyvex.IRStmt.LLSC):
        blockloc = self._codeloc(block_only=True)
        if isinstance(stmt.addr, pyvex.IRExpr.RdTmp):
            addr_tmp = VEXTmp(stmt.addr.tmp)
            if addr_tmp in self.replacements[blockloc]:
                addr = self.replacements[blockloc][addr_tmp]
                addr_v = self.extract_value_if_concrete(addr)
                if addr_v is not None:
                    # load-link in true case
                    xref_type = XRefType.Read if stmt.storedata is None else XRefType.Write
                    self.add_xref(xref_type, self._codeloc(), addr_v)

    def _handle_data_offset_refs(self, data_tmp):
        # is this thing a pointer?
        # If so, produce the ida-style "Offset" XRefs.
        blockloc = self._codeloc(block_only=True)
        tmp = VEXTmp(data_tmp)
        if tmp in self.replacements[blockloc] and not isinstance(self.replacements[blockloc][tmp], Top):
            data = self.replacements[blockloc][tmp]
            # Is this thing not an integer? If so, get out of here
            # e.g., you can't find_object_containing on an SPOffset
            data_v = self.extract_value_if_concrete(data)
            if data_v is None:
                return
            # HACK: Avoid spamming Xrefs if the binary is loaded at 0
            # e.g., firmware!
            # (magic value chosen due to length of CM EVT)
            if self.project.loader.find_object_containing(data_v) is not None and data_v > 0x200:
                self.add_xref(XRefType.Offset, self._codeloc(), data_v)

    #
    # Expression handlers
    #

    def _handle_Get(self, expr):
        return None

    def _handle_Load(self, expr):
        blockloc = self._codeloc(block_only=True)
        if type(expr.addr) is pyvex.IRExpr.RdTmp:
            addr_tmp = VEXTmp(expr.addr.tmp)
            if addr_tmp in self.replacements[blockloc] and not isinstance(self.replacements[blockloc][addr_tmp], Top):
                addr = self.replacements[blockloc][addr_tmp]
                addr_v = self.extract_value_if_concrete(addr)
                if addr_v is not None:
                    self.add_xref(XRefType.Read, self._codeloc(), addr_v)
        elif type(expr.addr) is pyvex.IRExpr.Const:
            addr = expr.addr.con.value
            self.add_xref(XRefType.Read, self._codeloc(), addr)

    def _handle_CCall(self, expr):
        return None

    def _handle_function(self, func):
        # pylint: disable=unused-argument,no-self-use
        return None  # TODO: Maybe add an execute-type XRef?


class XRefsAnalysis(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
    """
    XRefsAnalysis recovers in-depth x-refs (cross-references) in disassembly code.

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
            if not isinstance(func, Function):
                func = self.kb.functions[func]
            if block is not None:
                raise ValueError('You cannot specify both "func" and "block".')
            # traversing a function
            graph_visitor = visitors.FunctionGraphVisitor(func, func_graph)
            if replacements is None:
                prop = self.project.analyses[PropagatorAnalysis].prep()(func=func, func_graph=func_graph)
                replacements = prop.model.replacements
        elif block is not None:
            # traversing a block
            graph_visitor = visitors.SingleNodeGraphVisitor(block)
            if replacements is None:
                prop = self.project.analyses[PropagatorAnalysis].prep()(block=block)
                replacements = prop.model.replacements
        else:
            raise ValueError("Unsupported analysis target.")

        ForwardAnalysis.__init__(
            self, order_jobs=True, allow_merging=True, allow_widening=False, graph_visitor=graph_visitor
        )

        self._function = func
        self._max_iterations = max_iterations
        self._replacements = replacements

        self._node_iterations = defaultdict(int)

        self._engine_vex = SimEngineXRefsVEX(self.kb.xrefs, project=self.project, replacements=replacements)
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
        if block.size == 0:
            # VEX couldn't decode it
            return False, None
        block_key = node.addr
        engine = self._engine_vex

        engine.process(None, block=block, fail_fast=self._fail_fast)

        self._node_iterations[block_key] += 1

        if self._node_iterations[block_key] < self._max_iterations:
            return True, None
        return False, None

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass


register_analysis(XRefsAnalysis, "XRefs")
