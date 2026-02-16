from collections import defaultdict

from angr.ailment import AILBlockViewer
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, VirtualVariable, Tmp
from angr.ailment.statement import Call, Return, Statement, Store
from angr.rust.mixins import CFAMixin, DFAMixin, SRDAMixin
from angr.rust.utils.ail import CallVisitor, unwrap_stack_vvar_reference

from .pathfinder import Pathfinder

# ---------------------------------------------------------------------------
# Sub-collectors
# ---------------------------------------------------------------------------


class MemoryWriteCollector(AILBlockViewer):
    """
    Walk ret2arg0 paths and collect direct memory writes (Store statements)
    to parameter-backed addresses.
    """

    def __init__(self, fc: "FactCollector"):
        super().__init__()
        self._fc = fc

        self._path = None
        self._path_srda = None

    def collect(self):
        paths = Pathfinder(self._fc.graph, self._fc).find_ret2arg0_paths(remove_phi=True)

        for path in paths:
            self._walk_path(path)

    def _walk_path(self, path):
        self._path = path
        self._path_srda = SRDAMixin(self._fc.func, Pathfinder.path_to_graph(path), self._fc.project)
        for block in path:
            self.walk(block)

    def _add_memory_write(self, arg_idx, offset, expr):
        path = self._path
        if path not in self._fc.memory_writes[arg_idx]:
            self._fc.memory_writes[arg_idx][path] = {}
        if isinstance(expr, VirtualVariable):
            expr = self._path_srda.get_terminal_vvar_value(expr) or expr
        self._fc.memory_writes[arg_idx][path][offset] = (expr, self._fc.func.addr)

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None):
        addr = stmt.addr
        offset = 0
        if (
            isinstance(addr, BinaryOp)
            and addr.op == "Add"
            and isinstance(addr.operands[0], VirtualVariable)
            and isinstance(addr.operands[1], Const)
        ):
            offset = addr.operands[1].value
            addr = addr.operands[0]
        if isinstance(addr, VirtualVariable):
            addr = self._fc.get_terminal_vvar(addr)
        if isinstance(addr, VirtualVariable) and addr.was_parameter:
            if addr.varid == 0:
                self._fc.has_write_to_arg0 = True
            self._add_memory_write(addr.varid, offset, stmt.data)


class CalleeWriteCollector:
    """
    Visit all calls in the function graph. When a call forwards the current
    function's arg0 to a callee, recursively analyze the callee and merge
    its memory writes into the current function's facts.
    """

    def __init__(self, fc: "FactCollector"):
        self._fc = fc

    def collect(self):
        visitor = CallVisitor(self._handle_call)
        visitor.visit(self._fc.graph)

    def _handle_call(self, call: Call, block: Block, stmt: Statement, is_expr: bool):
        if not isinstance(call.target, Const) or call.target.value not in self._fc.project.kb.functions:
            return
        if not self._call_forwards_arg0(call):
            return
        func = self._fc.project.kb.functions[call.target.value]
        if func.name == "memcpy" and len(call.args) == 3 and isinstance(call.args[2], Const):
            tmp = Tmp(None, None, 0, call.args[2].value * self._fc.project.arch.byte_width)
            self._fc.has_write_to_arg0 = True
            # Use a single-block path as the key, consistent with memory_writes keying.
            path = (block,)
            if path not in self._fc.memory_writes[0]:
                self._fc.memory_writes[0][path] = {}
            self._fc.memory_writes[0][path][0] = (tmp, self._fc.func.addr)
        elif func.normalized and func.size and self._fc.analysis.depth < self._fc.analysis.max_depth:
            result = self._fc.project.analyses.RustCallingConvention(
                func,
                callsite_path=Pathfinder(self._fc.graph).find_backward_path(block),
                depth=self._fc.analysis.depth + 1,
                max_depth=self._fc.analysis.max_depth,
            )
            self._fc.memory_writes[0] |= result.model.memory_writes[0]
            if result.model.has_write_to_arg0:
                self._fc.has_write_to_arg0 = True

    def _call_forwards_arg0(self, call: Call) -> bool:
        """Does this call pass the current function's arg0 (parameter vvar 0) as its first argument?"""
        if not call.args:
            return False
        arg0 = call.args[0]
        if isinstance(arg0, VirtualVariable):
            vvar = self._fc.get_terminal_vvar(arg0)
            return isinstance(vvar, VirtualVariable) and vvar.was_parameter and vvar.varid == 0
        return False


class ConstRetValueCollector:
    """
    Iterate over return blocks and collect constant return values,
    including values propagated through tail calls.
    """

    def __init__(self, fc: "FactCollector"):
        self._fc = fc

    def _resolve_const_values(self, expr):
        """Resolve an expression to a set of constant integer values."""
        if isinstance(expr, Const):
            return {expr.value}
        if isinstance(expr, VirtualVariable):
            return {value.value for value in self._fc.get_terminal_vvar_values(expr) if isinstance(value, Const)}
        return set()

    def _collect_tail_calls(self, expr, block):
        """Find and process any tail calls in expr."""
        if isinstance(expr, Call):
            self._collect_from_tail_call(expr, block)
        elif isinstance(expr, VirtualVariable):
            for value in self._fc.get_terminal_vvar_values(expr):
                if isinstance(value, Call):
                    self._collect_from_tail_call(value, block)

    def collect(self):
        for block in self._fc.graph.nodes:
            if not block.statements or not isinstance(block.statements[-1], Return):
                continue
            ret_stmt: Return = block.statements[-1]
            if not ret_stmt.ret_exprs:
                continue

            ret_expr = ret_stmt.ret_exprs[0]
            overflow_ret_expr = ret_stmt.ret_exprs[1] if len(ret_stmt.ret_exprs) >= 2 else None

            # Handle tail calls (merges callee's tuples directly)
            self._collect_tail_calls(ret_expr, block)

            # Resolve const values and build (ret_value, overflow_ret_value|None) tuples
            ret_values = self._resolve_const_values(ret_expr)
            overflow_ret_values = (self._resolve_const_values(overflow_ret_expr) if overflow_ret_expr else set()) or {None}
            for ret_value in ret_values:
                for overflow_ret_value in overflow_ret_values:
                    self._fc.const_ret_values.add((ret_value, overflow_ret_value))

    def _collect_from_tail_call(self, call: Call, ret_block: Block):
        if not isinstance(call.target, Const) or call.target.value not in self._fc.project.kb.functions:
            return
        func = self._fc.project.kb.functions[call.target.value]
        if not (func.normalized and func.size and self._fc.analysis.depth < self._fc.analysis.max_depth):
            return
        def_block, _ = self._fc.get_def_block_and_stmt(call)
        if def_block is None:
            def_block = ret_block
        result = self._fc.project.analyses.RustCallingConvention(
            func,
            callsite_path=Pathfinder(self._fc.graph).find_backward_path(def_block),
            depth=self._fc.analysis.depth + 1,
            max_depth=self._fc.analysis.max_depth,
        )
        self._fc.const_ret_values |= result.model.const_ret_values


class CallsiteFactCollector:
    """
    From the *caller* context (callsite_path), collect memory writes to
    stack regions that initialize struct arguments passed by reference.
    """

    def __init__(self, fc: "FactCollector"):
        self._fc = fc

    def collect(self):
        callsite_path = self._fc.analysis.callsite_path
        if not callsite_path:
            return
        call = self._fc.terminal_call(callsite_path[-1])
        if not call or not call.args:
            return

        stack_offsets = sorted({vvar.stack_offset for arg in call.args if (vvar := unwrap_stack_vvar_reference(arg))})
        if not stack_offsets:
            return

        next_offset = {}
        for i in range(len(stack_offsets) - 1):
            next_offset[stack_offsets[i]] = stack_offsets[i + 1]
        next_offset[stack_offsets[-1]] = None

        stack_defs = DFAMixin(Pathfinder.path_to_graph(callsite_path)).collect_callsite_stack_defs(callsite_path[-1])

        for idx, arg in enumerate(call.args):
            vvar = unwrap_stack_vvar_reference(arg)
            if vvar is None:
                continue
            referenced_offsets = set()
            cur = vvar.stack_offset
            upper = next_offset[cur]
            while (upper is None or cur < upper) and cur not in referenced_offsets and cur in stack_defs:
                stack_def = stack_defs[cur]
                self._add_callsite_memory_write(idx, stack_def.block, cur - vvar.stack_offset, stack_def.data)
                if ref := unwrap_stack_vvar_reference(stack_def.data):
                    referenced_offsets.add(ref.stack_offset)
                cur += stack_def.data.size

    def _add_callsite_memory_write(self, arg_idx, block, offset, expr):
        if block not in self._fc.callsite_memory_writes[arg_idx]:
            self._fc.callsite_memory_writes[arg_idx][block] = {}
        self._fc.callsite_memory_writes[arg_idx][block][offset] = (expr, self._fc.func.addr)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class FactCollector(CFAMixin, SRDAMixin, DFAMixin):
    """
    Orchestrator that runs all sub-collectors and exposes the combined results.

    Sub-collectors write back to this object's fields; when collection is done,
    the results are flushed to the model.
    """

    def __init__(self, analysis):
        self.analysis = analysis
        self.project = analysis.project
        self.graph = analysis.graph
        self.func = analysis.func

        CFAMixin.__init__(self, self.graph, self.project)
        SRDAMixin.__init__(self, self.func, self.graph, self.project)
        DFAMixin.__init__(self, self.graph)

        # Accumulated facts — sub-collectors write directly to these.
        self.memory_writes = defaultdict(dict)
        self.callsite_memory_writes = defaultdict(dict)
        self.has_write_to_arg0 = False
        self.const_ret_values = set()  # set of (ret_value, overflow_ret_value|None) tuples

    def collect(self):
        """Run all sub-collectors, then flush results to the model."""
        MemoryWriteCollector(self).collect()
        CalleeWriteCollector(self).collect()
        ConstRetValueCollector(self).collect()
        CallsiteFactCollector(self).collect()

        self._flush_to_model()

    def _flush_to_model(self):
        self.analysis.model.memory_writes = self.memory_writes
        self.analysis.model.callsite_memory_writes = self.callsite_memory_writes
        self.analysis.model.has_write_to_arg0 = self.has_write_to_arg0
        self.analysis.model.const_ret_values = self.const_ret_values
