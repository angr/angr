from ailment import BinaryOp, Register, Const
from ailment.statement import Store, Call, Return

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.calling_conventions import SimRegArg
from angr.rust.sim_type import RustSimTypeFunction
from angr.sim_type import SimTypeFunction


class CallingConventionRecovery(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Recover Rust calling convention"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _recover_self_prototype(self):
        ret_sites = set()
        for block in self._graph.nodes:
            if block.statements and isinstance(block.statements[-1], Return):
                ret_sites.add(block)
        blocks = set()
        for ret_site in ret_sites:
            blocks = blocks.union(self._graph.predecessors(ret_site))
        import ipdb

        ipdb.set_trace()

    def _recover_prototype(self, func):
        try:
            cfg = self.project.kb.cfgs.get_most_accurate()
            clinic = self.project.analyses.Clinic(
                cfg=cfg,
                func=func,
                optimization_passes=[],
            )
            graph = clinic.graph
        except:
            graph = None
        if graph and len(func.arguments) and ((a0 := func.arguments[0]) and isinstance(a0, SimRegArg)):
            a0_name = a0.reg_name
            max_size = 0
            alignment = 0
            for block in graph.nodes:
                for stmt in block.statements:
                    if isinstance(stmt, Store):
                        reg = stmt.addr
                        offset = 0
                        if (
                            isinstance(reg, BinaryOp)
                            and isinstance(reg.operands[0], Register)
                            and isinstance(reg.operands[1], Const)
                        ):
                            offset = reg.operands[1].value
                            reg = reg.operands[0]
                        if isinstance(reg, Register) and reg.reg_name == a0_name:
                            max_size = max(max_size, offset + stmt.data.size)
                            alignment = max(alignment, stmt.data.size)
            if max_size and alignment:
                if max_size % alignment != 0:
                    max_size = max_size // alignment * alignment + alignment
                    # TODO: Recover the struct arg definition as well
                prototype = func.prototype
                new_prototype = RustSimTypeFunction(
                    prototype.args,
                    prototype.returnty,
                    label=prototype.label,
                    arg_names=prototype.arg_names,
                    variadic=prototype.variadic,
                )
                new_prototype.is_returnty_struct = True
                func.prototype = new_prototype

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            for stmt in block.statements:
                if isinstance(stmt, Call) and isinstance(stmt.target, Const) and stmt.target.value in self.kb.functions:
                    func = self.kb.functions[stmt.target.value]
                    if (
                        func.size > 0
                        and isinstance(func.prototype, SimTypeFunction)
                        and not isinstance(func.prototype, RustSimTypeFunction)
                    ):
                        self._recover_prototype(func)
                        if isinstance(func.prototype, RustSimTypeFunction):
                            stmt.prototype = func.prototype
        # if "clone" in self._func.name:
        #     self._recover_self_prototype()
