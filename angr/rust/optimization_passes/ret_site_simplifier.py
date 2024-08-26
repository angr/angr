from collections import OrderedDict

from ailment import BinaryOp, Register, Const
from ailment.expression import Convert
from ailment.statement import Store, Return, Jump

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.calling_conventions import SimRegArg
from angr.rust.ailment.expression import Struct
from angr.rust.sim_type import RustSimTypeFunction, RustSimTypeInt, RustSimStruct, RustSimTypeReference


class RetSiteSimplifier(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Simplify function return sites"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def simplify_ret_site(self, ret_site):
        a0_reg_name = self._func.arguments[0].reg_name
        offset_to_size = {}
        fields = OrderedDict()
        data = {}

        statements = ret_site.statements
        # The terminal statement should be Jump/Return/Store
        terminal = ret_site.statements[-1]
        if isinstance(terminal, Jump) or isinstance(terminal, Return):
            statements = ret_site.statements[:-1]
        elif not isinstance(terminal, Store):
            return

        new_statements = []
        pending_statements = []
        queue = list(statements)
        while len(queue):
            stmt = queue.pop()
            if isinstance(stmt, Store):
                reg_name = None
                offset = 0
                addr = stmt.addr
                if isinstance(addr, Convert):
                    addr = addr.operand
                if isinstance(addr, Register):
                    reg_name = addr.reg_name
                elif (
                    isinstance(addr, BinaryOp)
                    and addr.op == "Add"
                    and (isinstance(op0 := addr.operands[0], Register) and isinstance(op1 := addr.operands[1], Const))
                ):
                    reg_name = op0.reg_name
                    offset = op1.value
                if reg_name == a0_reg_name:
                    offset_to_size[offset] = stmt.data.size * self.project.arch.byte_width
                    data[offset] = stmt.data
                    pending_statements.append(stmt)
                    continue
            # Match ends here
            new_statements += queue
            new_statements.append(stmt)
            break

        for offset in sorted(offset_to_size.keys()):
            fields[f"field_{offset}"] = RustSimTypeInt(offset_to_size[offset], signed=False)
        ty = RustSimTypeReference(RustSimStruct(fields, pack=True)).with_arch(self.project.arch)
        prototype = self._func.prototype
        args = [ty] + list(prototype.args[1:])
        new_prototype = RustSimTypeFunction(
            args,
            prototype.returnty,
            label=prototype.label,
            arg_names=prototype.arg_names,
            variadic=prototype.variadic,
            is_returnty_struct=True,
        )
        self._func.prototype = new_prototype
        struct = Struct(0, data, ty.pts_to, **ret_site.statements[0].tags)
        store = list(filter(lambda ele: isinstance(ele.addr, Register), pending_statements))
        if len(store):
            if isinstance(terminal, Return):
                terminal = terminal.copy()
                terminal.ret_exprs = [struct]
                new_statements.append(terminal)
            else:
                ret = Return(idx=0, ret_exprs=[struct], **terminal.tags)
                new_statements.append(ret)
                # store = store[0].copy()
                # store.data = struct
                # store.size = struct.size
                # new_statements.append(store)
                # if isinstance(terminal, Jump):
                #     new_statements.append(terminal)
            ret_site.statements = new_statements
            return True
        return False

    def _analyze(self, cache=None):
        if len(self._func.arguments) and isinstance(self._func.arguments[0], SimRegArg):
            for block in self._graph.nodes:
                if block.statements and isinstance(block.statements[-1], Return):
                    if not self.simplify_ret_site(block):
                        for pred in self._graph.predecessors(block):
                            self.simplify_ret_site(pred)
