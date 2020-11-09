import logging

from ailment import Expr, Stmt

from ....engines.light import SimEngineLightAILMixin
from ....engines.light import SimEngineLight

_l = logging.getLogger(name=__name__)


class SimplifierAILState:
    def __init__(self, arch, variables=None):
        self.arch = arch
        self._variables = {} if variables is None else variables

    def __repr__(self):
        return "<SimplifierAILState>"

    def copy(self):
        rd = SimplifierAILState(
            self.arch,
            variables=self._variables.copy(),
        )

        return rd

    def merge(self, *others):
        raise NotImplementedError()

    def store_variable(self, old, new):
        if new is not None:
            self._variables[old] = new

    def get_variable(self, old):
        return self._variables.get(old, None)

    def remove_variable(self, old):
        self._variables.pop(old, None)

    def filter_variables(self, atom):
        keys_to_remove = set()

        for k, v in self._variables.items():
            if isinstance(v, Expr.Expression) and (v == atom or v.has_atom(atom)):
                keys_to_remove.add(k)

        for k in keys_to_remove:
            self._variables.pop(k)


class SimplifierAILEngine(
    SimEngineLightAILMixin,
    SimEngineLight,
    ):

    def __init__(self): #pylint: disable=useless-super-delegation

        super().__init__()

    def process(self, state, *args, **kwargs):

        # override SimEngineLight.process() so that we can return the processed block
        super().process(state, *args, **kwargs)
        return self.block

    def _process_Stmt(self, whitelist=None):

        if whitelist is not None:
            whitelist = set(whitelist)

        for stmt_idx, stmt in enumerate(self.block.statements):
            if whitelist is not None and stmt_idx not in whitelist:
                continue

            new_stmt = self._ail_handle_Stmt(stmt)
            if new_stmt and new_stmt != stmt:
                self.block.statements[stmt_idx] = new_stmt

    # handle stmt
    def _ail_handle_Stmt(self, stmt):
        handler = "_ail_handle_%s" % type(stmt).__name__
        if hasattr(self, handler):
            return getattr(self, handler)(stmt)
        else:
            _l.warning('Unsupported statement type %s.', type(stmt).__name__)
            return stmt

    def _ail_handle_Assignment(self, stmt):

        src = self._expr(stmt.src)
        dst = self._expr(stmt.dst)

        if isinstance(dst, Expr.Register) and not src.has_atom(dst):
            self.state.filter_variables(dst)
            self.state.store_variable(dst, src)

        if (src, dst) != (stmt.src, stmt.dst):
            return Stmt.Assignment(stmt.idx, dst, src, **stmt.tags)

        return stmt

    def _ail_handle_Store(self, stmt):

        addr = self._expr(stmt.addr)
        data = self._expr(stmt.data)

        # replace
        if(addr, data) != (stmt.addr, stmt.data):
            return Stmt.Store(stmt.idx, addr, data, stmt.size,
                              stmt.endness, variable=stmt.variable, **stmt.tags)

        return stmt

    def _ail_handle_Jump(self, stmt):

        target = self._expr(stmt.target)

        return Stmt.Jump(stmt.idx, target, **stmt.tags)

    def _ail_handle_ConditionalJump(self, stmt): #pylint: disable=no-self-use
        return stmt

    def _ail_handle_Call(self, stmt):

        target = self._expr(stmt.target)

        new_args = None

        if stmt.args:
            new_args = [ ]
            for arg in stmt.args:
                new_arg = self._expr(arg)
                new_args.append(new_arg)

        return Stmt.Call(stmt.idx, target, calling_convention=stmt.calling_convention,
                         prototype=stmt.prototype, args=new_args, ret_expr=stmt.ret_expr,
                         **stmt.tags)

    def _ail_handle_Load(self, expr):

        addr = self._expr(expr.addr)

        if addr != expr.addr:
            return Expr.Load(expr.idx, addr, expr.size, expr.endness, **expr.tags)
        return expr

    # handle expr

    def _expr(self, expr):

        handler = "_ail_handle_%s" % type(expr).__name__
        if hasattr(self, handler):
            v = getattr(self, handler)(expr)
            if v is None:
                return expr
            return v
        _l.warning('Unsupported expression type %s.', type(expr).__name__)
        return expr

    def _ail_handle_StackBaseOffset(self, expr):  # pylint:disable=no-self-use
        return expr

    def _ail_handle_Register(self, expr):

        new_expr = self.state.get_variable(expr)
        # TODO if got new expr here, former assignment can be killed
        return expr if new_expr is None else new_expr

    def _ail_handle_Mul(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        if (operand_0, operand_1) != (expr.operands[0], expr.operands[1]):
            return Expr.BinaryOp(expr.idx, 'Mul', [operand_0, operand_1], expr.signed, **expr.tags)
        return expr

    def _ail_handle_Const(self, expr):
        return expr

    def _ail_handle_Convert(self, expr: Expr.Convert):
        operand_expr = self._expr(expr.operand)
        # import ipdb; ipdb.set_trace()

        if type(operand_expr) is Expr.Convert:
            if expr.from_bits == operand_expr.to_bits and expr.to_bits == operand_expr.from_bits:
                # eliminate the redundant Convert
                return operand_expr.operand
            else:
                return Expr.Convert(expr.idx, operand_expr.from_bits, expr.to_bits, expr.is_signed,
                                    operand_expr.operand, **expr.tags)
        elif type(operand_expr) is Expr.Const:
            # do the conversion right away
            value = operand_expr.value
            mask = (2 ** expr.to_bits) - 1
            value &= mask
            return Expr.Const(expr.idx, operand_expr.variable, value, expr.to_bits, **expr.tags)
        elif type(operand_expr) is Expr.BinaryOp \
            and operand_expr.op in {'Mul', 'Shl', 'Div', 'DivMod', 'Add', 'Sub'}:
            if isinstance(operand_expr.operands[1], Expr.Const):
                if isinstance(operand_expr.operands[0], Expr.Register) and \
                        expr.from_bits == operand_expr.operands[0].bits:
                    converted = Expr.Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed,
                                             operand_expr.operands[0])
                    return Expr.BinaryOp(operand_expr.idx, operand_expr.op,
                                         [converted, operand_expr.operands[1]], operand_expr.signed, **expr.tags)
                elif isinstance(operand_expr.operands[0], Expr.Convert) and \
                        expr.from_bits == operand_expr.operands[0].to_bits and \
                        expr.to_bits == operand_expr.operands[0].from_bits:
                    return Expr.BinaryOp(operand_expr.idx, operand_expr.op,
                                         [operand_expr.operands[0].operand, operand_expr.operands[1]],
                                         operand_expr.signed,
                                         **operand_expr.tags)
            elif isinstance(operand_expr.operands[0], Expr.Convert) \
                    and isinstance(operand_expr.operands[1], Expr.Convert) \
                    and operand_expr.operands[0].from_bits == operand_expr.operands[1].from_bits:
                if operand_expr.operands[0].to_bits == operand_expr.operands[1].to_bits \
                        and expr.from_bits == operand_expr.operands[0].to_bits \
                        and expr.to_bits == operand_expr.operands[1].from_bits:
                    return Expr.BinaryOp(operand_expr.idx, operand_expr.op,
                                         [operand_expr.operands[0].operand, operand_expr.operands[1].operand],
                                         expr.is_signed,
                                         **operand_expr.tags)

        converted = Expr.Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed,
                                 operand_expr, **expr.tags)
        return converted
