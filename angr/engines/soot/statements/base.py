
from ..expressions import translate_expr
from ..values import translate_value


class SimSootStmt(object):
    """
    The base class of all symbolic Soot statement.
    """

    def __init__(self, stmt, state):
        self.stmt = stmt
        self.state = state

        self.invoke_expr = None
        self.jmp_targets_with_conditions = []

    def process(self):
        """
        Process the statement and apply all effects on the state.

        :return: None
        """

        self._execute()

    def _execute(self):
        raise NotImplementedError()

    def _translate_expr(self, expr):
        expr_ = translate_expr(expr, self.state)
        return expr_

    def _translate_value(self, value):
        value_ = translate_value(value, self.state)
        return value_

    #
    # Jumps
    #

    def _add_jmp_target(self, target, condition):
        self.jmp_targets_with_conditions += [ (target, condition) ]

    @property
    def has_jump_targets(self):
        return self.jmp_targets_with_conditions != []

    #
    # Invocations
    #

    def _add_invoke_target(self, invoke_expr, ret_var=None):
        self.invoke_expr = invoke_expr
        self.invoke_expr.ret_var = ret_var
    
    @property
    def has_invoke_target(self):
        return self.invoke_expr != None