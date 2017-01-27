
from ..expressions import translate_expr
from ..values import translate_value


class SimSootStmt(object):
    """
    The base class of all symbolic Soot statement.
    """

    def __init__(self, stmt, state):
        self.stmt = stmt
        self.state = state

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
        value_ = translate_value(value)
        return value_
