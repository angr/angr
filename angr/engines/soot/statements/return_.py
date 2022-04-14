
from .base import SimSootStmt


class SimSootStmt_Return(SimSootStmt):
    def __init__(self, stmt, state):
        super(SimSootStmt_Return, self).__init__(stmt, state)
        self.return_value = None

    def _execute(self):
        self.return_value = self._translate_expr(self.stmt.value).expr


class SimSootStmt_ReturnVoid(SimSootStmt):
    def __init__(self, stmt, state):
        super(SimSootStmt_ReturnVoid, self).__init__(stmt, state)
        self.return_value = None

    def _execute(self):
        pass
