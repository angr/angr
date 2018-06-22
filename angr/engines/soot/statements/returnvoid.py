
from .base import SimSootStmt


class SimSootStmt_ReturnVoid(SimSootStmt):
    def __init__(self, stmt, state):
        super(SimSootStmt_ReturnVoid, self).__init__(stmt, state)

    def _execute(self):
        pass
