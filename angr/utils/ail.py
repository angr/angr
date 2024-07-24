from ailment.expression import Phi, VirtualVariable
from ailment.statement import Assignment, Statement


def is_phi_assignment(stmt: Statement) -> bool:
    return isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi)
