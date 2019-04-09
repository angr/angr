from .store import SimIRStmt_Store

import ailment

# STMT_CLASSES = [None]*ailment.Stmt.tag_count
# for name, cls in vars(ailment.Stmt).items():
#     if isinstance(cls, type) and issubclass(cls, ailment.Stmt.Statement) and cls is not ailment.Stmt.IRStmt:
#         STMT_CLASSES[cls.tag_int] = globals()['SimIRStmt_' + name]
# if any(x is None for x in STMT_CLASSES):
#     raise ImportError("Something is messed up loading angr: not all ailment stmts accounted for")


STMT_CLASSES = {
	# ailment.Stmt.Assignment:       SimIRStmt_Assignment,
	ailment.Stmt.Store:            SimIRStmt_Store,
	# ailment.Stmt.Jump:             SimIRStmt_Jump,
	# ailment.Stmt.ConditionalJump:  SimIRStmt_ConditionalJump,
	# ailment.Stmt.Call:             SimIRStmt_Call,
	# ailment.Stmt.DirtyStatement:   SimIRStmt_DirtyStatement
}
