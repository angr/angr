#pragma once

// expression tags
const char *IRExprTag_to_str(IRExprTag);
IRExprTag str_to_IRExprTag(const char *);

// statement tags
const char *IRStmtTag_to_str(IRStmtTag);
IRStmtTag str_to_IRStmtTag(const char *);

// endness
const char *IREndness_to_str(IREndness);
IREndness str_to_IREndness(const char *);

// mbusevent
const char *IRMBusEvent_to_str(IRMBusEvent);
IRMBusEvent str_to_IRMBusEvent(const char *);

// jump kind
const char *IRJumpKind_to_str(IRJumpKind);
IRJumpKind str_to_IRJumpKind(const char *);

// constant type
const char *IRConstTag_to_str(IRConstTag);
IRConstTag str_to_IRConstTag(const char *);

// IR type
const char *IRType_to_str(IRType);
IRType str_to_IRType(const char *);

// IROp
const char *IROp_to_str(IROp);
IROp str_to_IROp(const char *);
