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
