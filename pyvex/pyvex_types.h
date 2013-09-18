#ifndef __PYVEX_TYPES_H
#define __PYVEX_TYPES_H

#include <libvex.h>
#include <Python.h>
#include "pyvex_macros.h"

// the module itself
extern PyObject *module;

// exceptions from pyvex
extern PyObject *VexException;

// blocks
PYVEX_TYPEHEADER(IRSB);

// type env
PYVEX_TYPEHEADER(IRTypeEnv);

// ir constants
PYVEX_TYPEHEADER(IRConst);
extern PyTypeObject pyIRConstU1Type;
extern PyTypeObject pyIRConstU8Type;
extern PyTypeObject pyIRConstU16Type;
extern PyTypeObject pyIRConstU32Type;
extern PyTypeObject pyIRConstU64Type;
extern PyTypeObject pyIRConstF32Type;
extern PyTypeObject pyIRConstF32iType;
extern PyTypeObject pyIRConstF64Type;
extern PyTypeObject pyIRConstF64iType;
extern PyTypeObject pyIRConstV128Type;
extern PyTypeObject pyIRConstV256Type;

// statements
PYVEX_TYPEHEADER(IRStmt);
extern PyTypeObject pyIRStmtNoOpType;
extern PyTypeObject pyIRStmtIMarkType;
extern PyTypeObject pyIRStmtAbiHintType;
extern PyTypeObject pyIRStmtPutType;
extern PyTypeObject pyIRStmtWrTmpType;
extern PyTypeObject pyIRStmtStoreType;
extern PyTypeObject pyIRStmtCASType;
extern PyTypeObject pyIRStmtLLSCType;
extern PyTypeObject pyIRStmtExitType;

// expressions
PYVEX_TYPEHEADER(IRExpr);
extern PyTypeObject pyIRExprRdTmpType;
extern PyTypeObject pyIRExprGetType;
extern PyTypeObject pyIRExprQopType;
extern PyTypeObject pyIRExprTriopType;
extern PyTypeObject pyIRExprBinopType;
extern PyTypeObject pyIRExprUnopType;

#endif
