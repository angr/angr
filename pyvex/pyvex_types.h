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

// statements
PYVEX_TYPEHEADER(IRStmt);
extern PyTypeObject pyIRStmtNoOpType;
extern PyTypeObject pyIRStmtIMarkType;
extern PyTypeObject pyIRStmtAbiHintType;
extern PyTypeObject pyIRStmtPutType;
extern PyTypeObject pyIRStmtWrTmpType;
extern PyTypeObject pyIRStmtStoreType;
extern PyTypeObject pyIRStmtCASType;

// expressions
PYVEX_TYPEHEADER(IRExpr);
extern PyTypeObject pyIRExprRdTmpType;

#endif
