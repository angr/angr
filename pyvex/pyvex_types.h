#ifndef __PYVEX_TYPES_H
#define __PYVEX_TYPES_H

#include <libvex.h>
#include "pyvex_macros.h"

// the module itself
extern PyObject *module;

// exceptions from pyvex
extern PyObject *VexException;

// blocks
extern PyTypeObject pyIRSBType;
PYVEX_STRUCT(IRSB);

// statements
extern PyTypeObject pyIRStmtType;
PYVEX_STRUCT(IRStmt);
PyObject *wrap_IRStmt(IRStmt *);

#endif
