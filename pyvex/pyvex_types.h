#ifndef __PYVEX_TYPES_H
#define __PYVEX_TYPES_H

#include <libvex.h>

// the module itself
extern PyObject *module;

// exceptions from pyvex
extern PyObject *VexException;

// blocks
extern PyTypeObject pyIRSBType;

// statements
extern PyTypeObject pyIRStmtType;
PyObject *wrap_stmt(IRStmt *);

#endif
