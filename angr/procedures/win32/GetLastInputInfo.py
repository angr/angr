from __future__ import annotations
import logging

import claripy

import angr


l = logging.getLogger(name=__name__)

# BOOL GetLastInputInfo(
#   PLASTINPUTINFO plii
# );

# | typedef struct tagLASTINPUTINFO {
# |   UINT  cbSize;  // The size of the structure, in bytes.
# |                  // This member must be set to sizeof(LASTINPUTINFO).
# |   DWORD dwTime;
# | } LASTINPUTINFO, *PLASTINPUTINFO;


class GetLastInputInfo(angr.SimProcedure):
    cbSize = None
    dwTime = None

    def run(self, plii):  # pylint:disable=arguments-differ
        self.fill_symbolic()
        l.info("Setting symbolic memory at %s", str(plii))
        self.state.mem[plii].dword = self.cbSize
        self.state.mem[plii + 4].dword = self.dwTime

        return 1

    def fill_symbolic(self):
        self.cbSize = self.state.solver.BVS("tagLASTINPUTINFO_cbSize", 32, key=("api", "tagLASTINPUTINFO_cbSize"))
        self.dwTime = self.state.solver.BVS("tagLASTINPUTINFO_dwTime", 32, key=("api", "tagLASTINPUTINFO_dwTime"))

    def fill_concrete(self):
        self.cbSize = claripy.BVV(3, 32)
        self.dwTime = claripy.BVV(3, 32)
