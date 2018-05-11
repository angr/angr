from ..java import JavaSimProcedure
import  logging

import claripy

l = logging.getLogger('angr.procedures.java.scanner.nextLine')

class ScannerNextLine(JavaSimProcedure):

    __provides__ = (
        ("java.util.Scanner", "nextLine()"),
    )

    def run(self, this):
        l.debug("Called SimProcedure java.utils.scanner.nextLine")
        return claripy.StringS("scanner_return", 1000)
