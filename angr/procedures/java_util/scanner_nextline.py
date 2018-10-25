import logging

from claripy import StringS

from ...engines.soot.values import SimSootValue_StringRef
from ..java import JavaSimProcedure

l = logging.getLogger('angr.procedures.java.scanner.nextLine')


class ScannerNextLine(JavaSimProcedure):

    __provides__ = (
        ("java.util.Scanner", "nextLine()"),
    )

    def run(self, this): # pylint: disable=arguments-differ,unused-argument
        str_ref = SimSootValue_StringRef(self.state.memory.get_new_uuid())
        self.state.memory.store(str_ref, StringS("scanner_return", 100))
        # save reference in global dict, so we can easily access it later
        try:
            self.state.globals['java.util.Scanner'].append(str_ref)
        except KeyError:
            self.state.globals['java.util.Scanner'] = [str_ref]
        return str_ref