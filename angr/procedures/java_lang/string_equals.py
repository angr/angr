from ..java import JavaSimProcedure
import  logging

l = logging.getLogger('angr.procedures.java.string.equals')

class StringEquals(JavaSimProcedure):

    NO_RET = True

    __provides__ = (
        ("java.lang.String", "equals(java.lang.String)"),
    )

    def run(self, str_1, str_2):
        l.info("Called SimProcedure java.string.equals with args: %s (%r), %s (%r)", str_1, str_1, str_2, str_2)

