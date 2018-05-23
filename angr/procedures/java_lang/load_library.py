
from ..java import JavaSimProcedure

class LoadLibrary(JavaSimProcedure):

    __provides__ = (
        ("java.lang.System", "loadLibrary(java.lang.String)"),
    )

    def run(self, lib):
        pass
