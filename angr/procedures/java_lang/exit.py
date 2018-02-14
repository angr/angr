
from ..java import JavaSimProcedure


class Exit(JavaSimProcedure):

    NO_RET = True

    __provides__ = (
        ("java.lang.System", "exit(int)"),
    )

    def run(self, exit_code):
        self.exit(exit_code)
