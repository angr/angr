
import pyvex

from . import Analysis, AnalysesHub


class CodeTags:
    HAS_XOR = 'HAS_XOR'
    HAS_BITSHIFTS = 'HAS_BITSHIFTS'
    LARGE_SWITCH = 'LARGE_SWITCH'


class CodeTagging(Analysis):

    def __init__(self, func):
        self._function = func
        self.tags = set()

        self.ANALYSES = [
            self.has_xor,
            self.has_bitshifts,
        ]

        self.analyze()

    def analyze(self):
        for analysis in self.ANALYSES:
            tags = analysis()
            if tags:
                self.tags |= tags

    #
    # Handlers
    #

    def has_xor(self):
        """
        Detects if there is any xor operation in the function.

        :return: Tags
        """

        def _has_xor(expr):
            return isinstance(expr, pyvex.IRExpr.Binop) and expr.op.startswith("Iop_Xor")

        found_xor = False

        for block in self._function.blocks:
            if block.size == 0:
                continue
            for stmt in block.vex.statements:
                if isinstance(stmt, pyvex.IRStmt.Put):
                    found_xor = found_xor or _has_xor(stmt.data)
                elif isinstance(stmt, pyvex.IRStmt.WrTmp):
                    found_xor = found_xor or _has_xor(stmt.data)
            if found_xor:
                break

        if found_xor:
            return { CodeTags.HAS_XOR }
        return None

    def has_bitshifts(self):
        """
        Detects if there is any bitwise operation in the function.

        :return: Tags.
        """

        def _has_bitshifts(expr):
            if isinstance(expr, pyvex.IRExpr.Binop):
                return expr.op.startswith("Iop_Shl") or expr.op.startswith("Iop_Shr") \
                       or expr.op.startswith("Iop_Sar")
            return False

        found_bitops = False

        for block in self._function.blocks:
            if block.size == 0:
                continue
            for stmt in block.vex.statements:
                if isinstance(stmt, pyvex.IRStmt.Put):
                    found_bitops = found_bitops or _has_bitshifts(stmt.data)
                elif isinstance(stmt, pyvex.IRStmt.WrTmp):
                    found_bitops = found_bitops or _has_bitshifts(stmt.data)

            if found_bitops:
                break

        if found_bitops:
            return { CodeTags.HAS_BITSHIFTS }
        return None


AnalysesHub.register_default('CodeTagging', CodeTagging)
