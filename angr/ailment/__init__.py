

from .block import Block
from . import statement as Stmt
from . import expression as Expr
from .statement import Assignment
from .expression import Expression, Const, Tmp, Register, UnaryOp, BinaryOp
from .converter_common import Converter
from .converter_vex import VEXIRSBConverter
from .manager import Manager

try:
    from angr.engines import pcode
    from .converter_pcode import PCodeIRSBConverter
except ImportError:
    pcode = None

class IRSBConverter(Converter):

    @staticmethod
    def convert(irsb, manager):  # pylint:disable=arguments-differ
        """
        Convert the given IRSB to an AIL block

        :param irsb:    The IRSB to convert
        :param manager: The manager to use
        :return:        Returns the converted block
        """

        if pcode and isinstance(irsb, pcode.lifter.IRSB):
            return PCodeIRSBConverter.convert(irsb, manager)
        else:
            return VEXIRSBConverter.convert(irsb, manager)
