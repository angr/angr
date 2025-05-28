from __future__ import annotations
import logging

from .block import Block
from . import statement
from . import expression
from .statement import Assignment, Statement
from .expression import Expression, Const, Tmp, Register, UnaryOp, BinaryOp
from .converter_common import Converter
from .manager import Manager
from .block_walker import AILBlockWalker, AILBlockWalkerBase

log = logging.getLogger(__name__)

# REALLY BAD
Expr = expression
Stmt = statement

available_converters: set[str] = set()

try:
    from .converter_vex import VEXIRSBConverter
    import pyvex

    available_converters.add("vex")
except ImportError as e:
    log.debug("Could not import VEXIRSBConverter")
    log.debug(e)
    VEXIRSBConverter = None

try:
    from .converter_pcode import PCodeIRSBConverter
    from angr.engines import pcode

    available_converters.add("pcode")
except ImportError as e:
    log.debug("Could not import PCodeIRSBConverter")
    log.debug(e)
    PCodeIRSBConverter = None


class IRSBConverter(Converter):
    @staticmethod
    def convert(irsb, manager):  # pylint:disable=arguments-differ
        """
        Convert the given IRSB to an AIL block

        :param irsb:    The IRSB to convert
        :param manager: The manager to use
        :return:        Returns the converted block
        """

        if "pcode" in available_converters and isinstance(irsb, pcode.lifter.IRSB):
            return PCodeIRSBConverter.convert(irsb, manager)
        if "vex" in available_converters and isinstance(irsb, pyvex.IRSB):
            return VEXIRSBConverter.convert(irsb, manager)
        raise ValueError(f"No converter available for {type(irsb)}")


__all__ = [
    "AILBlockWalker",
    "AILBlockWalkerBase",
    "Assignment",
    "BinaryOp",
    "Block",
    "Const",
    "Expr",
    "Expression",
    "IRSBConverter",
    "Manager",
    "PCodeIRSBConverter",
    "Register",
    "Statement",
    "Stmt",
    "Tmp",
    "UnaryOp",
    "VEXIRSBConverter",
    "available_converters",
    "expression",
    "statement",
]
