
import pyvex

from .block import Block
from .statement import Assignment
from .expression import Atom


class Converter(object):
    @staticmethod
    def convert(thing):
        raise NotImplementedError()


class VEXExprConverter(Converter):

    @staticmethod
    def convert(expr):
        """

        :param expr:
        :return:
        """

        return expr


class VEXStmtConverter(Converter):

    @staticmethod
    def convert(idx, stmt):
        """

        :param idx:
        :param stmt:
        :return:
        """

        if type(stmt) is pyvex.IRStmt.Put:
            return Assignment(idx, Atom(0, "Reg %d" % stmt.offset), VEXExprConverter.convert(stmt.data))

        return stmt


class IRSBConverter(Converter):

    @staticmethod
    def convert(irsb):
        """

        :param irsb:
        :return:
        """

        # convert each VEX statement into an AIL statement
        statements = [ ]
        idx = 0

        for stmt in irsb.statements:
            converted = VEXStmtConverter.convert(idx, stmt)
            statements.append(converted)

            idx += 1

        return Block(statements)
