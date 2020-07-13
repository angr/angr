import itertools
from typing import Any, Dict, Set


#
# Variables and expressions
#

class BaseExpression:
    def replace(self, rep_dict: Dict['BaseExpression',Set['BaseExpression']]) -> Set['BaseExpression']:
        raise NotImplementedError()


class Parameter(BaseExpression):
    def __init__(self, idx: int):
        self.idx = idx

    def replace(self, rep_dict: Dict[BaseExpression,Set[BaseExpression]]) -> Set['Parameter']:
        return { self }

    def __repr__(self):
        return "Param %d" % self.idx


class LocalVariable(BaseExpression):
    def __init__(self, atom, code_location):
        self.atom = atom
        self.code_location = code_location

    def replace(self, rep_dict: Dict[BaseExpression,Set[BaseExpression]]) -> Set['LocalVariable']:
        return { self }

    def __eq__(self, other):
        return isinstance(other, LocalVariable) \
                and self.atom == other.atom \
                and self.code_location == other.code_location

    def __hash__(self):
        return hash((LocalVariable, self.atom, self.code_location))

    def __repr__(self):
        return "%r@%r" % (self.atom, self.code_location)


class Constant(BaseExpression):
    def __init__(self, con: int):
        self.con = con

    def replace(self, rep_dict: Dict[BaseExpression,Set[BaseExpression]]) -> Set['Constant']:
        return { self }

    def __eq__(self, other):
        return isinstance(other, Constant) \
                and self.con == other.con

    def __hash__(self):
        return hash((Constant, self.con))

    def __repr__(self):
        return str(self.con)


class Add(BaseExpression):
    def __init__(self, variable: BaseExpression, expression: BaseExpression):
        self.variable = variable
        self.expression = expression

    def replace(self, rep_dict: Dict[BaseExpression,Set[BaseExpression]]) -> Set['Add']:
        if self.variable in rep_dict:
            variables = rep_dict[self.variable]
        else:
            variables = { self.variable }
        if self.expression in rep_dict:
            expressions = rep_dict[self.expression]
        else:
            expressions = self.expression.replace(rep_dict)
        if len(variables) == 1 and next(iter(variables)) is self.variable \
                and len(expressions) == 1 and next(iter(expressions)) is self.expression:
            return { self }

        return set(Add(v, ex) for v, ex in itertools.product(variables, expressions))

    def __eq__(self, other):
        return isinstance(other, Add) \
                and self.variable == other.variable \
                and self.expression == other.expression

    def __hash__(self):
        return hash((Add, self.variable, self.expression))

    def __repr__(self):
        return "%r+%r" % (self.variable, self.expression)


class AddN(BaseExpression):
    def __init__(self, variable: BaseExpression, n: int):
        self.variable = variable
        self.n = n

    def replace(self, rep_dict: Dict[BaseExpression,BaseExpression]) -> Set['AddN']:
        if self.variable in rep_dict:
            variables = rep_dict[self.variable]
        else:
            variables = { self.variable }
        if len(variables) == 1 and next(iter(variables)) is self.variable:
            return { self }
        return set(AddN(v, self.n) for v in variables)

    def __eq__(self, other):
        return isinstance(other, AddN) \
                and self.variable == other.variable \
                and self.n == other.n

    def __hash__(self):
        return hash((AddN, self.variable, self.n))

    def __repr__(self):
        return "%r%+d" % (self.variable, self.n)


#
# Values
#


class ValuedVariable:
    def __init__(self, variable: BaseExpression, value: Any):
        self.variable = variable
        self.value = value

    def __eq__(self, other):
        return isinstance(other, ValuedVariable) \
                and other.variable == self.variable \
                and other.value == self.value

    def __hash__(self):
        return hash((ValuedVariable, self.variable, self.value))


#
# Constraints
#

class BaseConstraint:
    def replace(self, rep_dict: Dict[BaseExpression,Set[BaseExpression]]) -> Set['BaseConstraint']:
        raise NotImplementedError()


class Assignment(BaseConstraint):
    def __init__(self, variable: BaseExpression, expression: BaseExpression):
        self.variable = variable
        self.expression = expression

    def replace(self, rep_dict: Dict[BaseExpression,Set[BaseExpression]]) -> Set['Assignment']:
        if self.variable in rep_dict:
            variables = rep_dict[self.variable]
        else:
            variables = { self.variable }
        if self.expression in rep_dict:
            expressions = rep_dict[self.expression]
        else:
            expressions = self.expression.replace(rep_dict)
        if len(variables) == 1 and next(iter(variables)) is self.variable \
                and len(expressions) == 1 and next(iter(expressions)) is self.expression:
            return { self }
        return set(Assignment(v, ex) for v, ex in itertools.product(variables, expressions) if v != ex)

    def __eq__(self, other):
        return isinstance(other, Assignment) \
                and self.variable == other.variable \
                and self.expression == other.expression

    def __hash__(self):
        return hash((Assignment, self.variable, self.expression))

    def __repr__(self):
        return "%r := %r" % (self.variable, self.expression)


class CmpBase(BaseConstraint):
    def __init__(self, variable: BaseExpression):
        self.variable = variable


class CmpLtExpr(CmpBase):
    def __init__(self, variable: BaseExpression, expression: BaseExpression):
        super().__init__(variable)
        self.expression = expression

    def replace(self, rep_dict: Dict[BaseExpression,Set[BaseExpression]]) -> Set['CmpLtExpr']:
        if self.variable in rep_dict:
            variables = rep_dict[self.variable]
        else:
            variables = { self.variable }
        if self.expression in rep_dict:
            expressions = rep_dict[self.expression]
        else:
            expressions = self.expression.replace(rep_dict)
        if len(variables) == 1 and next(iter(variables)) is self.variable \
                and len(expressions) == 1 and next(iter(expressions)) is self.expression:
            return { self }
        return set(CmpLtExpr(v, ex) for v, ex in itertools.product(variables, expressions))

    def __eq__(self, other):
        return isinstance(other, CmpLtExpr) \
                and self.variable == other.variable \
                and self.expression == other.expression

    def __hash__(self):
        return hash((CmpLtExpr, self.variable, self.expression))

    def __repr__(self):
        return "%r < %r" % (self.variable, self.expression)


class CmpLtN(CmpBase):
    def __init__(self, variable: BaseExpression, n: int):
        super().__init__(variable)
        self.n = n

    def replace(self, rep_dict: Dict[BaseExpression,BaseExpression]) -> Set['CmpLtN']:
        if self.variable in rep_dict:
            variables = rep_dict[self.variable]
        else:
            variables = { self.variable }
        if len(variables) == 1 and next(iter(variables)) is self.variable:
            return { self }
        return set(CmpLtN(v, self.n) for v in variables)

    def __eq__(self, other):
        return isinstance(other, CmpLtN) \
                and self.variable == other.variable \
                and self.n == other.n

    def __hash__(self):
        return hash((CmpLtN, self.variable, self.n))

    def __repr__(self):
        return "%r < %+d" % (self.variable, self.n)


class CmpLeExpr(CmpBase):
    def __init__(self, variable: BaseExpression, expression: BaseExpression):
        super().__init__(variable)
        self.expression = expression

    def replace(self, rep_dict: Dict[BaseExpression,Set[BaseExpression]]) -> Set['CmpLeExpr']:
        if self.variable in rep_dict:
            variables = rep_dict[self.variable]
        else:
            variables = { self.variable }
        if self.expression in rep_dict:
            expressions = rep_dict[self.expression]
        else:
            expressions = self.expression.replace(rep_dict)
        if len(variables) == 1 and next(iter(variables)) is self.variable \
                and len(expressions) == 1 and next(iter(expressions)) is self.expression:
            return { self }
        return set(CmpLeExpr(v, ex) for v, ex in itertools.product(variables, expressions))

    def __eq__(self, other):
        return isinstance(other, CmpLeExpr) \
                and self.variable == other.variable \
                and self.expression == other.expression

    def __hash__(self):
        return hash((CmpLeExpr, self.variable, self.expression))

    def __repr__(self):
        return "%r <= %r" % (self.variable, self.expression)


class Store(BaseConstraint):
    def __init__(self, addr: BaseExpression, size: int):
        self.addr = addr
        self.size = size

    def replace(self, rep_dict: Dict[BaseExpression,Set[BaseExpression]]) -> Set['Store']:
        if self.addr in rep_dict:
            addrs = rep_dict[self.addr]
        else:
            addrs = self.addr.replace(rep_dict)
        if len(addrs) == 1 and next(iter(addrs)) is self.addr:
            return { self }
        return set(Store(addr, self.size) for addr in addrs)

    def __eq__(self, other):
        return isinstance(other, Store) \
                and self.addr == other.addr \
                and self.size == other.size

    def __hash__(self):
        return hash((Store, self.addr, self.size))

    def __repr__(self):
        return "*(%r,%d) := X" % (self.addr, self.size)


class Load(BaseConstraint):
    def __init__(self, addr: BaseExpression, size: int):
        self.addr = addr
        self.size = size

    def replace(self, rep_dict: Dict[BaseExpression,Set[BaseExpression]]) -> Set['Load']:
        if self.addr in rep_dict:
            addrs = rep_dict[self.addr]
        else:
            addrs = self.addr.replace(rep_dict)
        if len(addrs) == 1 and next(iter(addrs)) is self.addr:
            return { self }
        return set(Load(addr, self.size) for addr in addrs)

    def __eq__(self, other):
        return isinstance(other, Load) \
               and self.addr == other.addr \
               and self.size == other.size

    def __hash__(self):
        return hash((Load, self.addr, self.size))

    def __repr__(self):
        return "X:= *(%r,%d)" % (self.addr, self.size)
