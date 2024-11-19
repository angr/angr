from ailment import Expression
from ailment.statement import Statement
from ailment.tagged_object import TaggedObject
from ailment.utils import stable_hash


class Macro(Expression, Statement):
    def __init__(self, idx, name, delimiter="()", **kwargs):
        super().__init__(idx, 1, **kwargs)
        self.name = name
        self.delimiter = delimiter


class FunctionLikeMacro(Macro):
    def __init__(self, idx, name, args, bits=None, delimiter="()", **kwargs):
        super().__init__(idx, name, delimiter, **kwargs)
        self.args = args
        self.bits = bits

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((FunctionLikeMacro, self.idx, self.name))

    def __str__(self):
        return f"{self.name}!{self.delimiter[0]}{self.args}{self.delimiter[1]}"

    def __repr__(self):
        return str(self)

    def likes(self, other):
        return (
            type(self) is type(other)
            and self.name == other.name
            and self.delimiter == other.delimiter
            and self.bits == other.bits
            and len(self.args) == len(other.args)
            and all(arg.likes(other_arg) for arg, other_arg in zip(self.args, other.args))
        )
