from typing import Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from claripy.ast.bv import BV
    from angr.state_plugins import SimActionData


class DepNodeTypes:
    """
    Enumeration of types of BaseDepNode supported by this analysis
    """
    Memory = 1
    Register = 2
    Tmp = 3
    Constant = 4


class BaseDepNode:
    """
    Base class for all nodes in a data-dependency graph
    """

    def __init__(self, type_: int, sim_act: 'SimActionData'):
        self._type = type_
        self._sim_act = sim_act
        self.ins_addr = sim_act.ins_addr
        self.stmt_idx = sim_act.stmt_idx
        self.action_id: int = sim_act.id
        self.value: Optional[int] = None
        self._value_ast: Optional['BV'] = None

    def value_tuple(self) -> Tuple['BV', int]:
        """
        :return: A tuple containing the node's value as a BV and as an evaluated integer
        """
        return self.ast, self.value

    @property
    def ast(self) -> 'BV':
        return self._value_ast

    @ast.setter
    def ast(self, new_ast: 'BV'):
        self._value_ast = new_ast

    @property
    def type(self) -> int:
        """
        Getter
        :return: An integer defined in DepNodeTypes, represents the subclass type of this DepNode.
        """
        return self._type

    def __repr__(self):
        raise NotImplementedError()

    def __eq__(self, other):
        return self.type == other.type and self.ins_addr == other.ins_addr and self.action_id == other.action_id

    def __hash__(self):
        return hash(self.type) ^ hash(self.ins_addr) ^ hash(self.stmt_idx) ^ hash(self.action_id)


class ConstantDepNode(BaseDepNode):
    """
    Used to create a DepNode that will hold a constant, numeric value
    Uniquely identified by its value
    """

    def __init__(self, sim_act: 'SimActionData', value: int):
        super().__init__(DepNodeTypes.Constant, sim_act)
        self.value = value

    def __str__(self):
        return f"Constant {hex(self.value)}"

    def __repr__(self):
        return f"Constant{hex(self.value)}"

    def __eq__(self, other):
        return self.value == other.value

    def __hash__(self):
        return hash(self.value)


class MemDepNode(BaseDepNode):
    """
    Used to represent SimActions of type MEM
    """

    def __init__(self, sim_act: 'SimActionData', addr: int):
        super().__init__(DepNodeTypes.Memory, sim_act)
        self.addr = addr

    @property
    def width(self) -> int:
        return self._sim_act.size.ast // 8

    def __str__(self):
        return hex(self.addr)

    def __repr__(self):
        val_str = 'None' if self.value is None else hex(self.value)
        return f"{hex(self.addr)}\n{hex(self.ins_addr)}:{self.stmt_idx}\n{val_str}"

    def __eq__(self, other):
        return super().__eq__(other) and self.addr == other.addr

    def __hash__(self):
        return super().__hash__() ^ hash(self.addr)

    @classmethod
    def cast_to_mem(cls, base_dep_node: BaseDepNode):
        """Casts a BaseDepNode into a MemDepNode"""
        assert isinstance(base_dep_node, BaseDepNode)
        base_dep_node.__class__ = cls
        assert isinstance(base_dep_node, MemDepNode)
        return base_dep_node


class VarDepNode(BaseDepNode):
    """
    Abstract class for representing SimActions of TYPE reg or tmp
    """

    def __init__(self, type_: int, sim_act: 'SimActionData', reg: int, arch_name: str = ''):
        super().__init__(type_, sim_act)
        self.reg = reg
        self.arch_name = arch_name

    @property
    def display_name(self) -> str:
        return self.arch_name if self.arch_name else hex(self.reg)

    def __str__(self):
        return self.display_name

    def __repr__(self):
        val_str = 'None' if self.value is None else hex(self.value)
        return f"{self.display_name}@{hex(self.ins_addr)}:{self.stmt_idx}\n{val_str}"

    def __eq__(self, other):
        return super().__eq__(other) and self.reg == other.reg

    def __hash__(self):
        return super().__hash__() ^ hash(self.reg)


class TmpDepNode(VarDepNode):
    """
    Used to represent SimActions of type TMP
    """

    def __init__(self, sim_act: 'SimActionData', reg: int, arch_name: str = ''):
        super().__init__(DepNodeTypes.Tmp, sim_act, reg, arch_name)


class RegDepNode(VarDepNode):
    """
    Base class for representing SimActions of TYPE reg
    """

    def __init__(self, sim_act: 'SimActionData', reg: int, arch_name: str = ''):
        super().__init__(DepNodeTypes.Register, sim_act, reg, arch_name)

    @property
    def reg_size(self) -> int:
        return self._sim_act.size.ast // 8
