"""
Defines the classes used to represent the different type of nodes in a Data Dependency NetworkX graph
"""
from typing import Optional, Tuple, TYPE_CHECKING
from copy import copy

if TYPE_CHECKING:
    from claripy.ast.bv import BV
    from angr.state_plugins import SimActionData


class DepNodeTypes:
    """
    Enumeration of types of BaseDepNode supported by this analysis
    """
    Memory = 1
    Register = 2
    Constant = 3


class BaseDepNode:
    """
    Base class for all nodes in a data-dependency graph
    """

    def __init__(self, type_: int, sim_act: 'SimActionData'):
        self._type = type_
        self._sim_act = sim_act
        self._ins_addr = sim_act.ins_addr
        self._stmt_idx = sim_act.stmt_idx
        self._action_id: int = sim_act.id
        self._iteration_num: Optional[int] = None  # Number representing times this instruction has been prev parsed
        self._value: Optional[int] = None
        self._value_ast: Optional['BV'] = None

        self._is_tmp = False

    @property
    def iteration(self) -> Optional[int]:
        return self._iteration_num

    @iteration.setter
    def iteration(self, iter_num: int):
        self._iteration_num = iter_num

    @property
    def action_id(self) -> Optional[int]:
        """
        Uniquely identifies a SimAction
        """
        return self._action_id

    @action_id.setter
    def action_id(self, new_id: int):
        self._action_id = new_id

    @property
    def is_tmp(self) -> bool:
        """
        :return: Whether or not the given node represents a temporary variable
        """
        return self._is_tmp

    def value_tuple(self) -> Tuple['BV', int]:
        """
        :return: A tuple containing the node's value as a BV and as an evaluated integer
        """
        return self.ast, self.value

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, new_val: int):
        self._value = new_val

    @property
    def ast(self) -> 'BV':
        return self._value_ast

    @ast.setter
    def ast(self, new_ast: 'BV'):
        self._value_ast = new_ast

    @property
    def ins_addr(self) -> int:
        return self._ins_addr

    @ins_addr.setter
    def ins_addr(self, new_ins_addr: int):
        self._ins_addr = new_ins_addr

    @property
    def stmt_idx(self) -> int:
        """
        Statement index of action
        :return:
        """
        return self._stmt_idx

    @stmt_idx.setter
    def stmt_idx(self, new_stmt_idx: int):
        self._stmt_idx = new_stmt_idx

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
        return self.type == other.type and self.ins_addr == other.ins_addr and self.iteration == other.iteration

    def __hash__(self):
        return hash(self.type) ^ hash(self.ins_addr) ^ hash(self.iteration)


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


class VarOffset:
    """
    Used to create a VarDepNode, holds the register offset and whether the source is a temp node
    Necessary as a tmp_16 and rax (offset 16) in the same instruction would otherwise have equivalent nodes
    """

    def __init__(self, reg: int, is_tmp: bool):
        self._reg = reg
        self._is_tmp = is_tmp

    @property
    def reg(self) -> int:
        return self._reg

    @reg.setter
    def reg(self, new_reg: int):
        self._reg = new_reg

    @property
    def is_tmp(self) -> bool:
        return self._is_tmp


class VarDepNode(BaseDepNode):
    """
    Base class for representing SimActions of TYPE tmp or reg
    """

    def __init__(self, sim_act: 'SimActionData', offset: 'VarOffset', arch_name: str = ''):
        super().__init__(DepNodeTypes.Register, sim_act)
        self._reg = offset.reg
        self._is_tmp = offset.is_tmp
        self._arch_name = arch_name

    @property
    def reg(self) -> int:
        return self._reg

    @property
    def display_name(self) -> str:
        return self._arch_name if self.arch_name else hex(self.reg)

    @property
    def arch_name(self) -> str:
        return self._arch_name

    @arch_name.setter
    def arch_name(self, new_arch_name: str):
        self._arch_name = new_arch_name

    def __str__(self):
        return self.display_name

    def __repr__(self):
        val_str = 'None' if self.value is None else hex(self.value)
        return f"{self.display_name}@{hex(self.ins_addr)}:{self.stmt_idx}\n{val_str}"

    def __eq__(self, other):
        return super().__eq__(other) and self.reg == other.reg and self.is_tmp == other.is_tmp

    def __hash__(self):
        return super().__hash__() ^ hash(self.reg) ^ hash(self.is_tmp)


class VarDepWriteNode(VarDepNode):
    """
    Needed as a write should create a new state, so the hash is overriden to include the statement index in equality
    and hash checks
    """

    @classmethod
    def cast_to_var_write(cls, var_node: VarDepNode):
        """Casts a VarDepNode to a VarDepWriteNode"""
        assert isinstance(var_node, VarDepNode)
        var_node.__class__ = cls
        assert isinstance(var_node, VarDepWriteNode)
        return var_node

    def __eq__(self, other):
        return super().__eq__(other) and self.stmt_idx == other.stmt_idx

    def __hash__(self):
        """
        As each write should be treated as a new "state" for a register or temp var, we need nodes of this type
        to hash to a unique bucket in the canonical graph dictionary. To accomplish this, a write node will also include
        its statement index in its hash.
        Meanwhile, the superclass will resolve to the same node for all statements in the instruction
        """
        return super().__hash__() ^ hash(self.stmt_idx)


class VarDepReadNode(VarDepNode):
    """
    Created to differentiate from VarDepWriteNodes. Reads shouldn't create a new state, so maintain the same generic
    hash inherited from the parent class.
    """

    @classmethod
    def cast_to_var_read(cls, var_node: VarDepNode):
        """Casts a VarDepNode to a VarDepReadNode"""
        assert isinstance(var_node, VarDepNode)
        var_node.__class__ = cls
        assert isinstance(var_node, VarDepReadNode)
        return var_node


class MemDepNode(BaseDepNode):
    """
    Used to represent SimActions of type MEM
    """

    def __init__(self, sim_act: 'SimActionData', addr: int):
        super().__init__(DepNodeTypes.Memory, sim_act)
        self.addr = addr

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


class MemDepWriteNode(MemDepNode):
    """
    Created for same reason as VarDepWriteNode, a write to a memory address should be treated as a new state and
    thus warrants a new node
    """

    def __eq__(self, other):
        return super().__eq__(other) and self.stmt_idx == other.stmt_idx

    def __hash__(self):
        """
        Same story as VarDepWriteNode, we want these to uniquely hash per statement
        """
        return super().__hash__() ^ hash(self.stmt_idx)

    @classmethod
    def cast_to_mem_write(cls, mem_dep_node: MemDepNode):
        """Casts a MemDepNode into a MemDepWriteNode"""
        assert isinstance(mem_dep_node, MemDepNode)
        mem_dep_node.__class__ = cls
        assert isinstance(mem_dep_node, MemDepWriteNode)
        return mem_dep_node


class MemDepReadNode(MemDepNode):
    """
    Same story as VarDepReadNode, we want these to use the generic hash from the parent class
    """

    @classmethod
    def cast_to_mem_read(cls, mem_dep_node: MemDepNode):
        """Casts a MemDepNode into a MemDepReadNode"""
        assert isinstance(mem_dep_node, MemDepNode)
        mem_dep_node.__class__ = cls
        assert isinstance(mem_dep_node, MemDepReadNode)
        return mem_dep_node
