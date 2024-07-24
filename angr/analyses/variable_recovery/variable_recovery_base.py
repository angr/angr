from __future__ import annotations
import weakref
from typing import Any, TYPE_CHECKING
from collections.abc import Generator, Iterable
import logging
from collections import defaultdict

import claripy
from claripy.annotation import Annotation
from archinfo import Arch
from ailment.expression import BinaryOp, StackBaseOffset

from ...utils.cowdict import DefaultChainMapCOW
from ...engines.light import SpOffset
from ...sim_variable import SimVariable
from ...errors import AngrRuntimeError
from ...storage.memory_mixins import MultiValuedMemory
from ..analysis import Analysis
from ..typehoon.typevars import TypeVariables, TypeVariable

if TYPE_CHECKING:
    from angr.storage import SimMemoryObject


l = logging.getLogger(name=__name__)


def parse_stack_pointer(sp):
    """
    Convert multiple supported forms of stack pointer representations into stack offsets.

    :param sp:  A stack pointer representation.
    :return:    A stack pointer offset.
    :rtype:     int
    """
    if isinstance(sp, int):
        return sp

    if isinstance(sp, StackBaseOffset):
        return sp.offset

    if isinstance(sp, BinaryOp):
        op0, op1 = sp.operands
        off0 = parse_stack_pointer(op0)
        off1 = parse_stack_pointer(op1)
        if sp.op == "Sub":
            return off0 - off1
        if sp.op == "Add":
            return off0 + off1

    raise NotImplementedError(f"Unsupported stack pointer representation type {type(sp)}.")


class VariableAnnotation(Annotation):
    __slots__ = ("addr_and_variables",)

    def __init__(self, addr_and_variables: list[tuple[int, SimVariable]]):
        self.addr_and_variables = addr_and_variables

    @property
    def relocatable(self):
        return True

    @property
    def eliminatable(self):
        return False

    def __eq__(self, other):
        if type(other) is VariableAnnotation:
            return self.addr_and_variables == other.addr_and_variables
        return False

    def __hash__(self):
        return hash(("Va", tuple(self.addr_and_variables)))

    def __repr__(self):
        return f"<VariableAnnotation: {self.addr_and_variables}>"


class VariableRecoveryBase(Analysis):
    """
    The base class for VariableRecovery and VariableRecoveryFast.
    """

    def __init__(self, func, max_iterations, store_live_variables: bool, vvar_to_vvar: dict[int, int] | None = None):
        self.function = func
        self.variable_manager = self.kb.variables

        self._max_iterations = max_iterations
        self._store_live_variables = store_live_variables

        self._outstates = {}
        self._instates: dict[Any, VariableRecoveryStateBase] = {}
        self._dominance_frontiers = None
        self.vvar_to_vvar = vvar_to_vvar

    #
    # Public methods
    #

    def get_variable_definitions(self, block_addr):
        """
        Get variables that are defined at the specified block.

        :param int block_addr:  Address of the block.
        :return:                A set of variables.
        """

        if block_addr in self._outstates:
            return self._outstates[block_addr].variables
        return set()

    #
    # Private methods
    #

    def initialize_dominance_frontiers(self):
        # Computer the dominance frontier for each node in the graph
        df = self.project.analyses.DominanceFrontier(self.function)
        self._dominance_frontiers = defaultdict(set)
        for b0, domfront in df.frontiers.items():
            for d in domfront:
                self._dominance_frontiers[d.addr].add(b0.addr)

    def _post_analysis(self):
        # remove temporary variables (stack variables created by _ensure_variable_existence() that are 1-byte long,
        # never accessed, and overlap with other stack variables at the same offset)
        varman = self.variable_manager[self.function.addr]
        stack_vars = varman.get_variables("stack")
        stack_vars_by_offset = defaultdict(list)
        for sv in stack_vars:
            stack_vars_by_offset[sv.offset].append(sv)
        for _offset, var_list in stack_vars_by_offset.items():
            if len(var_list) < 2:
                continue
            single_byte_vars = [v for v in var_list if v.size == 1]
            if len(single_byte_vars) != 1:
                continue
            single_byte_var = single_byte_vars[0]

            if not varman.get_variable_accesses(single_byte_var):
                # remove this variable
                varman._variables.discard(single_byte_var)


class VariableRecoveryStateBase:
    """
    The base abstract state for variable recovery analysis.
    """

    _tops = {}

    def __init__(
        self,
        block_addr,
        analysis,
        arch,
        func,
        stack_region=None,
        register_region=None,
        global_region=None,
        typevars=None,
        type_constraints=None,
        func_typevar=None,
        delayed_type_constraints=None,
        stack_offset_typevars=None,
        project=None,
    ):
        self.block_addr = block_addr
        self._analysis = analysis
        self.arch: Arch = arch
        self.function = func
        self.project = project

        if stack_region is not None:
            self.stack_region: MultiValuedMemory = stack_region
            self.stack_region._phi_maker = self._make_phi_variable
        else:
            self.stack_region: MultiValuedMemory = MultiValuedMemory(
                memory_id="mem",
                top_func=self.top,
                is_top_func=self.is_top,
                phi_maker=self._make_phi_variable,
                skip_missing_values_during_merging=True,
                page_kwargs={"mo_cmp": self._mo_cmp},
            )
        self.stack_region.set_state(self)

        if register_region is not None:
            self.register_region: MultiValuedMemory = register_region
            self.register_region._phi_maker = self._make_phi_variable
        else:
            self.register_region: MultiValuedMemory = MultiValuedMemory(
                memory_id="reg",
                top_func=self.top,
                is_top_func=self.is_top,
                phi_maker=self._make_phi_variable,
                skip_missing_values_during_merging=True,
                page_kwargs={"mo_cmp": self._mo_cmp},
            )
        self.register_region.set_state(self)

        if global_region is not None:
            self.global_region: MultiValuedMemory = global_region
            self.global_region._phi_maker = self._make_phi_variable
        else:
            self.global_region: MultiValuedMemory = MultiValuedMemory(
                memory_id="mem",
                top_func=self.top,
                is_top_func=self.is_top,
                phi_maker=self._make_phi_variable,
                skip_missing_values_during_merging=True,
                page_kwargs={"mo_cmp": self._mo_cmp},
            )
        self.global_region.set_state(self)

        # Used during merging
        self.successor_block_addr: int | None = None
        self.phi_variables: dict[SimVariable, SimVariable] = {}

        self.typevars = TypeVariables() if typevars is None else typevars
        self.type_constraints = defaultdict(set) if type_constraints is None else type_constraints
        self.func_typevar = func_typevar
        self.delayed_type_constraints = (
            DefaultChainMapCOW(default_factory=set, collapse_threshold=25)
            if delayed_type_constraints is None
            else delayed_type_constraints
        )
        self.stack_offset_typevars: dict[int, TypeVariable] = (
            {} if stack_offset_typevars is None else stack_offset_typevars
        )

    def _get_weakref(self):
        return weakref.proxy(self)

    @staticmethod
    def top(bits) -> claripy.ast.BV:
        if bits in VariableRecoveryStateBase._tops:
            return VariableRecoveryStateBase._tops[bits]
        r = claripy.BVS("top", bits, explicit_name=True)
        VariableRecoveryStateBase._tops[bits] = r
        return r

    @staticmethod
    def is_top(thing) -> bool:
        return bool(isinstance(thing, claripy.ast.BV) and thing.op == "BVS" and thing.args[0] == "top")

    @staticmethod
    def extract_variables(expr: claripy.ast.Base) -> Generator[tuple[int, SimVariable | SpOffset]]:
        for anno in expr.annotations:
            if isinstance(anno, VariableAnnotation):
                yield from anno.addr_and_variables

    @staticmethod
    def annotate_with_variables(
        expr: claripy.ast.Base, addr_and_variables: Iterable[tuple[int, SimVariable | SpOffset]]
    ) -> claripy.ast.Base:
        return expr.replace_annotations((VariableAnnotation(list(addr_and_variables)),))

    def stack_address(self, offset: int) -> claripy.ast.Base:
        base = claripy.BVS("stack_base", self.arch.bits, explicit_name=True)
        if offset:
            return base + offset
        return base

    @staticmethod
    def is_stack_address(addr: claripy.ast.Base) -> bool:
        return "stack_base" in addr.variables

    def is_global_variable_address(self, addr: claripy.ast.Base) -> bool:
        if addr.op == "BVV":
            addr_v = addr.concrete_value
            # make sure it is within a mapped region
            obj = self.project.loader.find_object_containing(addr_v)
            if obj is not None:
                return True
        return False

    @staticmethod
    def extract_stack_offset_from_addr(addr: claripy.ast.Base) -> claripy.ast.Base | None:
        r = None
        if addr.op == "BVS":
            if addr.args[0] == "stack_base":
                return claripy.BVV(0, addr.size())
            return None
        if addr.op == "BVV":
            r = addr
        elif addr.op == "__add__":
            arg_offsets = []
            for arg in addr.args:
                arg_offset = VariableRecoveryStateBase.extract_stack_offset_from_addr(arg)
                if arg_offset is None:
                    return None
                arg_offsets.append(arg_offset)
            r = sum(arg_offsets)
        elif addr.op == "__sub__":
            r1 = VariableRecoveryStateBase.extract_stack_offset_from_addr(addr.args[0])
            r2 = VariableRecoveryStateBase.extract_stack_offset_from_addr(addr.args[1])
            if r1 is None or r2 is None:
                return None
            r = r1 - r2
        return r

    def get_stack_offset(self, addr: claripy.ast.Base) -> int | None:
        if "stack_base" in addr.variables:
            r = VariableRecoveryStateBase.extract_stack_offset_from_addr(addr)
            if r is None:
                return None

            # extract_stack_offset_from_addr should ensure that r is a BVV
            assert r.concrete

            val = r.concrete_value
            # convert it to a signed integer
            if val >= 2 ** (self.arch.bits - 1):
                return val - 2**self.arch.bits
            if val < -(2 ** (self.arch.bits - 1)):
                return 2**self.arch.bits + val
            return val

        return None

    def stack_addr_from_offset(self, offset: int) -> int:
        if self.arch.bits == 32:
            base = 0x7FFF_FE00
            mask = 0xFFFF_FFFF
        elif self.arch.bits == 64:
            base = 0x7F_FFFF_FFFE_0000
            mask = 0xFFFF_FFFF_FFFF_FFFF
        else:
            raise AngrRuntimeError("Unsupported bits %d" % self.arch.bits)
        return (offset + base) & mask

    @property
    def func_addr(self):
        return self.function.addr

    @property
    def dominance_frontiers(self):
        return self._analysis._dominance_frontiers

    @property
    def variable_manager(self):
        return self._analysis.variable_manager

    @property
    def variables(self):
        for ro in self.stack_region:
            yield from ro.internal_objects
        for ro in self.register_region:
            yield from ro.internal_objects

    def get_variable_definitions(self, block_addr):
        """
        Get variables that are defined at the specified block.

        :param int block_addr:  Address of the block.
        :return:                A set of variables.
        """

        return self._analysis.get_variable_definitions(block_addr)

    def add_type_constraint(self, constraint):
        """
        Add a new type constraint.

        :param constraint:
        :return:
        """

        self.type_constraints[self.func_typevar].add(constraint)

    def add_type_constraint_for_function(self, func_typevar, constraint):
        """
        Add a new type constraint for a specified function.

        :param func_typevar:
        :param constraint:
        :return:
        """

        self.type_constraints[func_typevar].add(constraint)

    def downsize(self) -> None:
        """
        Remove unnecessary members.

        :return:    None
        """
        self.type_constraints = defaultdict(set)

    @staticmethod
    def downsize_region(region: MultiValuedMemory) -> MultiValuedMemory:
        """
        Get rid of unnecessary references in region so that it won't avoid garbage collection on those referenced
        objects.

        :param region:  A MultiValuedMemory region.
        :return:        None
        """
        region._phi_maker = None
        return region

    #
    # Private methods
    #

    @staticmethod
    def _mo_cmp(
        mos_self: set[SimMemoryObject], mos_other: set[SimMemoryObject], addr: int, size: int
    ):  # pylint:disable=unused-argument
        # comparing bytes from two sets of memory objects
        # we don't need to resort to byte-level comparison. object-level is good enough.

        return mos_self == mos_other

    def _make_phi_variable(self, values: set[claripy.ast.Base]) -> claripy.ast.Base | None:
        # we only create a new phi variable if the there is at least one variable involved
        variables = set()
        bits: int | None = None
        for v in values:
            bits = v.size()
            for _, var in self.extract_variables(v):
                variables.add(var)

        if len(variables) <= 1:
            return None

        assert self.successor_block_addr is not None

        # find existing phi variables
        phi_var = self.variable_manager[self.function.addr].make_phi_node(self.successor_block_addr, *variables)
        for var in variables:
            if var is not phi_var:
                self.phi_variables[var] = phi_var

        r = self.top(bits)
        return self.annotate_with_variables(r, [(0, phi_var)])

    def _phi_node_contains(self, phi_variable, variable):
        """
        Checks if `phi_variable` is a phi variable, and if it contains `variable` as a sub-variable.

        :param phi_variable:
        :param variable:
        :return:
        """

        if self.variable_manager[self.function.addr].is_phi_variable(phi_variable):
            return variable in self.variable_manager[self.function.addr].get_phi_subvariables(phi_variable)
        return False
