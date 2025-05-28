# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
from abc import abstractmethod
from typing import Any, TYPE_CHECKING
from collections import defaultdict
import weakref

from typing_extensions import Self

import angr.ailment as ailment
import claripy
import archinfo

from angr.errors import SimMemoryMissingError
from angr.project import Project
from angr.storage.memory_object import SimMemoryObject, SimLabeledMemoryObject
from angr.storage.memory_mixins import LabeledMemory
from angr.engines.light.engine import SimEngineLight
from angr.code_location import CodeLocation


if TYPE_CHECKING:
    from archinfo import Arch


class CallExprFinder(ailment.AILBlockWalker):
    """
    Walks an AIL expression to find if it contains a call expression anywhere.
    """

    def __init__(self):
        super().__init__()
        self.has_call = False

    # pylint:disable=unused-argument
    def _handle_CallExpr(
        self,
        expr_idx: int,
        expr: ailment.Stmt.Call,
        stmt_idx: int,
        stmt: ailment.Stmt.Statement,
        block: ailment.Block | None,
    ):
        self.has_call = True


class PropagatorState:
    """
    Describes the base state used in Propagator.

    :ivar arch:             Architecture of the binary.
    :ivar gp:               value of the global pointer for MIPS binaries.
    :ivar _replacements:    Stores expressions to replace, keyed by CodeLocation instances
    :ivar _only_consts:     Only track constants.
    :ivar _expr_used_locs:  A dict keyed by expressions and valued by CodeLocations where the expression is used.
    :ivar _max_prop_expr_occurrence:    The upperbound for the number of occurrences of an expression for Propagator
                            to propagate that expression to new locations (and replace the original expression).
                            Setting it to 0 disables this limit, which means Propagator will always propagate
                            expressions regardless of how many times it has been propagated.
    """

    __slots__ = (
        "__weakref__",
        "_artificial_reg_offsets",
        "_expr_used_locs",
        "_gp",
        "_max_prop_expr_occurrence",
        "_only_consts",
        "_replacements",
        "_store_tops",
        "arch",
        "gpr_size",
        "model",
        "project",
    )

    _tops = {}

    def __init__(
        self,
        arch: Arch,
        project: Project | None = None,
        replacements: defaultdict[CodeLocation, dict] | None = None,
        only_consts: bool = False,
        expr_used_locs: defaultdict[Any, set[CodeLocation]] | None = None,
        store_tops: bool = True,
        gp: int | None = None,
        max_prop_expr_occurrence: int = 1,
        model=None,
        artificial_reg_offsets=None,
    ):
        self.arch = arch
        self.gpr_size = arch.bits // arch.byte_width  # size of the general-purpose registers

        # propagation count of each expression
        self._expr_used_locs = defaultdict(list) if expr_used_locs is None else expr_used_locs
        self._only_consts = only_consts
        self._replacements = defaultdict(dict) if replacements is None else replacements
        self._store_tops = store_tops
        self._max_prop_expr_occurrence = max_prop_expr_occurrence
        self._artificial_reg_offsets = artificial_reg_offsets if artificial_reg_offsets is not None else set()

        # architecture-specific information
        self._gp: int | None = gp  # Value of gp for MIPS32 and 64 binaries

        self.project = project
        self.model = model

    def __repr__(self) -> str:
        return "<PropagatorState>"

    @classmethod
    def initial_state(
        cls,
        project: Project,
        only_consts=False,
        gp=None,
        do_binops=True,
        store_tops=False,
        func_addr=None,
        max_prop_expr_occurrence=None,
        initial_codeloc=None,
    ):
        raise NotImplementedError

    def _get_weakref(self):
        return weakref.proxy(self)

    @staticmethod
    def _is_const(v) -> bool:
        if isinstance(v, (int, ailment.Expr.Const)):
            return True
        if isinstance(v, claripy.ast.BV) and v.op == "BVV":
            return True
        if isinstance(v, claripy.ast.FP) and v.op == "FPV":
            return True
        return bool(isinstance(v, claripy.ast.Bool) and v.op == "BoolV")

    @staticmethod
    def _mo_cmp(
        mo_self: SimMemoryObject | SimLabeledMemoryObject,
        mo_other: SimMemoryObject | SimLabeledMemoryObject,
        addr: int,
        size: int,
    ):  # pylint:disable=unused-argument
        # comparing bytes from two sets of memory objects
        # we don't need to resort to byte-level comparison. object-level is good enough.

        # TODO what if object is bytes?
        if mo_self.object.symbolic or mo_other.object.symbolic:
            if type(mo_self) is SimLabeledMemoryObject and type(mo_other) is SimLabeledMemoryObject:
                return mo_self.label == mo_other.label and mo_self.object is mo_other.object
            if type(mo_self) is SimMemoryObject and type(mo_other) is SimMemoryObject:
                return mo_self.object is mo_other.object
            # SimMemoryObject vs SimLabeledMemoryObject -> the label must be different
            return False
        return None

    @staticmethod
    def top(bits: int) -> claripy.ast.BV:
        """
        Get a TOP value.

        :param size:    Width of the TOP value (in bits).
        :return:        The TOP value.
        """

        if bits in PropagatorState._tops:
            return PropagatorState._tops[bits]
        r = claripy.BVS("TOP", bits, explicit_name=True)
        PropagatorState._tops[bits] = r
        return r

    @staticmethod
    def is_top(expr) -> bool:
        """
        Check if the given expression is a TOP value.

        :param expr:    The given expression.
        :return:        True if the expression is TOP, False otherwise.
        """
        if isinstance(expr, claripy.ast.Base):
            if expr.op == "BVS" and expr.args[0] == "TOP":
                return True
            if "TOP" in expr.variables:
                return True
        return False

    @staticmethod
    def merge_replacements(replacements_0, replacements_1) -> bool:
        """
        The replacement merging logic is special: replacements_1 is the newer replacement result and replacement_0 is
        the older result waiting to be updated. When both replacements_1 and replacement_0 have a non-top value for the
        same variable and code location, we will update the slot in replacement_0 with the value from replacement_1.

        :return:            Whether merging has happened or not.
        """

        def _get_repl_size(repl_value: dict | ailment.Expression | claripy.ast.Bits) -> int:
            if isinstance(repl_value, dict):
                return _get_repl_size(repl_value["expr"])
            if isinstance(repl_value, ailment.Expression):
                return repl_value.bits
            return repl_value.size()

        merge_occurred = False
        for loc, vars_ in replacements_1.items():
            if loc not in replacements_0:
                replacements_0[loc] = vars_.copy()
                merge_occurred = True
            else:
                for var, repl in vars_.items():
                    if var not in replacements_0[loc]:
                        replacements_0[loc][var] = repl
                        merge_occurred = True
                    else:
                        if PropagatorState.is_top(repl) or PropagatorState.is_top(replacements_0[loc][var]):
                            if not PropagatorState.is_top(replacements_0[loc][var]):
                                t = PropagatorState.top(_get_repl_size(repl))
                                replacements_0[loc][var] = t
                                merge_occurred = True
                        elif (
                            (
                                isinstance(replacements_0[loc][var], claripy.ast.Base)
                                or isinstance(repl, claripy.ast.Base)
                            )
                            and replacements_0[loc][var] is not repl
                        ) or (
                            not isinstance(replacements_0[loc][var], claripy.ast.Base)
                            and not isinstance(repl, claripy.ast.Base)
                            and replacements_0[loc][var] != repl
                        ):
                            replacements_0[loc][var] = repl
                            merge_occurred = True
        return merge_occurred

    @abstractmethod
    def copy(self) -> Self:
        raise NotImplementedError

    def merge(self, *others: Self) -> tuple[Self, bool]:
        state = self.copy()
        merge_occurred = False

        for o in others:
            merge_occurred |= PropagatorState.merge_replacements(state._replacements, o._replacements)

        return state, merge_occurred

    def init_replacements(self):
        self._replacements = defaultdict(dict)

    def add_replacement(
        self, codeloc: CodeLocation, old, new, force_replace: bool = False  # pylint:disable=unused-argument
    ) -> bool:
        """
        Add a replacement record: Replacing expression `old` with `new` at program location `codeloc`.
        If the self._only_consts flag is set to true, only constant values will be set.

        :param codeloc:                 The code location.
        :param old:                     The expression to be replaced.
        :param new:                     The expression to replace with.
        :return:                        True if the replacement will happen. False otherwise.
        """
        if self.is_top(new):
            return False

        replaced = False
        if self._only_consts:
            if self._is_const(new) or self.is_top(new):
                self._replacements[codeloc][old] = new
                replaced = True
        else:
            self._replacements[codeloc][old] = new
            replaced = True

        return replaced

    def filter_replacements(self):
        pass

    def has_replacements_at(self, codeloc: CodeLocation) -> bool:
        if not self._replacements:
            return False
        if codeloc not in self._replacements:
            return False
        return not all(self.is_top(replaced_by) for replaced_by in self._replacements[codeloc].values())


# VEX state


class RegisterAnnotation(claripy.Annotation):
    """
    Annotates TOP values that are coming from registers.
    """

    def __init__(self, offset, size):
        self.offset = offset
        self.size = size

    @property
    def eliminatable(self) -> bool:
        return True

    @property
    def relocatable(self) -> bool:
        return True

    def __hash__(self):
        return hash((RegisterAnnotation, self.offset, self.size))

    def __eq__(self, other):
        return type(other) is RegisterAnnotation and self.offset == other.offset and self.size == other.size


class RegisterComparisonAnnotation(claripy.Annotation):
    """
    Annotate TOP values that are the result of register values comparing against constant values.
    """

    def __init__(self, offset: int, size: int, cmp_op: str, value: int):
        self.offset = offset
        self.size = size
        self.cmp_op = cmp_op
        self.value = value

    @property
    def eliminatable(self) -> bool:
        return True

    @property
    def relocatable(self) -> bool:
        return True

    def __hash__(self):
        return hash((RegisterComparisonAnnotation, self.offset, self.size, self.cmp_op, self.value))

    def __eq__(self, other):
        return (
            type(other) is RegisterComparisonAnnotation
            and self.offset == other.offset
            and self.size == other.size
            and self.cmp_op == other.cmp_op
            and self.value == other.value
        )


class PropagatorVEXState(PropagatorState):
    """
    Describes the state used in the VEX engine of Propagator.
    """

    __slots__ = (
        "_registers",
        "_stack_variables",
        "block_initial_reg_values",
        "do_binops",
    )

    def __init__(
        self,
        arch,
        project=None,
        registers=None,
        local_variables=None,
        replacements=None,
        only_consts=False,
        expr_used_locs=None,
        do_binops=True,
        store_tops=True,
        block_initial_reg_values=None,
        gp=None,
        max_prop_expr_occurrence: int = 1,
        model=None,
        artificial_reg_offsets=None,
    ):
        super().__init__(
            arch,
            project=project,
            replacements=replacements,
            only_consts=only_consts,
            expr_used_locs=expr_used_locs,
            store_tops=store_tops,
            gp=gp,
            max_prop_expr_occurrence=max_prop_expr_occurrence,
            model=model,
            artificial_reg_offsets=artificial_reg_offsets,
        )
        self.do_binops = do_binops
        self._registers = (
            LabeledMemory(memory_id="reg", top_func=self.top, page_kwargs={"mo_cmp": self._mo_cmp})
            if registers is None
            else registers
        )
        self._stack_variables = (
            LabeledMemory(memory_id="mem", top_func=self.top, page_kwargs={"mo_cmp": self._mo_cmp})
            if local_variables is None
            else local_variables
        )

        self._registers.set_state(self)
        self._stack_variables.set_state(self)
        self.block_initial_reg_values = (
            defaultdict(list) if block_initial_reg_values is None else block_initial_reg_values
        )

    def __repr__(self):
        return "<PropagatorVEXState>"

    @classmethod
    def initial_state(
        cls,
        project,
        only_consts=False,
        gp=None,
        do_binops=True,
        store_tops=False,
        func_addr=None,
        max_prop_expr_occurrence=None,
        initial_codeloc=None,
        model=None,
    ):
        state = cls(
            project.arch,
            project=project,
            only_consts=only_consts,
            do_binops=do_binops,
            store_tops=store_tops,
            gp=gp,
            max_prop_expr_occurrence=max_prop_expr_occurrence,
            model=model,
        )
        spoffset_var = SimEngineLight.sp_offset(project.arch.bits, 0)
        state.store_register(
            project.arch.sp_offset,
            project.arch.bytes,
            spoffset_var,
        )
        if project.arch.name == "MIPS64":
            if func_addr is not None:
                state.store_register(  # pylint:disable=too-many-function-args
                    project.arch.registers["t9"][0],
                    project.arch.registers["t9"][1],
                    claripy.BVV(func_addr, 64),
                )
        elif project.arch.name == "MIPS32":
            if func_addr is not None:
                state.store_register(  # pylint:disable=too-many-function-args
                    project.arch.registers["t9"][0],
                    project.arch.registers["t9"][1],
                    claripy.BVV(func_addr, 32),
                )
        elif archinfo.arch_arm.is_arm_arch(project.arch):
            state.store_register(  # pylint:disable=too-many-function-args
                project.arch.registers["fpscr"][0],
                project.arch.registers["fpscr"][1],
                claripy.BVV(0, 32),
            )
        return state

    def copy(self) -> PropagatorVEXState:
        return PropagatorVEXState(
            self.arch,
            project=self.project,
            registers=self._registers.copy(),
            local_variables=self._stack_variables.copy(),
            replacements=self._replacements.copy(),
            expr_used_locs=self._expr_used_locs.copy(),
            only_consts=self._only_consts,
            do_binops=self.do_binops,
            store_tops=self._store_tops,
            block_initial_reg_values=self.block_initial_reg_values.copy(),
            gp=self._gp,
            max_prop_expr_occurrence=self._max_prop_expr_occurrence,
            model=self.model,
            artificial_reg_offsets=self._artificial_reg_offsets,
        )

    def merge(self, *others: PropagatorVEXState) -> tuple[PropagatorVEXState, bool]:
        state = self.copy()
        merge_occurred = state._registers.merge([o._registers for o in others], None)
        merge_occurred |= state._stack_variables.merge([o._stack_variables for o in others], None)
        return state, merge_occurred

    def store_local_variable(self, offset, size, value, endness):  # pylint:disable=unused-argument
        # TODO: Handle size
        self._stack_variables.store(offset, value, size=size, endness=endness)

    def load_local_variable(self, offset, size, endness) -> claripy.ast.BV:  # pylint:disable=unused-argument
        # TODO: Handle size
        try:
            return self._stack_variables.load(offset, size=size, endness=endness)
        except SimMemoryMissingError:
            return self.top(size * self.arch.byte_width)

    def store_register(self, offset, size, value):
        self._registers.store(offset, value, size=size)

    def load_register(self, offset, size):
        try:
            v = self._registers.load(offset, size=size)
            if self.is_top(v):
                v = v.annotate(RegisterAnnotation(offset, size))
            return v
        except SimMemoryMissingError:
            return self.top(size * self.arch.byte_width).annotate(RegisterAnnotation(offset, size))

    def register_results(self) -> dict[str, claripy.ast.BV]:
        result = {}
        for reg, (offset, size) in self.arch.registers.items():
            val = self.load_register(offset, size)
            if not self.is_top(val):
                result[reg] = val
        return result


# AIL state


class Equivalence:
    """
    Describes an equivalence relationship between two atoms.
    """

    __slots__ = (
        "atom0",
        "atom1",
        "codeloc",
        "is_weakassignment",
    )

    def __init__(self, codeloc, atom0, atom1, is_weakassignment: bool = False):
        self.codeloc = codeloc
        self.atom0 = atom0
        self.atom1 = atom1
        self.is_weakassignment = is_weakassignment

    def __repr__(self):
        return f"<Eq@{self.codeloc!r}: {self.atom0!r}=={self.atom1!r}>"

    def __eq__(self, other):
        return (
            type(other) is Equivalence
            and other.codeloc == self.codeloc
            and other.atom0 == self.atom0
            and other.atom1 == self.atom1
            and other.is_weakassignment == self.is_weakassignment
        )

    def __hash__(self):
        return hash((Equivalence, self.codeloc, self.atom0, self.atom1, self.is_weakassignment))
