# pylint:disable=too-many-boolean-expressions
from typing import Set, Optional, Union, Tuple, DefaultDict, List, Any, Dict, TYPE_CHECKING
from collections import defaultdict
import weakref

import ailment
import claripy
import archinfo

from angr.errors import SimMemoryMissingError
from angr.project import Project
from angr.storage.memory_object import SimMemoryObject, SimLabeledMemoryObject
from angr.storage.memory_mixins import LabeledMemory
from angr.engines.light.engine import SimEngineLight
from angr.code_location import CodeLocation
from angr.knowledge_plugins.key_definitions import atoms
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE
from angr.engines.light.data import SpOffset

from .prop_value import PropValue, Detail

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
        block: Optional[ailment.Block],
    ):
        self.has_call = True


class PropagatorState:
    """
    Describes the base state used in Propagator.

    :ivar arch:             Architecture of the binary.
    :ivar gp:               alue of the global pointer for MIPS binaries.
    :ivar _replacements:    Stores expressions to replace, keyed by CodeLocation instances
    :ivar _equivalence:      Stores equivalence constraints that Propagator discovers during the analysis.
    :ivar _only_consts:     Only track constants.
    :ivar _expr_used_locs:  A dict keyed by expressions and valued by CodeLocations where the expression is used.
    :ivar _max_prop_expr_occurrence:    The upperbound for the number of occurrences of an expression for Propagator
                            to propagate that expression to new locations (and replace the original expression).
                            Setting it to 0 disables this limit, which means Propagator will always propagate
                            expressions regardless of how many times it has been propagated.
    """

    __slots__ = (
        "arch",
        "gpr_size",
        "_expr_used_locs",
        "_only_consts",
        "_replacements",
        "_equivalence",
        "project",
        "rda",
        "_store_tops",
        "_gp",
        "_max_prop_expr_occurrence",
        "model",
        "__weakref__",
    )

    _tops = {}

    def __init__(
        self,
        arch: "Arch",
        project: Optional["Project"] = None,
        rda=None,
        replacements: Optional[DefaultDict[CodeLocation, Dict]] = None,
        only_consts: bool = False,
        expr_used_locs: Optional[DefaultDict[Any, Set[CodeLocation]]] = None,
        equivalence: Optional[Set["Equivalence"]] = None,
        store_tops: bool = True,
        gp: Optional[int] = None,
        max_prop_expr_occurrence: int = 1,
        model=None,
    ):
        self.arch = arch
        self.gpr_size = arch.bits // arch.byte_width  # size of the general-purpose registers

        # propagation count of each expression
        self._expr_used_locs = defaultdict(list) if expr_used_locs is None else expr_used_locs
        self._only_consts = only_consts
        self._replacements = defaultdict(dict) if replacements is None else replacements
        self._equivalence: Set[Equivalence] = equivalence if equivalence is not None else set()
        self._store_tops = store_tops
        self._max_prop_expr_occurrence = max_prop_expr_occurrence

        # architecture-specific information
        self._gp: Optional[int] = gp  # Value of gp for MIPS32 and 64 binaries

        self.project = project
        self.model = model
        self.rda = rda

    def __repr__(self):
        return "<PropagatorState>"

    @classmethod
    def initial_state(
        cls,
        project: Project,
        rda=None,
        only_consts=False,
        gp=None,
        do_binops=True,
        store_tops=False,
        func_addr=None,
        max_prop_expr_occurrence=None,
        initial_codeloc=None,
    ):
        raise NotImplementedError()

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
        if isinstance(v, claripy.ast.Bool) and v.op == "BoolV":
            return True
        return False

    @staticmethod
    def _mo_cmp(
        mo_self: Union["SimMemoryObject", "SimLabeledMemoryObject"],
        mo_other: Union["SimMemoryObject", "SimLabeledMemoryObject"],
        addr: int,
        size: int,
    ):  # pylint:disable=unused-argument
        # comparing bytes from two sets of memory objects
        # we don't need to resort to byte-level comparison. object-level is good enough.

        if mo_self.object.symbolic or mo_other.object.symbolic:
            if type(mo_self) is SimLabeledMemoryObject and type(mo_other) is SimLabeledMemoryObject:
                return mo_self.label == mo_other.label and mo_self.object is mo_other.object
            if type(mo_self) is SimMemoryObject and type(mo_other) is SimMemoryObject:
                return mo_self.object is mo_other.object
            # SimMemoryObject vs SimLabeledMemoryObject -> the label must be different
            return False
        return None

    @staticmethod
    def top(bits: int) -> claripy.ast.Bits:
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

        def _get_repl_size(repl_value: Union[Dict, ailment.Expression, claripy.ast.Bits]) -> int:
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
                            t = PropagatorState.top(_get_repl_size(repl))
                            replacements_0[loc][var] = t
                            merge_occurred = True
                        elif (
                            isinstance(replacements_0[loc][var], claripy.ast.Base) or isinstance(repl, claripy.ast.Base)
                        ) and replacements_0[loc][var] is not repl:
                            replacements_0[loc][var] = repl
                            merge_occurred = True
                        elif (
                            not isinstance(replacements_0[loc][var], claripy.ast.Base)
                            and not isinstance(repl, claripy.ast.Base)
                            and replacements_0[loc][var] != repl
                        ):
                            replacements_0[loc][var] = repl
                            merge_occurred = True
        return merge_occurred

    def copy(self) -> "PropagatorState":
        raise NotImplementedError()

    def merge(self, *others):
        state = self.copy()
        merge_occurred = False

        for o in others:
            merge_occurred |= PropagatorState.merge_replacements(state._replacements, o._replacements)

            if state._equivalence != o._equivalence:
                merge_occurred = True
                state._equivalence |= o._equivalence

        return state, merge_occurred

    def init_replacements(self):
        self._replacements = defaultdict(dict)

    def add_replacement(
        self, codeloc: CodeLocation, old, new, force_replace: bool = False
    ) -> bool:  # pylint:disable=unused-argument
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
        if all(self.is_top(replaced_by) for replaced_by in self._replacements[codeloc].values()):
            return False
        return True


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


class RegisterComparisonAnnotation(claripy.Annotation):
    """
    Annotate TOP values that are the result of register values comparing against constant values.
    """

    def __init__(self, offset, size, cmp_op, value):
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


class PropagatorVEXState(PropagatorState):
    """
    Describes the state used in the VEX engine of Propagator.
    """

    __slots__ = (
        "_registers",
        "_stack_variables",
        "do_binops",
        "block_initial_reg_values",
    )

    def __init__(
        self,
        arch,
        project=None,
        rda=None,
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
    ):
        super().__init__(
            arch,
            project=project,
            rda=rda,
            replacements=replacements,
            only_consts=only_consts,
            expr_used_locs=expr_used_locs,
            store_tops=store_tops,
            gp=gp,
            max_prop_expr_occurrence=max_prop_expr_occurrence,
            model=model,
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
        rda=None,
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
            rda=rda,
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

    def copy(self) -> "PropagatorVEXState":
        cp = PropagatorVEXState(
            self.arch,
            project=self.project,
            rda=self.rda,
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
        )

        return cp

    def merge(self, *others: "PropagatorVEXState") -> Tuple["PropagatorVEXState", bool]:
        state = self.copy()
        merge_occurred = state._registers.merge([o._registers for o in others], None)
        merge_occurred |= state._stack_variables.merge([o._stack_variables for o in others], None)
        return state, merge_occurred

    def store_local_variable(self, offset, size, value, endness):  # pylint:disable=unused-argument
        # TODO: Handle size
        self._stack_variables.store(offset, value, size=size, endness=endness)

    def load_local_variable(self, offset, size, endness):  # pylint:disable=unused-argument
        # TODO: Handle size
        try:
            return self._stack_variables.load(offset, size=size, endness=endness)
        except SimMemoryMissingError:
            return self.top(size * self.arch.byte_width)

    def store_register(self, offset, size, value):
        self._registers.store(offset, value, size=size)

    def load_register(self, offset, size):
        # TODO: Fix me
        if size != self.gpr_size:
            return self.top(size * self.arch.byte_width).annotate(RegisterAnnotation(offset, size))

        try:
            v = self._registers.load(offset, size=size)
            if self.is_top(v):
                v = v.annotate(RegisterAnnotation(offset, size))
            return v
        except SimMemoryMissingError:
            return self.top(size * self.arch.byte_width).annotate(RegisterAnnotation(offset, size))

    def register_results(self) -> Dict[str, claripy.ast.BV]:
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
        "codeloc",
        "atom0",
        "atom1",
    )

    def __init__(self, codeloc, atom0, atom1):
        self.codeloc = codeloc
        self.atom0 = atom0
        self.atom1 = atom1

    def __repr__(self):
        return f"<Eq@{self.codeloc!r}: {self.atom0!r}=={self.atom1!r}>"

    def __eq__(self, other):
        return (
            type(other) is Equivalence
            and other.codeloc == self.codeloc
            and other.atom0 == self.atom0
            and other.atom1 == self.atom1
        )

    def __hash__(self):
        return hash((Equivalence, self.codeloc, self.atom0, self.atom1))


class PropagatorAILState(PropagatorState):
    """
    Describes the state used in the AIL engine of Propagator.
    """

    __slots__ = (
        "_registers",
        "_stack_variables",
        "_tmps",
        "temp_expressions",
        "register_expressions",
        "last_stack_store",
        "global_stores",
        "block_initial_reg_values",
        "_sp_adjusted",
    )

    def __init__(
        self,
        arch,
        project=None,
        rda=None,
        replacements=None,
        only_consts=False,
        expr_used_locs=None,
        equivalence=None,
        stack_variables=None,
        registers=None,
        gp=None,
        block_initial_reg_values=None,
        max_prop_expr_occurrence: int = 1,
        sp_adjusted: bool = False,
        model=None,
    ):
        super().__init__(
            arch,
            project=project,
            rda=rda,
            replacements=replacements,
            only_consts=only_consts,
            expr_used_locs=expr_used_locs,
            equivalence=equivalence,
            gp=gp,
            max_prop_expr_occurrence=max_prop_expr_occurrence,
            model=model,
        )

        self._stack_variables = (
            LabeledMemory(memory_id="mem", top_func=self.top, page_kwargs={"mo_cmp": self._mo_cmp})
            if stack_variables is None
            else stack_variables
        )
        self._registers = (
            LabeledMemory(memory_id="reg", top_func=self.top, page_kwargs={"mo_cmp": self._mo_cmp})
            if registers is None
            else registers
        )
        self._tmps = {}
        self.temp_expressions = {}
        self.register_expressions = {}
        self.block_initial_reg_values: DefaultDict[
            Tuple[int, int], List[Tuple[ailment.Expr.Register, ailment.Expr.Const]]
        ] = (defaultdict(list) if block_initial_reg_values is None else block_initial_reg_values)
        self._sp_adjusted: bool = sp_adjusted

        self._registers.set_state(self)
        self._stack_variables.set_state(self)
        # last_stack_store stores the most recent stack store statement with a non-concrete or unresolvable address. we
        # use this information to determine if stack reads after this store can be safely resolved to definitions prior
        # to the stack read.
        self.last_stack_store: Optional[Tuple[int, int, ailment.Stmt.Store]] = None
        self.global_stores: List[Tuple[int, int, Any, ailment.Stmt.Store]] = []

    def __repr__(self):
        return "<PropagatorAILState>"

    @classmethod
    def initial_state(
        cls,
        project: Project,
        rda=None,
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
            rda=rda,
            only_consts=only_consts,
            gp=gp,
            max_prop_expr_occurrence=max_prop_expr_occurrence,
            model=model,
        )
        spoffset_var = ailment.Expr.StackBaseOffset(None, project.arch.bits, 0)
        sp_value = PropValue(
            claripy.BVV(0x7FFF_FF00, project.arch.bits),
            offset_and_details={0: Detail(project.arch.bytes, spoffset_var, initial_codeloc)},
        )
        state.store_register(
            ailment.Expr.Register(None, None, project.arch.sp_offset, project.arch.bits),
            sp_value,
        )

        if project.arch.name == "MIPS64":
            if func_addr is not None:
                reg_expr = ailment.Expr.Register(
                    None, None, project.arch.registers["t9"][0], project.arch.registers["t9"][1]
                )
                reg_value = ailment.Expr.Const(None, None, func_addr, 64)
                state.store_register(
                    reg_expr,
                    PropValue(
                        claripy.BVV(func_addr, 64),
                        offset_and_details={0: Detail(8, reg_value, initial_codeloc)},
                    ),
                )
        elif project.arch.name == "MIPS32":
            if func_addr is not None:
                reg_expr = ailment.Expr.Register(
                    None, None, project.arch.registers["t9"][0], project.arch.registers["t9"][1]
                )
                reg_value = ailment.Expr.Const(None, None, func_addr, 32)
                state.store_register(
                    reg_expr,
                    PropValue(
                        claripy.BVV(func_addr, 32),
                        offset_and_details={0: Detail(4, reg_value, initial_codeloc)},
                    ),
                )
        elif archinfo.arch_arm.is_arm_arch(project.arch):
            # clear fpscr
            reg_expr = ailment.Expr.Register(None, None, *project.arch.registers["fpscr"])
            reg_value = ailment.Expr.Const(None, None, 0, 32)
            state.store_register(
                reg_expr,
                PropValue(claripy.BVV(0, 32), offset_and_details={0: Detail(4, reg_value, initial_codeloc)}),
            )

        if project is not None and project.simos is not None and project.simos.function_initial_registers:
            if func_addr is not None:
                for reg_name, reg_value in project.simos.function_initial_registers.items():
                    reg_size = project.arch.registers[reg_name][1]
                    reg_expr = ailment.Expr.Register(None, None, project.arch.registers[reg_name][0], reg_size)
                    reg_value_expr = ailment.Expr.Const(None, None, reg_value, reg_size * 8)
                    state.store_register(
                        reg_expr,
                        PropValue(
                            claripy.BVV(reg_value, project.arch.bits),
                            offset_and_details={0: Detail(reg_size, reg_value_expr, initial_codeloc)},
                        ),
                    )

        return state

    def copy(self) -> "PropagatorAILState":
        rd = PropagatorAILState(
            self.arch,
            project=self.project,
            rda=self.rda,
            replacements=self._replacements.copy(),
            expr_used_locs=self._expr_used_locs.copy(),
            only_consts=self._only_consts,
            equivalence=self._equivalence.copy(),
            stack_variables=self._stack_variables.copy(),
            registers=self._registers.copy(),
            block_initial_reg_values=self.block_initial_reg_values.copy(),
            # drop tmps
            gp=self._gp,
            max_prop_expr_occurrence=self._max_prop_expr_occurrence,
            sp_adjusted=self._sp_adjusted,
            model=self.model,
        )

        return rd

    @staticmethod
    def is_const_or_register(value: Optional[Union[ailment.Expr.Expression, claripy.ast.Bits]]) -> bool:
        if value is None:
            return False
        if isinstance(value, claripy.ast.BV):
            return not value.symbolic
        if isinstance(value, ailment.Expr.Register):
            return True
        if isinstance(value, ailment.Expr.Const) or (isinstance(value, int) and value == 0):
            return True
        if isinstance(value, ailment.Expr.StackBaseOffset):
            return True
        # more hacks: also store the eq comparisons
        if isinstance(value, ailment.Expr.BinaryOp) and value.op == "CmpEQ":
            if all(isinstance(arg, (ailment.Expr.Const, ailment.Expr.Tmp)) for arg in value.operands):
                return True
        # more hacks: also store the conversions
        if isinstance(value, ailment.Expr.Convert) and PropagatorAILState.is_const_or_register(value.operand):
            return True
        return False

    def merge(self, *others) -> Tuple["PropagatorAILState", bool]:
        state, merge_occurred = super().merge(*others)
        state: "PropagatorAILState"

        merge_occurred |= state._registers.merge([o._registers for o in others], None)
        merge_occurred |= state._stack_variables.merge([o._stack_variables for o in others], None)

        return state, merge_occurred

    def store_temp(self, tmp_idx: int, value: PropValue):
        self._tmps[tmp_idx] = value

    def load_tmp(self, tmp_idx: int) -> Optional[PropValue]:
        return self._tmps.get(tmp_idx, None)

    def store_register(self, reg: ailment.Expr.Register, value: PropValue) -> None:
        if isinstance(value, ailment.Expr.Expression) and value.has_atom(reg, identity=False):
            return

        for offset, chopped_value, size, label in value.value_and_labels():
            self._registers.store(
                reg.reg_offset + offset,
                chopped_value,
                size=size,
                label=label,
                endness=self.project.arch.register_endness,
            )

    def store_stack_variable(
        self, sp_offset: int, new: PropValue, endness=None
    ) -> None:  # pylint:disable=unused-argument
        # normalize sp_offset to handle negative offsets
        sp_offset += 0x65536
        sp_offset &= (1 << self.arch.bits) - 1

        for offset, value, size, label in new.value_and_labels():
            self._stack_variables.store(sp_offset + offset, value, size=size, endness=endness, label=label)

    def load_register(self, reg: ailment.Expr.Register) -> Optional[PropValue]:
        try:
            value, labels = self._registers.load_with_labels(
                reg.reg_offset, size=reg.size, endness=self.project.arch.register_endness
            )
        except SimMemoryMissingError:
            # value does not exist
            return None

        prop_value = PropValue.from_value_and_labels(value, labels)
        return prop_value

    def load_stack_variable(self, sp_offset: int, size, endness=None) -> Optional[PropValue]:
        # normalize sp_offset to handle negative offsets
        sp_offset += 0x65536
        sp_offset &= (1 << self.arch.bits) - 1
        try:
            value, labels = self._stack_variables.load_with_labels(sp_offset, size=size, endness=endness)
        except SimMemoryMissingError as ex:
            # the stack variable does not exist - however, maybe some portion of it exists!
            if ex.missing_addr > sp_offset:
                # some data exist. load again
                try:
                    value, labels = self._stack_variables.load_with_labels(
                        sp_offset, size=ex.missing_addr - sp_offset, endness=endness
                    )
                    # then we zero-extend both the value and labels
                    if value is not None and len(labels) == 1 and labels[0][0] == 0:
                        value = claripy.ZeroExt(ex.missing_size * self.arch.byte_width, value)
                        offset, offset_in_expr, size, label = labels[0]
                        labels = ((offset, offset_in_expr, size + ex.missing_size, label),)
                except SimMemoryMissingError:
                    # failed again... welp
                    return None
            else:
                return None

        prop_value = PropValue.from_value_and_labels(value, labels)
        return prop_value

    def add_replacement(
        self,
        codeloc: CodeLocation,
        old,
        new,
        force_replace: bool = False,
        stmt_to_remove: Optional[CodeLocation] = None,
        bp_as_gpr: bool = False,
    ) -> bool:
        if self._only_consts:
            if self.is_const_or_register(new) or self.is_top(new):
                pass
            else:
                new = self.top(1)

        # do not replace anything with a call expression
        if isinstance(new, ailment.statement.Call):
            return False
        else:
            callexpr_finder = CallExprFinder()
            callexpr_finder.walk_expression(new)
            if callexpr_finder.has_call:
                return False

        if self.is_top(new):
            self._replacements[codeloc][old] = self.top(1)  # placeholder
            return False

        if isinstance(new, ailment.Expr.Expression) and (
            self.is_expression_too_deep(new) or (self.has_ternary_expr(new) and not isinstance(old, ailment.Expr.Tmp))
        ):
            # eliminate the past propagation of this expression
            self._replacements[codeloc][old] = self.top(1)  # placeholder
            self.revert_past_replacements(new, to_replace=old)
            return False

        replaced = False
        # count-based propagation rule only matters when we are performing a full-function copy propagation
        if self._max_prop_expr_occurrence == 0:
            if (
                isinstance(old, ailment.Expr.Tmp)
                or isinstance(old, ailment.Expr.Register)
                and (old.reg_offset == self.arch.sp_offset or (not bp_as_gpr and old.reg_offset == self.arch.bp_offset))
            ):
                self._replacements[codeloc][old] = (
                    new if stmt_to_remove is None else {"expr": new, "stmt_to_remove": stmt_to_remove}
                )
                replaced = True
        else:
            prop_count = 0
            def_ = None
            if isinstance(old, ailment.Expr.Tmp) or isinstance(new, ailment.Expr.Const):
                # we always propagate tmp and constants
                pass
            elif self.is_simple_expression(new):
                # always propagate variables without other operations
                pass
            else:
                if self.rda is not None:
                    if isinstance(old, ailment.Expr.Register):
                        defs = self.rda.get_defs(atoms.Register(old.reg_offset, old.size), codeloc, OP_BEFORE)
                        if len(defs) == 1:
                            def_ = next(iter(defs))
                    elif isinstance(old, ailment.Expr.Load) and isinstance(old.addr, ailment.Expr.StackBaseOffset):
                        defs = self.rda.get_defs(
                            atoms.MemoryLocation(SpOffset(old.addr.bits, old.addr.offset), old.size), codeloc, OP_BEFORE
                        )
                        if len(defs) == 1:
                            def_ = next(iter(defs))
                    if def_ is not None:
                        self._expr_used_locs[def_].append(codeloc)
                        # we must consider known future uses of this definition as well
                        prop_count = max(len(self._expr_used_locs[def_]), len(self.rda.all_uses.get_uses(def_)))
                    else:
                        # multiple definitions or no definitions - do not propagate
                        return False
                else:
                    # when RDA result is not available, we use the expression directly for worse results
                    self._expr_used_locs[new].append(codeloc)
                    prop_count = len(self._expr_used_locs[new])

            if (  # pylint:disable=too-many-boolean-expressions
                force_replace
                or prop_count <= self._max_prop_expr_occurrence
                or isinstance(new, ailment.Expr.StackBaseOffset)
                or isinstance(new, ailment.Expr.Convert)
                and isinstance(new.operand, ailment.Expr.StackBaseOffset)
                or (
                    isinstance(old, ailment.Expr.Register)
                    and self.arch.is_artificial_register(old.reg_offset, old.size)
                )
            ):
                # we can propagate this expression
                self._replacements[codeloc][old] = (
                    new if stmt_to_remove is None else {"expr": new, "stmt_to_remove": stmt_to_remove}
                )
                replaced = True
            else:
                self._replacements[codeloc][old] = self.top(1)  # placeholder

                # eliminate the past propagation of this expression
                for codeloc_ in self._replacements:
                    if old in self._replacements[codeloc_]:
                        self._replacements[codeloc_][old] = self.top(1)
                self.revert_past_replacements(new, to_replace=old, to_replace_def=def_)

        return replaced

    def revert_past_replacements(self, replaced_by, to_replace=None, to_replace_def=None) -> Set[CodeLocation]:
        updated_codelocs = set()
        if self.model.replacements is not None:
            for codeloc_ in self._expr_used_locs[to_replace_def if to_replace_def is not None else to_replace]:
                for key, replace_with in list(self.model.replacements[codeloc_].items()):
                    if isinstance(replace_with, dict):
                        replace_with = replace_with["expr"]
                    if not self.is_top(replace_with) and replace_with == replaced_by:
                        self.model.replacements[codeloc_][key] = self.top(1)
                        updated_codelocs.add(codeloc_)

        for codeloc_ in self._expr_used_locs[to_replace_def if to_replace_def is not None else to_replace]:
            if codeloc_ in self._replacements:
                for key, replace_with in list(self._replacements[codeloc_].items()):
                    if isinstance(replace_with, dict):
                        replace_with = replace_with["expr"]
                    if not self.is_top(replace_with) and replace_with == replaced_by:
                        if to_replace.likes(key):
                            self._replacements[codeloc_][key] = self.top(1)
                            updated_codelocs.add(codeloc_)

        return updated_codelocs

    def add_equivalence(self, codeloc, old, new):
        eq = Equivalence(codeloc, old, new)
        self._equivalence.add(eq)

    @staticmethod
    def is_simple_expression(expr: ailment.Expr.Expression) -> bool:
        if PropagatorAILState.is_shallow_expression(expr):
            return True
        if (
            isinstance(expr, ailment.Expr.BinaryOp)
            and expr.op in {"Add", "Sub"}
            and (
                isinstance(expr.operands[0], ailment.Expr.Register)
                and PropagatorAILState.is_global_variable_load(expr.operands[1])
                or isinstance(expr.operands[1], ailment.Expr.Register)
                and PropagatorAILState.is_global_variable_load(expr.operands[0])
            )
        ):
            return True
        return False

    @staticmethod
    def is_shallow_expression(expr: ailment.Expr.Expression) -> bool:
        return expr.depth <= 0 or PropagatorAILState.is_global_variable_load(expr)

    @staticmethod
    def is_global_variable_load(expr: ailment.Expr.Expression) -> bool:
        if isinstance(expr, ailment.Expr.Load) and isinstance(expr.addr, ailment.Expr.Const):
            return True
        if isinstance(expr, ailment.Expr.Convert) and PropagatorAILState.is_global_variable_load(expr.operand):
            return True
        return False

    @staticmethod
    def is_expression_too_deep(expr: ailment.Expr.Expression) -> bool:
        # determine if the expression is too deep to propagate
        return expr.depth >= 30

    @staticmethod
    def has_ternary_expr(expr: ailment.Expr.Expression) -> bool:
        class _has_ternary_expr:
            """
            Temporary class holding values.
            """

            v = False

        def _handle_ITE(*args, **kwargs):  # pylint:disable=unused-argument
            _has_ternary_expr.v = True

        walker = ailment.AILBlockWalkerBase()
        walker.expr_handlers[ailment.Expr.ITE] = _handle_ITE
        walker.walk_expression(expr, 0, None, None)
        return _has_ternary_expr.v
