from collections import defaultdict
from typing import List, Set, Dict, Tuple, Optional
import logging

from .domain import (BaseExpression, BaseConstraint, LocalVariable, Constant, Parameter, Assignment, Store, Load,
                     CmpBase, CmpLtExpr, CmpLeExpr, CmpLtN, Add, AddN)
from .descriptors import BaseDescriptor, SimpleLoopVariable
from .types import Buffer, Pointer


_l = logging.getLogger(name=__name__)
_l.setLevel(logging.DEBUG)


class FuncProtoSolver:
    def __init__(self, constraints: Set[BaseConstraint]):

        self._original_constraints = constraints

        self._constraints: Set[BaseConstraint] = set()
        self._var_descriptors: Dict[BaseExpression,Set[BaseDescriptor]] = defaultdict(set)
        self.param_descriptors: Dict[Parameter,Set[BaseDescriptor]] = defaultdict(set)

        self._constraints_by_expr: Dict[BaseExpression, Set[BaseConstraint]] = defaultdict(set)

        self._constraints = self._eliminate_equivalent_variables(self._original_constraints)
        self._categorize_constraints()
        self._solve()

    def _solve(self):
        self._find_loops_a()
        self._find_buffer_loads()
        self._find_buffer_stores()

    def _categorize_constraints(self):
        constraints_by_expr: Dict[BaseExpression, Set[BaseConstraint]] = defaultdict(set)
        for con in self._constraints:
            if isinstance(con, Assignment):
                constraints_by_expr[con.variable].add(con)
            elif isinstance(con, CmpBase):
                constraints_by_expr[con.variable].add(con)

        self._constraints_by_expr = constraints_by_expr

    def _eliminate_equivalent_variables(self, constraints: Set[BaseConstraint]) -> Set[BaseConstraint]:
        """
        Perform redundant variable elimination on all variables.

        A := B  ==>  A can be represented by B iff this is the only assignment on A
        """
        assignments_by_variable: Dict[LocalVariable,Set[BaseExpression]] = defaultdict(set)

        for con in constraints:
            if isinstance(con, Assignment) \
                    and isinstance(con.variable, LocalVariable):
                assignments_by_variable[con.variable].add(con.expression)

        equivalence: Dict[LocalVariable,Set[LocalVariable]] = defaultdict(set)
        for variable, assigned_exprs in assignments_by_variable.items():
            for expr in assigned_exprs:
                if isinstance(expr, LocalVariable):
                    # A == B
                    equivalence[variable].add(expr)

        # build a closure
        changed = True
        while changed:
            changed = False
            for variable in list(equivalence.keys()):
                for equal_to in list(equivalence[variable]):
                    if variable == equal_to:
                        equivalence[variable].remove(equal_to)
                        changed = True
                    if equal_to in equivalence:
                        equivalence[variable].remove(equal_to)
                        equivalence[variable] |= equivalence[equal_to]
                        changed = True

        equivalence = dict((k, v) for k, v in equivalence.items() if v)

        # simplify all constraints
        simplified_constraints: Set[BaseConstraint] = set()
        for con in constraints:
            new_cons = con.replace(equivalence)
            simplified_constraints |= new_cons
        return simplified_constraints

    #
    # Util methods
    #

    def _get_root_definitions(self, var: LocalVariable) -> Set[BaseExpression]:
        """
        Find the root definition of a given variable. Stops tracing back when the variable is defined by another
        non-local-variable expression.

        :param var:     The variable to find root definition for.
        :return:        The set of expressions that was assigned to it.
        """

        queue: List[BaseExpression] = [var]
        encountered: Set[BaseExpression] = set()
        result = set()
        while queue:
            var_ = queue.pop(0)
            encountered.add(var_)
            if isinstance(var_, LocalVariable):
                # get its definition
                if var_ in self._constraints_by_expr:
                    assignments = [con for con in self._constraints_by_expr[var_] if isinstance(con, Assignment)]
                    for assign in assignments:
                        if assign.expression not in encountered: queue.append(assign.expression)
                        else: result.add(assign.expression)
                    continue

            result.add(var_)

        return result

    def _get_root_definitions_wo_addn(self, var: LocalVariable) -> Set[BaseExpression]:

        queue: List[BaseExpression] = [var]
        encountered: Set[BaseExpression] = set()
        result = set()
        while queue:
            var_ = queue.pop(0)
            encountered.add(var_)
            if isinstance(var_, LocalVariable):
                # get its definition
                if var_ in self._constraints_by_expr:
                    assignments = [con for con in self._constraints_by_expr[var_] if isinstance(con, Assignment)]
                    for assign in assignments:
                        expr = assign.expression
                        if isinstance(expr, AddN):
                            # drop N
                            expr = expr.variable
                        if expr not in encountered: queue.append(expr)
                        else: result.add(expr)
                    continue

            result.add(var_)

        return result

    #
    # Loop A
    #

    def _find_loops_a(self) -> None:
        """
        Find loops that satisfy the following models:

        Model A::
            i0 = A
            for (i1 = i0; i1 < B; i1 += C) {
                // do something
            }
        """
        # find i1
        for var, constraints in self._constraints_by_expr.items():
            incrementers, ltchecks = self._loop_a_incrementers_and_ltchecks(constraints)
            if incrementers and ltchecks:
                # source variables of rhs of incrementers
                incrementers_rhs_vars = set(inc.expression.variable for inc in incrementers
                                            if isinstance(inc, Assignment) and isinstance(inc.expression, AddN)
                                            )
                # find initializer
                initializers = set()
                for inc_rhs_var in incrementers_rhs_vars:
                    if inc_rhs_var in self._constraints_by_expr:
                        initializers |= self._loop_a_initializers(self._constraints_by_expr[inc_rhs_var],
                                                                  incrementers_rhs_vars)

                if initializers:
                    # found all three
                    _l.debug("Found a loop-a variable with the following constraints. incrementers: %r, ltchecks: %r,"
                             "intializers: %r", incrementers, ltchecks, initializers)
                    if len(incrementers) >= 1 and len(ltchecks) == 1 and len(initializers) == 1:
                        inc = next(iter(incrementers))
                        ltcheck = next(iter(ltchecks))
                        init = next(iter(initializers))

                        interval = None
                        ubound = None
                        lbound = None
                        if isinstance(inc, Assignment) and isinstance(inc.expression, AddN):
                            interval = inc.expression.n
                        if isinstance(ltcheck, CmpLtN):
                            ubound = ltcheck.n
                        elif isinstance(ltcheck, CmpLtExpr):
                            ubound = tuple(self._get_root_definitions(ltcheck.expression))
                        if isinstance(init, Assignment) and isinstance(init.expression, Constant):
                            lbound = init.expression.con
                        self._var_descriptors[var].add(SimpleLoopVariable(64,  # TODO: Use the correct bits
                                                                          lbound,
                                                                          ubound,
                                                                          interval
                                                                          )
                                                       )

    @staticmethod
    def _loop_a_incrementers_and_ltchecks(constraints: Set[BaseConstraint]) -> Tuple[Set[BaseConstraint],Set[BaseConstraint]]:
        incrementers = set()
        lt_checks = set()
        for con in constraints:
            # i1 += C
            is_incrementer = lambda x: isinstance(x, Assignment) and isinstance(x.expression, AddN)
            # i1 < B
            is_lt_check = lambda x: isinstance(x, (CmpLtExpr, CmpLeExpr, CmpLtN))

            if is_incrementer(con):
                incrementers.add(con)
            elif is_lt_check(con):
                lt_checks.add(con)

        return incrementers, lt_checks

    @staticmethod
    def _loop_a_initializers(constraints: Set[BaseConstraint], exclude: Set[LocalVariable]) -> Set[BaseConstraint]:
        initializers = set()
        for con in constraints:
            # i1 = i0
            is_initializer = lambda x: isinstance(x, Assignment) and (
                (isinstance(x.expression, LocalVariable) and x.expression not in exclude)
                or isinstance(x.expression, Constant)
            )
            if is_initializer(con):
                initializers.add(con)
        return initializers

    #
    # Common methods for both buffer loads and stores
    #

    def _model_a_find_addr_base_and_inc(self, constraint) -> Tuple[Optional[Set[BaseExpression]],Optional[Set[BaseExpression]]]:
        addr = constraint.addr
        # addr = addr_base + addr_inc
        addr_base: Optional[BaseExpression] = None
        addr_inc: Optional[BaseExpression] = None
        while True:
            if isinstance(addr, LocalVariable):
                addr_defs = self._get_root_definitions(addr)
                if not addr_defs or len(addr_defs) == 1 and next(iter(addr_defs)) is addr:
                    # couldn't find who defined it!
                    break
                addr = next(iter(addr_defs))
            elif isinstance(addr, Add):
                addr_base, addr_inc = addr.variable, addr.expression
                break
            else:
                # unsupported
                return None, None

        if addr_base is None or addr_inc is None:
            return None, None

        if isinstance(addr_base, LocalVariable):
            addr_bases = self._get_root_definitions(addr_base)
        else:
            addr_bases = {addr_base}

        if isinstance(addr_inc, LocalVariable):
            addr_incs = self._get_root_definitions_wo_addn(addr_inc)
        else:
            addr_incs = {addr_inc}

        return addr_bases, addr_incs

    #
    # Buffer loads
    #

    def _find_buffer_loads(self) -> None:
        """
        Find buffer loads that satisfy the following models:

        Model A::
            v = paramN + loop_var
            ? = *(v)
        """

        # Find all load constraints
        for con in self._constraints:
            if isinstance(con, Load):
                fits = self._load_addr_fits_model_a(con)

    def _load_addr_fits_model_a(self, constraint: Load) -> bool:
        addr_bases, addr_incs = self._model_a_find_addr_base_and_inc(constraint)
        if addr_bases is None or addr_incs is None:
            return False

        # filter out parameters from bases
        bases = set(b for b in addr_bases if isinstance(b, Parameter))
        # filter out inc-expressions who depend on loop variables
        for inc in addr_incs:
            if isinstance(inc, LocalVariable):
                if inc in self._var_descriptors:
                    # found a descriptor for it!
                    descs = self._var_descriptors[inc]
                    if len(descs) == 1:
                        desc = next(iter(descs))
                        if isinstance(desc, SimpleLoopVariable):
                            # it's a buffer!
                            element_count = None
                            if isinstance(desc.lbound, int) and isinstance(desc.ubound, int):
                                element_count = desc.ubound - desc.lbound
                            buf_desc = Buffer(lbound=desc.lbound, ubound=desc.ubound,
                                              element_size=1,  # TODO: FIXME
                                              element_count=element_count,
                                              in_=True,
                                              out_=False
                                              )
                            base_desc = Pointer(buf_desc, in_=True, out_=False)
                            for base in bases:
                                self.param_descriptors[base].add(base_desc)
                        return True

    #
    # Buffer stores
    #

    def _find_buffer_stores(self) -> None:
        """
        Find buffer stores that satisfy the following models:

        Model A::
            v = paramN + loop_var
            *(v) = ?
        """

        # Find all load constraints
        for con in self._constraints:
            if isinstance(con, Store):
                fits = self._store_addr_fits_model_a(con)

    def _store_addr_fits_model_a(self, constraint: Store) -> bool:
        addr_bases, addr_incs = self._model_a_find_addr_base_and_inc(constraint)
        if addr_bases is None or addr_incs is None:
            return False

        # filter out parameters from bases
        bases = set(b for b in addr_bases if isinstance(b, Parameter))
        # filter out inc-expressions who depend on loop variables
        for inc in addr_incs:
            if isinstance(inc, LocalVariable):
                if inc in self._var_descriptors:
                    # found a descriptor for it!
                    descs = self._var_descriptors[inc]
                    if len(descs) == 1:
                        desc = next(iter(descs))
                        if isinstance(desc, SimpleLoopVariable):
                            # it's a buffer!
                            element_count = None
                            if isinstance(desc.lbound, int) and isinstance(desc.ubound, int):
                                element_count = desc.ubound - desc.lbound
                            buf_desc = Buffer(lbound=desc.lbound, ubound=desc.ubound,
                                              element_size=1,  # TODO: FIXME
                                              element_count=element_count,
                                              in_=False,
                                              out_=True,
                                              )
                            base_desc = Pointer(buf_desc, in_=True, out_=False)
                            for base in bases:
                                self.param_descriptors[base].add(base_desc)
                        return True
