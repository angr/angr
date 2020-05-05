
import itertools
from collections import defaultdict

import networkx

from .typevars import Existence, Equivalence, Subtype, TypeVariable, DerivedTypeVariable, HasField
from .typeconsts import (BottomType, TopType, TypeConstant, Int, Int8, Int16, Int32, Int64, Pointer32, Pointer64,
                         Struct, int_type, TypeVariableReference)


BASE_LATTICE = networkx.DiGraph()
BASE_LATTICE.add_edge(TopType, Int)
BASE_LATTICE.add_edge(Int, Pointer64)
BASE_LATTICE.add_edge(Int, Int32)
BASE_LATTICE.add_edge(Pointer64, Int64)
BASE_LATTICE.add_edge(Int64, BottomType)
BASE_LATTICE.add_edge(Int32, BottomType)
BASE_LATTICE.add_edge(Int16, BottomType)
BASE_LATTICE.add_edge(Int, Int16)
BASE_LATTICE.add_edge(Int8, BottomType)
BASE_LATTICE.add_edge(Int, Int8)


class RecursiveType:
    def __init__(self, typevar, offset):
        self.typevar = typevar
        self.offset = offset


class SimpleSolver:
    """
    SimpleSolver is, literally, a simple, unification-based type constraint solver.
    """
    def __init__(self, constraints):
        self._constraints = constraints

        #
        # Solving state
        #
        self._equivalence = { }
        self._lower_bounds = defaultdict(BottomType)
        self._upper_bounds = defaultdict(TopType)
        self._recursive_types = defaultdict(set)

        self.solve()
        self.solution = self.determine()

    def solve(self):
        # import pprint
        # pprint.pprint(self._constraints)

        constraints = self._handle_equivalence()
        subtypevars, supertypevars = self._calculate_closure(constraints)
        self._find_recursive_types(subtypevars)
        self._compute_lower_upper_bounds(subtypevars, supertypevars)
        # self._unify_struct_fields()
        # import pprint
        # print("Lower bounds")
        # pprint.pprint(self._lower_bounds)
        # print("Upper bounds")
        # pprint.pprint(self._upper_bounds)


        # import pprint
        # print("Lower bounds")
        # pprint.pprint(self._lower_bounds)
        # print("Upper bounds")
        # pprint.pprint(self._upper_bounds)

    def determine(self):

        solution = { }

        for v in self._lower_bounds:
            if isinstance(v, TypeVariable) and not isinstance(v, DerivedTypeVariable):
                lb = self._lower_bounds[v]
                if isinstance(lb, BottomType):
                    # use its upper bound instead
                    solution[v] = self._upper_bounds[v]
                else:
                    solution[v] = lb

        for v in self._upper_bounds:
            if v not in solution:
                ub = self._upper_bounds[v]
                if not isinstance(ub, TopType):
                    solution[v] = ub

        for v in self._equivalence:
            if v not in solution:
                solution[v] = solution.get(self._equivalence[v], None)

        # import pprint
        # print("Lower bounds")
        # pprint.pprint(self._lower_bounds)
        # print("Upper bounds")
        # pprint.pprint(self._upper_bounds)
        # print("Solution")
        # pprint.pprint(solution)
        return solution

    def _handle_equivalence(self):

        graph = networkx.Graph()

        replacements = { }
        constraints = set()

        # collect equivalence relations
        for constraint in self._constraints:

            if isinstance(constraint, Existence):
                pass

            elif isinstance(constraint, Equivalence):
                # type_a == type_b
                # we apply unification and removes one of them
                ta, tb = constraint.type_a, constraint.type_b
                graph.add_edge(ta, tb)

            elif isinstance(constraint, Subtype):
                pass

            else:
                raise NotImplementedError("Unsupported instance type %s." % type(constraint))

        for components in networkx.connected_components(graph):
            components_lst = list(components)
            representative = components_lst[0]
            for tv in components_lst[1:]:
                replacements[tv] = representative

        # replace
        for constraint in self._constraints:
            if isinstance(constraint, Existence):
                replaced, new_constraint = constraint.replace(replacements)

                if replaced:
                    constraints.add(new_constraint)
                else:
                    constraints.add(constraint)

            elif isinstance(constraint, Subtype):
                # subtype <: supertype
                # replace type variables
                replaced, new_constraint = constraint.replace(replacements)

                if replaced:
                    constraints.add(new_constraint)
                else:
                    constraints.add(constraint)

        # import pprint
        # print("Replacements")
        # pprint.pprint(replacements)
        # print("Constraints (after replacement)")
        # pprint.pprint(constraints)

        self._equivalence = replacements
        return constraints

    @staticmethod
    def _calculate_closure(constraints):

        subtypevars = defaultdict(set)  # (k,v): all vars in value are sub-types of k
        supertypevars = defaultdict(set)  # (k,v): all vars in value are super-types of k

        while constraints:
            constraint = constraints.pop()

            if isinstance(constraint, Existence):
                # has a derived type
                if isinstance(constraint.type_, DerivedTypeVariable):
                    # handle label
                    if isinstance(constraint.type_.label, HasField):
                        # the original variable is a pointer
                        v = constraint.type_.type_var.type_var
                        if isinstance(v, TypeVariable):
                            subtypevars[v].add(
                                Pointer64(
                                    Struct(fields={constraint.type_.label.offset: int_type(constraint.type_.label.bits),
                                                   })
                                )
                            )

            elif isinstance(constraint, Subtype):
                # subtype <: supertype

                subtype, supertype = constraint.sub_type, constraint.super_type

                if isinstance(supertype, TypeVariable):
                    if subtype not in subtypevars[supertype]:
                        subtypevars[supertype].add(subtype)
                        for s in supertypevars[subtype]:
                            # re-add impacted constraints
                            constraints.add(Subtype(s, subtype))

                    if subtype in subtypevars:
                        for v in subtypevars[subtype]:
                            if v not in subtypevars[supertype]:
                                subtypevars[supertype].add(v)
                                for sub in supertypevars[v]:
                                    constraints.add(Subtype(supertype, sub))

                if isinstance(subtype, TypeVariable):
                    if supertype not in supertypevars[subtype]:
                        supertypevars[subtype].add(supertype)
                        for s in subtypevars[supertype]:
                            # re-add impacted constraints
                            constraints.add(Subtype(supertype, s))

                    if supertype in supertypevars:
                        for v in supertypevars[supertype]:
                            if v not in supertypevars[subtype]:
                                supertypevars[subtype].add(v)
                                for s in supertypevars[v]:
                                    constraints.add(Subtype(s, subtype))

            elif isinstance(constraint, Equivalence):
                raise Exception("Shouldn't exist anymore.")

            else:
                raise NotImplementedError("Unsupported instance type %s." % type(constraint))

        # import pprint
        # print("Subtype vars")
        # pprint.pprint(subtypevars)
        # print("Supertype vars")
        # pprint.pprint(supertypevars)

        return subtypevars, supertypevars

    def _find_recursive_types(self, subtypevars):
        for var in list(subtypevars.keys()):
            sts = subtypevars[var].copy()
            if isinstance(var, DerivedTypeVariable) and \
                    isinstance(var.label, HasField):
                for subtype_var in sts:
                    if var.type_var.type_var == subtype_var:
                        subtypevars[subtype_var].add(Pointer64(
                            Struct({
                                var.label.offset: TypeVariableReference(subtype_var)
                            })
                        ))
                        self._recursive_types[subtype_var].add(var.label.offset)

    def _get_lower_bound(self, v):
        if isinstance(v, TypeConstant):
            return v
        return self._lower_bounds[v]

    def _get_upper_bound(self, v):
        if isinstance(v, TypeConstant):
            return v
        return self._upper_bounds[v]

    def _compute_lower_upper_bounds(self, subtypevars, supertypevars):

        for typevar, vars_ in subtypevars.items():
            if typevar is None:
                continue
            if isinstance(typevar, TypeConstant):
                continue
            supermum = BottomType() if typevar not in self._lower_bounds else self._lower_bounds[typevar]
            # attempt to update the lower bound of the supertype variable
            for subtypevar in vars_:
                supermum = self._join(subtypevar, supermum, self._get_lower_bound)
            self._lower_bounds[typevar] = supermum

            # because of T-InheritR, fields are propagated *both ways* in a subtype relation
            for subtypevar in vars_:
                if isinstance(typevar, TypeVariable):
                    subtype_supermum = BottomType() if subtypevar not in self._lower_bounds else \
                        self._lower_bounds[subtypevar]
                    if isinstance(subtype_supermum, Pointer64) and \
                            isinstance(subtype_supermum.basetype, Struct):
                        subtype_supermum = self._join(subtypevar, supermum, self._get_lower_bound)
                        self._lower_bounds[subtypevar] = subtype_supermum

        for typevar, vars_ in supertypevars.items():
            if isinstance(typevar, TypeConstant):
                continue
            infimum = TopType() if typevar not in self._upper_bounds else self._upper_bounds[typevar]
            # attempt to update the upper bound of the subtype variable
            for supertypevar in vars_:
                # import ipdb; ipdb.set_trace()
                infimum = self._meet(supertypevar, infimum, self._get_upper_bound)
            self._upper_bounds[typevar] = infimum

    def _unify_struct_fields(self):

        for v in self._lower_bounds.keys():
            if isinstance(v, DerivedTypeVariable) and isinstance(v.label, HasField):
                # unpack v
                ptrv = v.type_var.type_var

                if ptrv in self._lower_bounds:
                    # unification

                    v_subtype = self._lower_bounds[v]
                    ptrv_subtype = self._lower_bounds[ptrv]

                    # make sure it's a pointer at the offset that v.label specifies
                    if isinstance(ptrv_subtype, Pointer64):
                        if isinstance(ptrv_subtype.basetype, Struct):
                            the_field = ptrv_subtype.basetype.fields[v.label.offset]
                            new_field = self._join(the_field, v_subtype, self._get_lower_bound)
                            if new_field != the_field:
                                new_fields = ptrv_subtype.basetype.fields.copy()
                                new_fields.update(
                                    {v.label.offset: new_field,
                                     }
                                )
                                self._lower_bounds[ptrv] = Pointer64(Struct(new_fields))

    def _abstract(self, t):  # pylint:disable=no-self-use
        return t.__class__

    def _concretize(self, n_cls, t1, t2, translate):

        if n_cls is Pointer64:
            if isinstance(t1, Pointer64) and isinstance(t2, Pointer64):
                # we need to merge them
                return Pointer64(self._join(t1.basetype, t2.basetype, translate))
            if isinstance(t1, Pointer64):
                return t1
            elif isinstance(t2, Pointer64):
                return t2
            else:
                # huh?
                return Pointer64(BottomType())

        return n_cls()

    def _join(self, t1, t2, translate):
        """
        Get the least upper bound of t1 and t2.

        :param t1:
        :param t2:
        :return:
        """

        # Trivial cases
        t1 = translate(t1)
        t2 = translate(t2)

        if t1 == t2:
            return t1
        if isinstance(t1, TopType):
            return t2
        elif isinstance(t2, TopType):
            return t1

        if isinstance(t1, TypeVariableReference) and not isinstance(t2, TypeVariableReference):
            return t1
        elif isinstance(t2, TypeVariableReference) and not isinstance(t1, TypeVariableReference):
            return t2

        # consult the graph
        t1_cls = self._abstract(t1)
        t2_cls = self._abstract(t2)

        if t1_cls in BASE_LATTICE and t2_cls in BASE_LATTICE:
            queue = [ t1_cls ]
            while queue:
                n = queue[0]
                queue = queue[1:]

                if networkx.has_path(BASE_LATTICE, n, t2_cls):
                    return self._concretize(n, t1, t2, translate)
                # go up
                queue.extend(BASE_LATTICE.predecessors(n))

        # handling Struct
        if t1_cls is Struct and t2_cls is Struct:
            fields = { }
            for offset in sorted(set(itertools.chain(t1.fields.keys(), t2.fields.keys()))):
                if offset in t1.fields and offset in t2.fields:
                    v = self._join(t1.fields[offset], t2.fields[offset], translate)
                elif offset in t1.fields:
                    v = t1.fields[offset]
                elif offset in t2.fields:
                    v = t2.fields[offset]
                else:
                    raise Exception("Impossible")
                fields[offset] = v
            return Struct(fields)

        if t1_cls is Pointer64 and t2_cls is Struct:
            # swap them
            t1, t1_cls, t2, t2_cls = t2, t2_cls, t1, t1_cls
        if t1_cls is Struct and len(t1.fields) == 1 and 0 in t1.fields:
            if t1.fields[0].size == 8 and t2_cls is Pointer64:
                # they are equivalent
                # e.g., struct{0: int64}  ptr64(int8)
                # return t2 since t2 is more specific
                return t2
            elif t1.fields[0].size == 4 and t2_cls is Pointer32:
                return t2

        # import ipdb; ipdb.set_trace()
        return TopType()

    def _meet(self, t1, t2, translate):
        """
        Get the greatest lower bound of t1 and t2.

        :param t1:
        :param t2:
        :return:
        """

        t1 = translate(t1)
        t2 = translate(t2)

        if t1 == t2:
            return t1

        if isinstance(t1, BottomType):
            return t2
        elif isinstance(t2, BottomType):
            return t1

        # consult the graph
        t1_cls = self._abstract(t1)
        t2_cls = self._abstract(t2)

        if t1_cls in BASE_LATTICE and t2_cls in BASE_LATTICE:
            queue = [t1_cls]
            while queue:
                n = queue[0]
                queue = queue[1:]

                if networkx.has_path(BASE_LATTICE, t2_cls, n):
                    return self._concretize(n, t1, t2, translate)
                # go down
                queue.extend(BASE_LATTICE.successors(n))

        # import ipdb; ipdb.set_trace()
        return BottomType()
