import itertools
from collections import defaultdict
from typing import Union, Type

import networkx

from .typevars import Existence, Equivalence, Subtype, TypeVariable, DerivedTypeVariable, HasField, Add, ConvertTo
from .typeconsts import (BottomType, TopType, TypeConstant, Int, Int8, Int16, Int32, Int64, Pointer, Pointer32,
                         Pointer64, Struct, int_type, TypeVariableReference)

# lattice for 64-bit binaries
BASE_LATTICE_64 = networkx.DiGraph()
BASE_LATTICE_64.add_edge(TopType, Int)
BASE_LATTICE_64.add_edge(Int, Int64)
BASE_LATTICE_64.add_edge(Int, Int32)
BASE_LATTICE_64.add_edge(Int64, Pointer64)
BASE_LATTICE_64.add_edge(Pointer64, BottomType)
BASE_LATTICE_64.add_edge(Int32, BottomType)
BASE_LATTICE_64.add_edge(Int16, BottomType)
BASE_LATTICE_64.add_edge(Int, Int16)
BASE_LATTICE_64.add_edge(Int8, BottomType)
BASE_LATTICE_64.add_edge(Int, Int8)

# lattice for 32-bit binaries
BASE_LATTICE_32 = networkx.DiGraph()
BASE_LATTICE_32.add_edge(TopType, Int)
BASE_LATTICE_32.add_edge(Int, Int32)
BASE_LATTICE_32.add_edge(Int32, Pointer32)
BASE_LATTICE_32.add_edge(Int64, BottomType)
BASE_LATTICE_32.add_edge(Pointer32, BottomType)
BASE_LATTICE_32.add_edge(Int16, BottomType)
BASE_LATTICE_32.add_edge(Int, Int16)
BASE_LATTICE_32.add_edge(Int8, BottomType)
BASE_LATTICE_32.add_edge(Int, Int8)

BASE_LATTICES = {
    32: BASE_LATTICE_32,
    64: BASE_LATTICE_64,
}


class RecursiveType:
    def __init__(self, typevar, offset):
        self.typevar = typevar
        self.offset = offset


class SimpleSolver:
    """
    SimpleSolver is, literally, a simple, unification-based type constraint solver.
    """
    def __init__(self, bits: int, constraints):

        if bits not in (32, 64):
            raise ValueError("Pointer size %d is not supported. Expect 32 or 64." % bits)

        self.bits = bits
        self._constraints = constraints
        self._base_lattice = BASE_LATTICES[bits]

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
        subtype_constraints = self._subtype_constraints_from_add()
        constraints.update(subtype_constraints)
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
            if isinstance(constraint, Equivalence):
                # type_a == type_b
                # we apply unification and removes one of them
                ta, tb = constraint.type_a, constraint.type_b
                graph.add_edge(ta, tb)

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

    def _subtype_constraints_from_add(self):
        """
        Handle Add constraints.
        """
        new_constraints = set()
        for constraint in self._constraints:
            if isinstance(constraint, Add):
                # we want to be conservative and take a guess here - normally the resulting type variable is a subtype
                # of the first type variable
                new_constraints.add(Subtype(constraint.type_0, constraint.type_r))
        return new_constraints

    def _pointer_class(self) -> Union[Type[Pointer32],Type[Pointer64]]:
        if self.bits == 32:
            return Pointer32
        elif self.bits == 64:
            return Pointer64
        raise NotImplementedError("Unsupported bits %d" % self.bits)

    def _calculate_closure(self, constraints):

        ptr_class = self._pointer_class()

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
                                ptr_class(
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
        ptr_class = self._pointer_class()

        for var in list(subtypevars.keys()):
            sts = subtypevars[var].copy()
            if isinstance(var, DerivedTypeVariable) and \
                    isinstance(var.label, HasField):
                for subtype_var in sts:
                    if var.type_var.type_var == subtype_var:
                        subtypevars[subtype_var].add(ptr_class(
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
        if v in self._upper_bounds:
            return self._upper_bounds[v]

        # try to compute it
        if isinstance(v, DerivedTypeVariable):
            if isinstance(v.label, ConvertTo):
                # after integer conversion,
                ub = int_type(v.label.to_bits)
                if ub is not None:
                    self._upper_bounds[v] = ub
            elif isinstance(v.label, HasField):
                ub = int_type(v.label.bits)
                if ub is not None:
                    self._upper_bounds[v] = ub

        if v not in self._upper_bounds:
            self._upper_bounds[v] = TopType()
        return self._upper_bounds[v]

    def _compute_lower_upper_bounds(self, subtypevars, supertypevars):

        # compute the least upper bound for each type variable
        for typevar, vars_ in supertypevars.items():
            if typevar is None:
                continue
            if isinstance(typevar, TypeConstant):
                continue
            supermum = BottomType() if typevar not in self._upper_bounds else self._upper_bounds[typevar]
            # attempt to update the upper bound of the supertype variable
            for subtypevar in vars_:
                supermum = self._join(subtypevar, supermum, self._get_upper_bound)
            self._upper_bounds[typevar] = supermum

        # compute the greatest lower bound for each type variable
        for typevar, vars_ in subtypevars.items():
            if isinstance(typevar, TypeConstant):
                continue
            infimum = TopType() if typevar not in self._lower_bounds else self._lower_bounds[typevar]
            # attempt to update the lower bound of the subtype variable
            for supertypevar in vars_:
                infimum = self._meet(supertypevar, infimum, self._get_lower_bound)
            self._lower_bounds[typevar] = infimum

            # because of T-InheritR, fields are propagated *both ways* in a subtype relation
            for subtypevar in vars_:
                if isinstance(typevar, TypeVariable):
                    subtype_infimum = TopType() if subtypevar not in self._lower_bounds else \
                        self._lower_bounds[subtypevar]
                    if isinstance(subtype_infimum, Pointer) and \
                            isinstance(subtype_infimum.basetype, Struct):
                        subtype_infimum = self._meet(subtypevar, infimum, self._get_lower_bound)
                        self._lower_bounds[subtypevar] = subtype_infimum

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
                    if isinstance(ptrv_subtype, Pointer):
                        if isinstance(ptrv_subtype.basetype, Struct):
                            the_field = ptrv_subtype.basetype.fields[v.label.offset]
                            new_field = self._join(the_field, v_subtype, self._get_lower_bound)
                            if new_field != the_field:
                                new_fields = ptrv_subtype.basetype.fields.copy()
                                new_fields.update(
                                    {v.label.offset: new_field,
                                     }
                                )
                                self._lower_bounds[ptrv] = ptrv_subtype.__class__(Struct(new_fields))

    def _abstract(self, t):  # pylint:disable=no-self-use
        return t.__class__

    def _concretize(self, n_cls, t1, t2, join_or_meet, translate):

        ptr_class = self._pointer_class()

        if n_cls is ptr_class:
            if isinstance(t1, ptr_class) and isinstance(t2, ptr_class):
                # we need to merge them
                return ptr_class(join_or_meet(t1.basetype, t2.basetype, translate))
            if isinstance(t1, ptr_class):
                return t1
            elif isinstance(t2, ptr_class):
                return t2
            else:
                # huh?
                return ptr_class(BottomType())

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

        if t1_cls in self._base_lattice and t2_cls in self._base_lattice:
            queue = [ t1_cls ]
            while queue:
                n = queue[0]
                queue = queue[1:]

                if networkx.has_path(self._base_lattice, n, t2_cls):
                    return self._concretize(n, t1, t2, self._join, translate)
                # go up
                queue.extend(self._base_lattice.predecessors(n))

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
            return Struct(fields=fields)

        # single element and single-element struct
        if issubclass(t2_cls, Int) and t1_cls is Struct:
            # swap them
            t1, t1_cls, t2, t2_cls = t2, t2_cls, t1, t1_cls
        if issubclass(t1_cls, Int) and t2_cls is Struct and len(t2.fields) == 1 and 0 in t2.fields:
            # e.g., char & struct {0: char}
            return Struct(fields={0: self._join(t1, t2.fields[0], translate)})

        ptr_class = self._pointer_class()

        # Struct and Pointers
        if t1_cls is ptr_class and t2_cls is Struct:
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
        elif isinstance(t1, BottomType):
            return t2
        elif isinstance(t2, BottomType):
            return t1

        if isinstance(t1, TypeVariableReference) and not isinstance(t2, TypeVariableReference):
            return t1
        elif isinstance(t2, TypeVariableReference) and not isinstance(t1, TypeVariableReference):
            return t2

        # consult the graph
        t1_cls = self._abstract(t1)
        t2_cls = self._abstract(t2)

        if t1_cls in self._base_lattice and t2_cls in self._base_lattice:
            queue = [t1_cls]
            while queue:
                n = queue[0]
                queue = queue[1:]

                if networkx.has_path(self._base_lattice, t2_cls, n):
                    return self._concretize(n, t1, t2, self._meet, translate)
                # go down
                queue.extend(self._base_lattice.successors(n))

        # handling Struct
        if t1_cls is Struct and t2_cls is Struct:
            fields = { }
            for offset in sorted(set(itertools.chain(t1.fields.keys(), t2.fields.keys()))):
                if offset in t1.fields and offset in t2.fields:
                    v = self._meet(t1.fields[offset], t2.fields[offset], translate)
                elif offset in t1.fields:
                    v = t1.fields[offset]
                elif offset in t2.fields:
                    v = t2.fields[offset]
                else:
                    raise Exception("Impossible")
                fields[offset] = v
            return Struct(fields=fields)

        # single element and single-element struct
        if issubclass(t2_cls, Int) and t1_cls is Struct:
            # swap them
            t1, t1_cls, t2, t2_cls = t2, t2_cls, t1, t1_cls
        if issubclass(t1_cls, Int) and t2_cls is Struct and len(t2.fields) == 1 and 0 in t2.fields:
            # e.g., char & struct {0: char}
            return Struct(fields={0: self._meet(t1, t2.fields[0], translate)})

        ptr_class = self._pointer_class()

        # Struct and Pointers
        if t1_cls is ptr_class and t2_cls is Struct:
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
        return BottomType()
