# pylint:disable=missing-class-docstring
import itertools
from collections import defaultdict
from typing import Union, Type, Callable

import networkx

from .typevars import Existence, Equivalence, Subtype, TypeVariable, DerivedTypeVariable, HasField, Add, ConvertTo, \
    IsArray
from .typeconsts import (BottomType, TopType, TypeConstant, Int, Int8, Int16, Int32, Int64, Pointer, Pointer32,
                         Pointer64, Struct, int_type, TypeVariableReference)

# lattice for 64-bit binaries
BASE_LATTICE_64 = networkx.DiGraph()
BASE_LATTICE_64.add_edge(TopType, Int)
BASE_LATTICE_64.add_edge(Int, Int64)
BASE_LATTICE_64.add_edge(Int, Int32)
BASE_LATTICE_64.add_edge(Int, Int16)
BASE_LATTICE_64.add_edge(Int, Int8)
BASE_LATTICE_64.add_edge(Int32, BottomType)
BASE_LATTICE_64.add_edge(Int16, BottomType)
BASE_LATTICE_64.add_edge(Int8, BottomType)
BASE_LATTICE_64.add_edge(Int64, Pointer64)
BASE_LATTICE_64.add_edge(Pointer64, BottomType)

# lattice for 32-bit binaries
BASE_LATTICE_32 = networkx.DiGraph()
BASE_LATTICE_32.add_edge(TopType, Int)
BASE_LATTICE_32.add_edge(Int, Int64)
BASE_LATTICE_32.add_edge(Int, Int32)
BASE_LATTICE_32.add_edge(Int, Int16)
BASE_LATTICE_32.add_edge(Int, Int8)
BASE_LATTICE_32.add_edge(Int32, Pointer32)
BASE_LATTICE_32.add_edge(Int64, BottomType)
BASE_LATTICE_32.add_edge(Pointer32, BottomType)
BASE_LATTICE_32.add_edge(Int16, BottomType)
BASE_LATTICE_32.add_edge(Int8, BottomType)

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

        eq_constraints = self._eq_constraints_from_add()
        self._constraints |= eq_constraints
        constraints = self._handle_equivalence()
        subtypevars, supertypevars = self._calculate_closure(constraints)
        self._find_recursive_types(subtypevars)
        self._compute_lower_upper_bounds(subtypevars, supertypevars)
        self._lower_struct_fields()
        self._convert_arrays(constraints)
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

        for v, e in self._equivalence.items():
            if v not in solution:
                solution[v] = solution.get(e, None)

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
                if isinstance(ta, TypeConstant) and isinstance(tb, TypeVariable):
                    # replace tb with ta
                    replacements[tb] = ta
                elif isinstance(ta, TypeVariable) and isinstance(tb, TypeConstant):
                    # replace ta with tb
                    replacements[ta] = tb
                else:
                    # they are both type variables. we will determine a representative later
                    graph.add_edge(ta, tb)

        for components in networkx.connected_components(graph):
            components_lst = list(sorted(components, key=lambda x: str(x)))  # pylint:disable=unnecessary-lambda
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

    def _eq_constraints_from_add(self):
        """
        Handle Add constraints.
        """
        new_constraints = set()
        for constraint in self._constraints:
            if isinstance(constraint, Add):
                if isinstance(constraint.type_0, TypeVariable) \
                        and not isinstance(constraint.type_0, DerivedTypeVariable) \
                        and isinstance(constraint.type_r, TypeVariable) \
                        and not isinstance(constraint.type_r, DerivedTypeVariable):
                    new_constraints.add(Equivalence(constraint.type_0, constraint.type_r))
                if isinstance(constraint.type_1, TypeVariable) \
                        and not isinstance(constraint.type_1, DerivedTypeVariable) \
                        and isinstance(constraint.type_r, TypeVariable) \
                        and not isinstance(constraint.type_r, DerivedTypeVariable):
                    new_constraints.add(Equivalence(constraint.type_1, constraint.type_r))
        return new_constraints

    def _pointer_class(self) -> Union[Type[Pointer32],Type[Pointer64]]:
        if self.bits == 32:
            return Pointer32
        elif self.bits == 64:
            return Pointer64
        raise NotImplementedError("Unsupported bits %d" % self.bits)

    def _calculate_closure(self, constraints):

        ptr_class = self._pointer_class()

        # a mapping from type variables to all the variables which are {super,sub}types of them
        subtypevars = defaultdict(set)  # {k: {v}}: v <: k
        supertypevars = defaultdict(set)  # {k: {v}}: k <: v

        constraints = set(constraints)  # make a copy

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
                        if supertype is not subtype:
                            subtypevars[supertype].add(subtype)
                            for s in supertypevars[subtype]:
                                # re-add impacted constraints
                                constraints.add(Subtype(subtype, s))

                    if subtype in subtypevars:
                        for v in subtypevars[subtype]:
                            if v not in subtypevars[supertype]:
                                if supertype is not v:
                                    subtypevars[supertype].add(v)
                                    for sup in supertypevars[v]:
                                        constraints.add(Subtype(subtype, sup))

                if isinstance(subtype, TypeVariable):
                    if supertype not in supertypevars[subtype]:
                        if subtype is not supertype:
                            supertypevars[subtype].add(supertype)
                            for s in subtypevars[supertype]:
                                # re-add impacted constraints
                                constraints.add(Subtype(s, supertype))

                    if supertype in supertypevars:
                        for v in supertypevars[supertype]:
                            if v not in supertypevars[subtype]:
                                if v is not subtype:
                                    supertypevars[subtype].add(v)
                                    for sup in supertypevars[v]:
                                        constraints.add(Subtype(subtype, sup))

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

        # if all that failed, let the defaultdict generate a Top
        return self._upper_bounds[v]

    def _compute_lower_upper_bounds(self, subtypevars, supertypevars):

        # compute the least upper bound for each type variable
        for typevar, upper_bounds in supertypevars.items():
            if typevar is None:
                continue
            if isinstance(typevar, TypeConstant):
                continue
            self._upper_bounds[typevar] = self._meet(typevar, *upper_bounds, translate=self._get_upper_bound)

        # compute the greatest lower bound for each type variable
        seen = set()  # loop avoidance
        queue = list(subtypevars)
        while queue:
            typevar = queue.pop(0)
            lower_bounds = subtypevars[typevar]

            if typevar not in seen:
                # we detect if it depends on any other typevar upon the first encounter
                seen.add(typevar)

                abort = False
                for subtypevar in lower_bounds:
                    if isinstance(subtypevar, TypeVariable) and subtypevar not in self._lower_bounds:
                        # oops - we should analyze the subtypevar first
                        queue.append(typevar)
                        # to avoid loops, make sure typevar does not rely on
                        abort = True
                        break
                if abort:
                    continue
            else:
                # avoid loop and continue no matter what
                pass

            self._lower_bounds[typevar] = self._join(typevar, *lower_bounds, translate=self._get_lower_bound)

            # because of T-InheritR, fields are propagated *both ways* in a subtype relation
            for subtypevar in lower_bounds:
                if not isinstance(subtypevar, TypeVariable):
                    continue
                subtype_infimum = self._lower_bounds[subtypevar]
                if isinstance(subtype_infimum, Pointer) and \
                        isinstance(subtype_infimum.basetype, Struct):
                    subtype_infimum = self._join(subtypevar, typevar, translate=self._get_lower_bound)
                    self._lower_bounds[subtypevar] = subtype_infimum

    def _lower_struct_fields(self):

        # tv_680: ptr32(struct{0: int32})
        # tv_680.load.<32>@0: ptr32(struct{5: int8})
        #    becomes
        # tv_680: ptr32(struct{0: ptr32(struct{5: int8})})

        for outer, outer_lb in self._lower_bounds.items():
            if isinstance(outer, DerivedTypeVariable) and isinstance(outer.label, HasField) \
                    and not isinstance(outer_lb, BottomType):
                # unpack v
                base = outer.type_var.type_var

                if base in self._lower_bounds:

                    base_lb = self._lower_bounds[base]

                    # make sure it's a pointer at the offset that v.label specifies
                    if isinstance(base_lb, Pointer):
                        if isinstance(base_lb.basetype, Struct):
                            the_field = base_lb.basetype.fields[outer.label.offset]
                            # replace this field
                            new_field = self._meet(the_field, outer_lb, translate=self._get_upper_bound)
                            if new_field != the_field:
                                new_fields = base_lb.basetype.fields.copy()
                                new_fields.update(
                                    {outer.label.offset: new_field,
                                     }
                                )
                                base_lb = base_lb.__class__(Struct(new_fields))
                                self._lower_bounds[base] = base_lb

                            # another attempt: if a pointer to a struct has only one field, remove the struct
                            if len(base_lb.basetype.fields) == 1 and 0 in base_lb.basetype.fields:
                                base_lb = base_lb.__class__(base_lb.basetype.fields[0])
                                self._lower_bounds[base] = base_lb


    def _convert_arrays(self, constraints):
        for constraint in constraints:
            if not isinstance(constraint, Existence):
                continue
            inner = constraint.type_
            if isinstance(inner, DerivedTypeVariable) and isinstance(inner.label, IsArray):
                if inner.type_var in self._lower_bounds:
                    curr_type = self._lower_bounds[inner.type_var]
                    if isinstance(curr_type, Pointer) and isinstance(curr_type.basetype, Struct):
                        # replace all fields with the first field
                        if 0 in curr_type.basetype.fields:
                            first_field = curr_type.basetype.fields[0]
                            for offset in curr_type.basetype.fields.keys():
                                curr_type.basetype.fields[offset] = first_field

    def _abstract(self, t):  # pylint:disable=no-self-use
        return t.__class__

    def _concretize(self, n_cls, t1, t2, join_or_meet, translate):

        ptr_class = self._pointer_class()

        if n_cls is ptr_class:
            if isinstance(t1, ptr_class) and isinstance(t2, ptr_class):
                # we need to merge them
                return ptr_class(join_or_meet(t1.basetype, t2.basetype, translate=translate))
            if isinstance(t1, ptr_class):
                return t1
            elif isinstance(t2, ptr_class):
                return t2
            else:
                # huh?
                return ptr_class(BottomType())

        return n_cls()

    def _join(self, *args, translate:Callable):
        """
        Get the least upper bound (V, maximum) of the arguments.
        """

        if len(args) == 0:
            return BottomType()
        if len(args) == 1:
            return translate(args[0])
        if len(args) > 2:
            split = len(args) // 2
            first = self._join(*args[:split], translate=translate)
            second = self._join(*args[split:], translate=translate)
            return self._join(first, second, translate=translate)

        t1 = translate(args[0])
        t2 = translate(args[1])

        # Trivial cases
        if t1 == t2:
            return t1
        if isinstance(t1, TopType):
            return t1
        elif isinstance(t2, TopType):
            return t2
        if isinstance(t1, BottomType):
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

                if networkx.has_path(self._base_lattice, n, t2_cls):
                    return self._concretize(n, t1, t2, self._join, translate)
                # go up
                queue.extend(self._base_lattice.predecessors(n))

        # handling Struct
        if t1_cls is Struct and t2_cls is Struct:
            fields = { }
            for offset in sorted(set(itertools.chain(t1.fields.keys(), t2.fields.keys()))):
                if offset in t1.fields and offset in t2.fields:
                    v = self._join(t1.fields[offset], t2.fields[offset], translate=translate)
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
            return Struct(fields={0: self._join(t1, t2.fields[0], translate=translate)})

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

    def _meet(self, *args, translate:Callable):
        """
        Get the greatest lower bound (^, minimum) of the arguments.
        """

        if len(args) == 0:
            return TopType()
        if len(args) == 1:
            return translate(args[0])
        if len(args) > 2:
            split = len(args) // 2
            first = self._meet(*args[:split], translate=translate)
            second = self._meet(*args[split:], translate=translate)
            return self._meet(first, second, translate=translate)

        t1 = translate(args[0])
        t2 = translate(args[1])

        # Trivial cases
        if t1 == t2:
            return t1
        elif isinstance(t1, BottomType):
            return t1
        elif isinstance(t2, BottomType):
            return t2
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
                    v = self._meet(t1.fields[offset], t2.fields[offset], translate=translate)
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
            return Struct(fields={0: self._meet(t1, t2.fields[0], translate=translate)})

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
