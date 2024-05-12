# pylint:disable=missing-class-docstring
from typing import DefaultDict
import enum
from collections import defaultdict
import logging

import networkx

from angr.utils.constants import MAX_POINTSTO_BITS
from .typevars import (
    Existence,
    Subtype,
    Equivalence,
    Add,
    TypeVariable,
    DerivedTypeVariable,
    HasField,
    IsArray,
    TypeConstraint,
    Load,
    Store,
    BaseLabel,
    FuncIn,
    FuncOut,
    ConvertTo,
)
from .typeconsts import (
    BottomType,
    TopType,
    TypeConstant,
    Int,
    Int8,
    Int16,
    Int32,
    Int64,
    Pointer,
    Pointer32,
    Pointer64,
    Struct,
    Array,
    Function,
    int_type,
)
from .variance import Variance
from .dfa import DFAConstraintSolver, EmptyEpsilonNFAError

_l = logging.getLogger(__name__)


PRIMITIVE_TYPES = {
    TopType(),
    Int(),
    Int8(),
    Int16(),
    Int32(),
    Int64(),
    Pointer32(),
    Pointer64(),
    BottomType(),
    Struct(),
    Array(),
}

Top_ = TopType()
Int_ = Int()
Int64_ = Int64()
Int32_ = Int32()
Int16_ = Int16()
Int8_ = Int8()
Bottom_ = BottomType()
Pointer64_ = Pointer64()
Pointer32_ = Pointer32()
Struct_ = Struct()
Array_ = Array()

# lattice for 64-bit binaries
BASE_LATTICE_64 = networkx.DiGraph()
BASE_LATTICE_64.add_edge(Top_, Int_)
BASE_LATTICE_64.add_edge(Int_, Int64_)
BASE_LATTICE_64.add_edge(Int_, Int32_)
BASE_LATTICE_64.add_edge(Int_, Int16_)
BASE_LATTICE_64.add_edge(Int_, Int8_)
BASE_LATTICE_64.add_edge(Int32_, Bottom_)
BASE_LATTICE_64.add_edge(Int16_, Bottom_)
BASE_LATTICE_64.add_edge(Int8_, Bottom_)
BASE_LATTICE_64.add_edge(Int64_, Pointer64_)
BASE_LATTICE_64.add_edge(Pointer64_, Bottom_)

# lattice for 32-bit binaries
BASE_LATTICE_32 = networkx.DiGraph()
BASE_LATTICE_32.add_edge(Top_, Int_)
BASE_LATTICE_32.add_edge(Int_, Int64_)
BASE_LATTICE_32.add_edge(Int_, Int32_)
BASE_LATTICE_32.add_edge(Int_, Int16_)
BASE_LATTICE_32.add_edge(Int_, Int8_)
BASE_LATTICE_32.add_edge(Int32_, Pointer32_)
BASE_LATTICE_32.add_edge(Int64_, Bottom_)
BASE_LATTICE_32.add_edge(Pointer32_, Bottom_)
BASE_LATTICE_32.add_edge(Int16_, Bottom_)
BASE_LATTICE_32.add_edge(Int8_, Bottom_)

BASE_LATTICES = {
    32: BASE_LATTICE_32,
    64: BASE_LATTICE_64,
}


#
# Sketch
#


class SketchNodeBase:
    """
    The base class for nodes in a sketch.
    """

    __slots__ = ()


class SketchNode(SketchNodeBase):
    """
    Represents a node in a sketch graph.
    """

    __slots__ = ("typevar", "upper_bound", "lower_bound")

    def __init__(self, typevar: TypeVariable | DerivedTypeVariable):
        self.typevar: TypeVariable | DerivedTypeVariable = typevar
        self.upper_bound = TopType()
        self.lower_bound = BottomType()

    def __repr__(self):
        return f"{self.lower_bound} <: {self.typevar} <: {self.upper_bound}"

    def __eq__(self, other):
        return isinstance(other, SketchNode) and self.typevar == other.typevar

    def __hash__(self):
        return hash((SketchNode, self.typevar))


class RecursiveRefNode(SketchNodeBase):
    """
    Represents a cycle in a sketch graph.

    This is equivalent to sketches.LabelNode in the reference implementation of retypd.
    """

    def __init__(self, target: DerivedTypeVariable):
        self.target: DerivedTypeVariable = target

    def __hash__(self):
        return hash((RecursiveRefNode, self.target))

    def __eq__(self, other):
        return type(other) is RecursiveRefNode and other.target == self.target


class Sketch:
    """
    Describes the sketch of a type variable.
    """

    __slots__ = (
        "graph",
        "root",
        "node_mapping",
        "solver",
    )

    def __init__(self, solver: "SimpleSolver", root: TypeVariable):
        self.root: SketchNode = SketchNode(root)
        self.graph = networkx.DiGraph()
        self.node_mapping: dict[TypeVariable | DerivedTypeVariable, SketchNodeBase] = {}
        self.solver = solver

        # add the root node
        self.graph.add_node(self.root)
        self.node_mapping[root] = self.root

    def lookup(self, typevar: TypeVariable | DerivedTypeVariable) -> SketchNodeBase | None:
        if typevar in self.node_mapping:
            return self.node_mapping[typevar]
        node: SketchNodeBase | None = None
        if isinstance(typevar, DerivedTypeVariable):
            node = self.node_mapping[SimpleSolver._to_typevar_or_typeconst(typevar.type_var)]
            for label in typevar.labels:
                succs = []
                for _, dst, data in self.graph.out_edges(node, data=True):
                    if "label" in data and data["label"] == label:
                        succs.append(dst)
                assert len(succs) <= 1
                if not succs:
                    return None
                node = succs[0]
                if isinstance(node, RecursiveRefNode):
                    node = self.lookup(node.target)
        return node

    def add_edge(self, src: SketchNodeBase, dst: SketchNodeBase, label):
        self.graph.add_edge(src, dst, label=label)

    def add_constraint(self, constraint: TypeConstraint) -> None:
        # sub <: super
        if not isinstance(constraint, Subtype):
            return
        subtype = self.flatten_typevar(constraint.sub_type)
        supertype = self.flatten_typevar(constraint.super_type)
        if SimpleSolver._typevar_inside_set(subtype, PRIMITIVE_TYPES) and not SimpleSolver._typevar_inside_set(
            supertype, PRIMITIVE_TYPES
        ):
            super_node: SketchNode | None = self.lookup(supertype)
            if super_node is not None:
                super_node.lower_bound = self.solver.join(super_node.lower_bound, subtype)
        elif SimpleSolver._typevar_inside_set(supertype, PRIMITIVE_TYPES) and not SimpleSolver._typevar_inside_set(
            subtype, PRIMITIVE_TYPES
        ):
            sub_node: SketchNode | None = self.lookup(subtype)
            # assert sub_node is not None
            if sub_node is not None:
                sub_node.upper_bound = self.solver.meet(sub_node.upper_bound, supertype)

    @staticmethod
    def flatten_typevar(
        derived_typevar: TypeVariable | TypeConstant | DerivedTypeVariable,
    ) -> DerivedTypeVariable | TypeVariable | TypeConstant:
        # pylint:disable=too-many-boolean-expressions
        if (
            isinstance(derived_typevar, DerivedTypeVariable)
            and isinstance(derived_typevar.type_var, Pointer)
            and SimpleSolver._typevar_inside_set(derived_typevar.type_var.basetype, PRIMITIVE_TYPES)
            and len(derived_typevar.labels) == 2
            and isinstance(derived_typevar.labels[0], Load)
            and isinstance(derived_typevar.labels[1], HasField)
            and derived_typevar.labels[1].offset == 0
            and derived_typevar.labels[1].bits == MAX_POINTSTO_BITS
        ):
            return derived_typevar.type_var.basetype
        return derived_typevar


#
# Constraint graph
#


class ConstraintGraphTag(enum.Enum):
    LEFT = 0
    RIGHT = 1
    UNKNOWN = 2


class FORGOTTEN(enum.Enum):
    PRE_FORGOTTEN = 0
    POST_FORGOTTEN = 1


class ConstraintGraphNode:
    __slots__ = ("typevar", "variance", "tag", "forgotten")

    def __init__(
        self,
        typevar: TypeVariable | DerivedTypeVariable,
        variance: Variance,
        tag: ConstraintGraphTag,
        forgotten: FORGOTTEN,
    ):
        self.typevar = typevar
        self.variance = variance
        self.tag = tag
        self.forgotten = forgotten

    def __repr__(self):
        variance_str = "CO" if self.variance == Variance.COVARIANT else "CONTRA"
        if self.tag == ConstraintGraphTag.LEFT:
            tag_str = "L"
        elif self.tag == ConstraintGraphTag.RIGHT:
            tag_str = "R"
        else:
            tag_str = "U"
        forgotten_str = "PRE" if FORGOTTEN.PRE_FORGOTTEN else "POST"
        s = f"{self.typevar}#{variance_str}.{tag_str}.{forgotten_str}"
        if ":" in s:
            return '"' + s + '"'
        return s

    def __eq__(self, other):
        if not isinstance(other, ConstraintGraphNode):
            return False
        return (
            self.typevar == other.typevar
            and self.variance == other.variance
            and self.tag == other.tag
            and self.forgotten == other.forgotten
        )

    def __hash__(self):
        return hash((ConstraintGraphNode, self.typevar, self.variance, self.tag, self.forgotten))

    def forget_last_label(self) -> tuple["ConstraintGraphNode", BaseLabel] | None:
        if isinstance(self.typevar, DerivedTypeVariable) and self.typevar.labels:
            last_label = self.typevar.labels[-1]
            if len(self.typevar.labels) == 1:
                prefix = self.typevar.type_var
            else:
                prefix = DerivedTypeVariable(self.typevar.type_var, None, labels=self.typevar.labels[:-1])
            if self.variance == last_label.variance:
                variance = Variance.COVARIANT
            else:
                variance = Variance.CONTRAVARIANT
            return (
                ConstraintGraphNode(prefix, variance, self.tag, FORGOTTEN.PRE_FORGOTTEN),
                self.typevar.labels[-1],
            )
        return None

    def recall(self, label: BaseLabel) -> "ConstraintGraphNode":
        if isinstance(self.typevar, DerivedTypeVariable):
            labels = self.typevar.labels + (label,)
            typevar = self.typevar.type_var
        elif isinstance(self.typevar, TypeVariable):
            labels = (label,)
            typevar = self.typevar
        elif isinstance(self.typevar, TypeConstant):
            labels = (label,)
            typevar = self.typevar
        else:
            raise TypeError(f"Unsupported type {type(self.typevar)}")
        if self.variance == label.variance:
            variance = Variance.COVARIANT
        else:
            variance = Variance.CONTRAVARIANT
        if not labels:
            var = typevar
        else:
            var = DerivedTypeVariable(typevar, None, labels=labels)
        return ConstraintGraphNode(var, variance, self.tag, FORGOTTEN.PRE_FORGOTTEN)

    def inverse(self) -> "ConstraintGraphNode":
        if self.tag == ConstraintGraphTag.LEFT:
            tag = ConstraintGraphTag.RIGHT
        elif self.tag == ConstraintGraphTag.RIGHT:
            tag = ConstraintGraphTag.LEFT
        else:
            tag = ConstraintGraphTag.UNKNOWN

        if self.variance == Variance.COVARIANT:
            variance = Variance.CONTRAVARIANT
        else:
            variance = Variance.COVARIANT

        return ConstraintGraphNode(self.typevar, variance, tag, self.forgotten)

    def inverse_wo_tag(self) -> "ConstraintGraphNode":
        """
        Invert the variance only.
        """
        if self.variance == Variance.COVARIANT:
            variance = Variance.CONTRAVARIANT
        else:
            variance = Variance.COVARIANT

        return ConstraintGraphNode(self.typevar, variance, self.tag, self.forgotten)


#
# The solver
#


class SimpleSolver:
    """
    SimpleSolver is, by its name, a simple solver. Most of this solver is based on the (complex) simplification logic
    that the retypd paper describes and the retypd re-implementation (https://github.com/GrammaTech/retypd) implements.
    Additionally, we add some improvements to allow type propagation of known struct names, among a few other
    improvements.
    """

    def __init__(self, bits: int, constraints, typevars):
        if bits not in (32, 64):
            raise ValueError("Pointer size %d is not supported. Expect 32 or 64." % bits)

        self.bits = bits
        self._constraints: dict[TypeVariable, set[TypeConstraint]] = constraints
        self._typevars: set[TypeVariable] = typevars
        self._base_lattice = BASE_LATTICES[bits]
        self._base_lattice_inverted = networkx.DiGraph()
        for src, dst in self._base_lattice.edges:
            self._base_lattice_inverted.add_edge(dst, src)

        #
        # Solving state
        #
        self._equivalence = defaultdict(dict)
        for typevar in list(self._constraints):
            if self._constraints[typevar]:
                self._constraints[typevar] |= self._eq_constraints_from_add(typevar)
                self._constraints[typevar] = self._handle_equivalence(typevar)
        equ_classes, sketches, _ = self.solve()
        self.solution = {}
        self._solution_cache = {}
        self.determine(equ_classes, sketches, self.solution)
        for typevar in list(self._constraints):
            self._convert_arrays(self._constraints[typevar])

    def solve(self):
        """
        Steps:

        For each type variable,
        - Infer the shape in its sketch
        - Build the constraint graph
        - Collect all constraints
        - Apply constraints to derive the lower and upper bounds
        """

        typevars = set(self._constraints) | self._typevars
        constraints = set()
        for tv in typevars:
            if tv in self._constraints:
                constraints |= self._constraints[tv]

        # collect typevars used in the constraint set
        constrained_typevars = set()
        for constraint in constraints:
            if isinstance(constraint, Subtype):
                for t in (constraint.sub_type, constraint.super_type):
                    if isinstance(t, DerivedTypeVariable):
                        if t.type_var in typevars:
                            constrained_typevars.add(t.type_var)
                    elif isinstance(t, TypeVariable):
                        if t in typevars:
                            constrained_typevars.add(t)

        equivalence_classes, sketches = self.infer_shapes(typevars, constraints)
        # TODO: Handle global variables

        type_schemes = constraints

        constraintset2tvs = defaultdict(set)
        for idx, tv in enumerate(constrained_typevars):
            _l.debug("Collecting constraints for type variable %r (%d/%d)", tv, idx + 1, len(constrained_typevars))
            # build a sub constraint set for the type variable
            constraint_subset = frozenset(self._generate_constraint_subset(constraints, {tv}))
            constraintset2tvs[constraint_subset].add(tv)

        for idx, (constraint_subset, tvs) in enumerate(constraintset2tvs.items()):
            _l.debug(
                "Solving %d constraints for type variables %r (%d/%d)",
                len(constraint_subset),
                tvs,
                idx + 1,
                len(constraintset2tvs),
            )
            base_constraint_graph = self._generate_constraint_graph(constraint_subset, tvs | PRIMITIVE_TYPES)
            for idx_0, tv in enumerate(tvs):
                _l.debug("Solving for type variable %r (%d/%d)", tv, idx_0 + 1, len(tvs))
                primitive_constraints = self._generate_primitive_constraints({tv}, base_constraint_graph)
                for primitive_constraint in primitive_constraints:
                    sketches[tv].add_constraint(primitive_constraint)

        return equivalence_classes, sketches, type_schemes

    def infer_shapes(
        self, typevars: set[TypeVariable], constraints: set[TypeConstraint]
    ) -> tuple[dict, dict[TypeVariable, Sketch]]:
        """
        Computing sketches from constraint sets. Implements Algorithm E.1 in the retypd paper.
        """

        equivalence_classes, quotient_graph = self.compute_quotient_graph(constraints)

        sketches: dict[TypeVariable, Sketch] = {}
        for tv in typevars:
            sketches[tv] = Sketch(self, tv)

        for tv, sketch in sketches.items():
            sketch_node = sketch.lookup(tv)
            graph_node = equivalence_classes.get(tv, None)
            # assert graph_node is not None
            if graph_node is None:
                continue
            visited = {graph_node: sketch_node}
            self._get_all_paths(quotient_graph, sketch, graph_node, visited)
        return equivalence_classes, sketches

    def compute_quotient_graph(self, constraints: set[TypeConstraint]):
        """
        Compute the quotient graph (the constraint graph modulo ~ in Algorithm E.1 in the retypd paper) with respect to
        a given set of type constraints.
        """

        g = networkx.DiGraph()
        # collect all derived type variables
        typevars = self._typevars_from_constraints(constraints)
        g.add_nodes_from(typevars)
        # add paths for each derived type variable into the graph
        for tv in typevars:
            last_node = tv
            prefix = tv
            while isinstance(prefix, DerivedTypeVariable) and prefix.labels:
                prefix = prefix.longest_prefix()
                if prefix is None:
                    continue
                g.add_edge(prefix, last_node, label=last_node.labels[-1])
                last_node = prefix

        # compute the constraint graph modulo ~
        equivalence_classes = {node: node for node in g}

        load = Load()
        store = Store()
        for node in g.nodes:
            lbl_to_node = {}
            for succ in g.successors(node):
                lbl_to_node[succ.labels[-1]] = succ
                if load in lbl_to_node and store in lbl_to_node:
                    self._unify(equivalence_classes, lbl_to_node[load], lbl_to_node[store], g)

        for constraint in constraints:
            if isinstance(constraint, Subtype):
                if self._typevar_inside_set(constraint.super_type, PRIMITIVE_TYPES) or self._typevar_inside_set(
                    constraint.sub_type, PRIMITIVE_TYPES
                ):
                    continue
                self._unify(equivalence_classes, constraint.super_type, constraint.sub_type, g)

        out_graph = networkx.MultiDiGraph()  # there can be multiple edges between two nodes, each edge is associated
        # with a different label
        for src, dst, data in g.edges(data=True):
            src_cls = equivalence_classes[src]
            dst_cls = equivalence_classes[dst]
            label = None if not data else data["label"]
            if label is not None and out_graph.has_edge(src_cls, dst_cls):
                # do not add the same edge twice
                existing_labels = {
                    data_["label"]
                    for _, dst_cls_, data_ in out_graph.out_edges(src_cls, data=True)
                    if dst_cls_ == dst_cls and data
                }
                if label in existing_labels:
                    continue
            out_graph.add_edge(src_cls, dst_cls, label=label)

        return equivalence_classes, out_graph

    def _generate_primitive_constraints(
        self,
        non_primitive_endpoints: set[TypeVariable | DerivedTypeVariable],
        constraint_graph,
    ) -> set[TypeConstraint]:
        # FIXME: Extract interesting variables
        constraints_0 = self._solve_constraints_between(constraint_graph, non_primitive_endpoints, PRIMITIVE_TYPES)
        constraints_1 = self._solve_constraints_between(constraint_graph, PRIMITIVE_TYPES, non_primitive_endpoints)
        return constraints_0 | constraints_1

    @staticmethod
    def _typevars_from_constraints(constraints: set[TypeConstraint]) -> set[TypeVariable | DerivedTypeVariable]:
        """
        Collect derived type variables from a set of constraints.
        """

        typevars: set[TypeVariable | DerivedTypeVariable] = set()
        for constraint in constraints:
            if isinstance(constraint, Subtype):
                typevars.add(constraint.sub_type)
                typevars.add(constraint.super_type)
            # TODO: Other types of constraints?
        return typevars

    @staticmethod
    def _get_all_paths(
        graph: networkx.DiGraph,
        sketch: Sketch,
        node: DerivedTypeVariable,
        visited: dict[TypeVariable | DerivedTypeVariable, SketchNode],
    ):
        if node not in graph:
            return
        curr_node = visited[node]
        for _, succ, data in graph.out_edges(node, data=True):
            label = data["label"]
            if succ not in visited:
                if isinstance(curr_node.typevar, DerivedTypeVariable):
                    base_typevar = curr_node.typevar.type_var
                    labels = curr_node.typevar.labels
                elif isinstance(curr_node.typevar, TypeVariable):
                    base_typevar = curr_node.typevar
                    labels = ()
                else:
                    raise TypeError("Unexpected")
                labels += (label,)
                succ_derived_typevar = DerivedTypeVariable(
                    base_typevar,
                    None,
                    labels=labels,
                )
                succ_node = SketchNode(succ_derived_typevar)
                sketch.add_edge(curr_node, succ_node, label)
                visited[succ] = succ_node
                SimpleSolver._get_all_paths(graph, sketch, succ, visited)
                del visited[succ]
            else:
                # a cycle exists
                ref_node = RecursiveRefNode(visited[succ].typevar)
                sketch.add_edge(curr_node, ref_node, label)

    @staticmethod
    def _unify(
        equivalence_classes: dict, cls0: DerivedTypeVariable, cls1: DerivedTypeVariable, graph: networkx.DiGraph
    ) -> None:
        # first convert cls0 and cls1 to their equivalence classes
        cls0 = equivalence_classes[cls0]
        cls1 = equivalence_classes[cls1]

        # unify if needed
        if cls0 != cls1:
            # MakeEquiv
            existing_elements = {key for key, item in equivalence_classes.items() if item in {cls0, cls1}}
            rep_cls = cls0
            for elem in existing_elements:
                equivalence_classes[elem] = rep_cls
            # the logic below refers to the retypd reference implementation. it is different from Algorithm E.1
            # note that graph is used read-only in this method, so we do not need to make copy of edges
            for _, dst0, data0 in graph.out_edges(cls0, data=True):
                if "label" in data0 and data0["label"] is not None:
                    for _, dst1, data1 in graph.out_edges(cls1, data=True):
                        if (
                            data0["label"] == data1["label"]
                            or isinstance(data0["label"], Load)
                            and isinstance(data1["label"], Store)
                        ):
                            SimpleSolver._unify(
                                equivalence_classes, equivalence_classes[dst0], equivalence_classes[dst1], graph
                            )

    def _eq_constraints_from_add(self, typevar: TypeVariable):
        """
        Handle Add constraints.
        """
        new_constraints = set()
        for constraint in self._constraints[typevar]:
            if isinstance(constraint, Add):
                if (
                    isinstance(constraint.type_0, TypeVariable)
                    and not isinstance(constraint.type_0, DerivedTypeVariable)
                    and isinstance(constraint.type_r, TypeVariable)
                    and not isinstance(constraint.type_r, DerivedTypeVariable)
                ):
                    new_constraints.add(Equivalence(constraint.type_0, constraint.type_r))
                if (
                    isinstance(constraint.type_1, TypeVariable)
                    and not isinstance(constraint.type_1, DerivedTypeVariable)
                    and isinstance(constraint.type_r, TypeVariable)
                    and not isinstance(constraint.type_r, DerivedTypeVariable)
                ):
                    new_constraints.add(Equivalence(constraint.type_1, constraint.type_r))
        return new_constraints

    def _handle_equivalence(self, typevar: TypeVariable):
        graph = networkx.Graph()

        replacements = {}
        constraints = set()

        # collect equivalence relations
        for constraint in self._constraints[typevar]:
            if isinstance(constraint, Equivalence):
                # | type_a == type_b
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
        for constraint in self._constraints[typevar]:
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

    def _convert_arrays(self, constraints):
        for constraint in constraints:
            if not isinstance(constraint, Existence):
                continue
            inner = constraint.type_
            if isinstance(inner, DerivedTypeVariable) and isinstance(inner.one_label(), IsArray):
                if inner.type_var in self.solution:
                    curr_type = self.solution[inner.type_var]
                    if isinstance(curr_type, Pointer) and isinstance(curr_type.basetype, Struct):
                        # replace all fields with the first field
                        if 0 in curr_type.basetype.fields:
                            first_field = curr_type.basetype.fields[0]
                            for offset in curr_type.basetype.fields.keys():
                                curr_type.basetype.fields[offset] = first_field

    #
    # Constraint graph
    #

    @staticmethod
    def _generate_constraint_subset(
        constraints: set[TypeConstraint], typevars: set[TypeVariable]
    ) -> set[TypeConstraint]:
        subset = set()
        related_typevars = set(typevars)
        while True:
            new = set()
            for constraint in constraints:
                if constraint in subset:
                    continue
                if isinstance(constraint, Subtype):
                    if isinstance(constraint.sub_type, DerivedTypeVariable):
                        subt = constraint.sub_type.type_var
                    elif isinstance(constraint.sub_type, TypeVariable):
                        subt = constraint.sub_type
                    else:
                        subt = None
                    if isinstance(constraint.super_type, DerivedTypeVariable):
                        supert = constraint.super_type.type_var
                    elif isinstance(constraint.super_type, TypeVariable):
                        supert = constraint.super_type
                    else:
                        supert = None
                    if subt in related_typevars or supert in related_typevars:
                        new.add(constraint)
                        if subt is not None:
                            related_typevars.add(subt)
                        if supert is not None:
                            related_typevars.add(supert)
            if not new:
                break
            subset |= new
        return subset

    def _generate_constraint_graph(
        self, constraints: set[TypeConstraint], interesting_variables: set[DerivedTypeVariable]
    ) -> networkx.DiGraph:
        """
        A constraint graph is the same as the finite state transducer that is presented in Appendix D in the retypd
        paper.
        """

        graph = networkx.DiGraph()
        for constraint in constraints:
            if isinstance(constraint, Subtype):
                self._constraint_graph_add_edges(
                    graph, constraint.sub_type, constraint.super_type, interesting_variables
                )
        self._constraint_graph_saturate(graph)
        self._constraint_graph_remove_self_loops(graph)
        self._constraint_graph_recall_forget_split(graph)
        return graph

    @staticmethod
    def _constraint_graph_add_recall_edges(graph: networkx.DiGraph, node: ConstraintGraphNode) -> None:
        while True:
            r = node.forget_last_label()
            if r is None:
                break
            prefix, last_label = r
            graph.add_edge(prefix, node, label=(last_label, "recall"))
            node = prefix

    @staticmethod
    def _constraint_graph_add_forget_edges(graph: networkx.DiGraph, node: ConstraintGraphNode) -> None:
        while True:
            r = node.forget_last_label()
            if r is None:
                break
            prefix, last_label = r
            graph.add_edge(node, prefix, label=(last_label, "forget"))
            node = prefix

    def _constraint_graph_add_edges(
        self,
        graph: networkx.DiGraph,
        subtype: TypeVariable | DerivedTypeVariable,
        supertype: TypeVariable | DerivedTypeVariable,
        interesting_variables: set[DerivedTypeVariable],
    ):
        # left and right tags
        if self._typevar_inside_set(self._to_typevar_or_typeconst(subtype), interesting_variables):
            left_tag = ConstraintGraphTag.LEFT
        else:
            left_tag = ConstraintGraphTag.UNKNOWN
        if self._typevar_inside_set(self._to_typevar_or_typeconst(supertype), interesting_variables):
            right_tag = ConstraintGraphTag.RIGHT
        else:
            right_tag = ConstraintGraphTag.UNKNOWN
        # nodes
        forward_src = ConstraintGraphNode(subtype, Variance.COVARIANT, left_tag, FORGOTTEN.PRE_FORGOTTEN)
        forward_dst = ConstraintGraphNode(supertype, Variance.COVARIANT, right_tag, FORGOTTEN.PRE_FORGOTTEN)
        graph.add_edge(forward_src, forward_dst)
        # add recall edges and forget edges
        self._constraint_graph_add_recall_edges(graph, forward_src)
        self._constraint_graph_add_forget_edges(graph, forward_dst)

        # backward edges
        backward_src = forward_dst.inverse()
        backward_dst = forward_src.inverse()
        graph.add_edge(backward_src, backward_dst)
        self._constraint_graph_add_recall_edges(graph, backward_src)
        self._constraint_graph_add_forget_edges(graph, backward_dst)

    @staticmethod
    def _constraint_graph_saturate(graph: networkx.DiGraph) -> None:
        """
        The saturation algorithm D.2 as described in Appendix of the retypd paper.
        """
        R: DefaultDict[ConstraintGraphNode, set[tuple[BaseLabel, ConstraintGraphNode]]] = defaultdict(set)

        # initialize the reaching-push sets R(x)
        for x, y, data in graph.edges(data=True):
            if "label" in data and data.get("label")[1] == "forget":
                d = data["label"][0], x
                R[y].add(d)

        # repeat ... until fixed point
        changed = True
        while changed:
            changed = False
            for x, y, data in graph.edges(data=True):
                if "label" not in data:
                    if R[y].issuperset(R[x]):
                        continue
                    changed = True
                    R[y] |= R[x]
            for x, y, data in graph.edges(data=True):
                lbl = data.get("label")
                if lbl and lbl[1] == "recall":
                    for label, z in R[x]:
                        if not graph.has_edge(z, y):
                            changed = True
                            graph.add_edge(z, y)
            v_contravariant = []
            for node in graph.nodes:
                node: ConstraintGraphNode
                if node.variance == Variance.CONTRAVARIANT:
                    v_contravariant.append(node)
            # lazily apply saturation rules corresponding to S-Pointer
            for x in v_contravariant:
                for z_label, z in R[x]:
                    label = None
                    if isinstance(z_label, Store):
                        label = Load()
                    elif isinstance(z_label, Load):
                        label = Store()
                    if label is not None:
                        x_inverse = x.inverse_wo_tag()
                        d = label, z
                        if d not in R[x_inverse]:
                            changed = True
                            R[x_inverse].add(d)

    @staticmethod
    def _constraint_graph_remove_self_loops(graph: networkx.DiGraph):
        for node in list(graph.nodes):
            if graph.has_edge(node, node):
                graph.remove_edge(node, node)

    @staticmethod
    def _constraint_graph_recall_forget_split(graph: networkx.DiGraph):
        """
        Ensure that recall edges are not reachable after traversing a forget node.
        """
        for src, dst, data in list(graph.edges(data=True)):
            src: ConstraintGraphNode
            dst: ConstraintGraphNode
            if "label" in data and data["label"][1] == "recall":
                continue
            forget_src = ConstraintGraphNode(src.typevar, src.variance, src.tag, FORGOTTEN.POST_FORGOTTEN)
            forget_dst = ConstraintGraphNode(dst.typevar, dst.variance, dst.tag, FORGOTTEN.POST_FORGOTTEN)
            if "label" in data and data["label"][1] == "forget":
                graph.remove_edge(src, dst)
                graph.add_edge(src, forget_dst, **data)
            graph.add_edge(forget_src, forget_dst, **data)

    @staticmethod
    def _to_typevar_or_typeconst(obj: TypeVariable | DerivedTypeVariable | TypeConstant) -> TypeVariable | TypeConstant:
        if isinstance(obj, DerivedTypeVariable):
            return SimpleSolver._to_typevar_or_typeconst(obj.type_var)
        elif isinstance(obj, TypeVariable):
            return obj
        elif isinstance(obj, TypeConstant):
            return obj
        raise TypeError(f"Unsupported type {type(obj)}")

    #
    # Graph solver
    #

    @staticmethod
    def _typevar_inside_set(typevar, typevar_set: set[TypeConstant | TypeVariable | DerivedTypeVariable]) -> bool:
        if typevar in typevar_set:
            return True
        if isinstance(typevar, Struct) and Struct_ in typevar_set:
            if not typevar.fields:
                return True
            return all(
                SimpleSolver._typevar_inside_set(field_typevar, typevar_set)
                for field_typevar in typevar.fields.values()
            )
        if isinstance(typevar, Array) and Array_ in typevar_set:
            return SimpleSolver._typevar_inside_set(typevar.element, typevar_set)
        if isinstance(typevar, Pointer) and (Pointer32_ in typevar_set or Pointer64_ in typevar_set):
            return SimpleSolver._typevar_inside_set(typevar.basetype, typevar_set)
        return False

    def _solve_constraints_between(
        self,
        graph: networkx.DiGraph,
        starts: set[TypeConstant | TypeVariable | DerivedTypeVariable],
        ends: set[TypeConstant | TypeVariable | DerivedTypeVariable],
    ) -> set[TypeConstraint]:
        start_nodes = set()
        end_nodes = set()
        for node in graph.nodes:
            node: ConstraintGraphNode
            if (
                self._typevar_inside_set(self._to_typevar_or_typeconst(node.typevar), starts)
                and node.tag == ConstraintGraphTag.LEFT
            ):
                start_nodes.add(node)
            if (
                self._typevar_inside_set(self._to_typevar_or_typeconst(node.typevar), ends)
                and node.tag == ConstraintGraphTag.RIGHT
            ):
                end_nodes.add(node)

        if not start_nodes or not end_nodes:
            return set()

        dfa_solver = DFAConstraintSolver()
        try:
            return dfa_solver.generate_constraints_between(graph, start_nodes, end_nodes)
        except EmptyEpsilonNFAError:
            return set()

    #
    # Type lattice
    #

    def join(self, t1: TypeConstant | TypeVariable, t2: TypeConstant | TypeVariable) -> TypeConstant:
        abstract_t1 = self.abstract(t1)
        abstract_t2 = self.abstract(t2)
        if abstract_t1 in self._base_lattice and abstract_t2 in self._base_lattice:
            ancestor = networkx.lowest_common_ancestor(self._base_lattice, abstract_t1, abstract_t2)
            if ancestor == abstract_t1:
                return t1
            elif ancestor == abstract_t2:
                return t2
            else:
                return ancestor
        if t1 == Bottom_:
            return t2
        if t2 == Bottom_:
            return t1
        return Bottom_

    def meet(self, t1: TypeConstant | TypeVariable, t2: TypeConstant | TypeVariable) -> TypeConstant:
        abstract_t1 = self.abstract(t1)
        abstract_t2 = self.abstract(t2)
        if abstract_t1 in self._base_lattice_inverted and abstract_t2 in self._base_lattice_inverted:
            ancestor = networkx.lowest_common_ancestor(self._base_lattice_inverted, abstract_t1, abstract_t2)
            if ancestor == abstract_t1:
                return t1
            elif ancestor == abstract_t2:
                return t2
            else:
                return ancestor
        if t1 == Top_:
            return t2
        if t2 == Top_:
            return t1
        return Top_

    @staticmethod
    def abstract(t: TypeConstant | TypeVariable) -> TypeConstant | TypeVariable:
        if isinstance(t, Pointer32):
            return Pointer32()
        elif isinstance(t, Pointer64):
            return Pointer64()
        return t

    def determine(
        self,
        equivalent_classes: dict[TypeVariable, TypeVariable],
        sketches,
        solution: dict,
        nodes: set[SketchNode] | None = None,
    ) -> None:
        """
        Determine C-like types from sketches.

        :param equivalent_classes:  A dictionary mapping each type variable from its representative in the equivalence
                                    class over ~.
        :param sketches:            A dictionary storing sketches for each type variable.
        :param solution:            The dictionary storing C-like types for each type variable. Output.
        :param nodes:               Optional. Nodes that should be considered in the sketch.
        :return:                    None
        """
        for typevar, sketch in sketches.items():
            self._determine(equivalent_classes, typevar, sketch, solution, nodes=nodes)

        for v, e in self._equivalence.items():
            if v not in solution and e in solution:
                solution[v] = solution[e]

    def _determine(self, equivalent_classes, the_typevar, sketch, solution: dict, nodes: set[SketchNode] | None = None):
        """
        Return the solution from sketches
        """

        if not nodes:
            # TODO: resolve references
            node = sketch.lookup(the_typevar)
            assert node is not None
            nodes = {node}

        # consult the cache
        cached_results = set()
        for node in nodes:
            if node.typevar in self._solution_cache:
                cached_results.add(self._solution_cache[node.typevar])
        if len(cached_results) == 1:
            return next(iter(cached_results))
        elif len(cached_results) > 1:
            # we get nodes for multiple type variables?
            raise RuntimeError("Getting nodes for multiple type variables. Unexpected.")

        # collect all successors and the paths (labels) of this type variable
        path_and_successors = []
        last_labels = []
        for node in nodes:
            path_and_successors += self._collect_sketch_paths(node, sketch)
        for labels, _ in path_and_successors:
            if labels:
                last_labels.append(labels[-1])

        # now, what is this variable?
        result = None

        if last_labels and all(isinstance(label, (FuncIn, FuncOut)) for label in last_labels):
            # create a dummy result and dump it to the cache
            func_type = Function([], [])
            result = self._pointer_class()(basetype=func_type)
            for node in nodes:
                self._solution_cache[node.typevar] = result

            # this is a function variable
            func_inputs = defaultdict(set)
            func_outputs = defaultdict(set)

            for labels, succ in path_and_successors:
                last_label = labels[-1] if labels else None

                if isinstance(last_label, FuncIn):
                    func_inputs[last_label.loc].add(succ)
                elif isinstance(last_label, FuncOut):
                    func_outputs[last_label.loc].add(succ)
                else:
                    raise RuntimeError("Unreachable")

            input_args = []
            output_values = []
            for vals, out in [(func_inputs, input_args), (func_outputs, output_values)]:
                for idx in range(0, max(vals) + 1):
                    if idx in vals:
                        sol = self._determine(equivalent_classes, the_typevar, sketch, solution, nodes=vals[idx])
                        out.append(sol)
                    else:
                        out.append(None)

            # back patch
            func_type.params = input_args
            func_type.outputs = output_values

            for node in nodes:
                solution[node.typevar] = result

        elif path_and_successors:
            # maybe this is a pointer to a struct?
            if len(nodes) == 1:
                the_node = next(iter(nodes))
                if (
                    isinstance(the_node.upper_bound, self._pointer_class())
                    and isinstance(the_node.upper_bound.basetype, Struct)
                    and the_node.upper_bound.basetype.name
                ):
                    # handle pointers to known struct types
                    result = (
                        the_node.lower_bound
                        if not isinstance(the_node.lower_bound, BottomType)
                        else the_node.upper_bound
                    )
                    for node in nodes:
                        solution[node.typevar] = result
                        self._solution_cache[node.typevar] = result
                    return result

            # create a dummy result and shove it into the cache
            struct_type = Struct(fields={})
            result = self._pointer_class()(struct_type)
            for node in nodes:
                self._solution_cache[node.typevar] = result

            # this might be a struct
            fields = {}

            candidate_bases = defaultdict(set)

            for labels, succ in path_and_successors:
                last_label = labels[-1] if labels else None
                if isinstance(last_label, HasField):
                    candidate_bases[last_label.offset].add(last_label.bits // 8)

            node_to_base = {}

            for labels, succ in path_and_successors:
                last_label = labels[-1] if labels else None
                if isinstance(last_label, HasField):
                    for start_offset, sizes in candidate_bases.items():
                        for size in sizes:
                            if last_label.offset > start_offset:
                                if last_label.offset < start_offset + size:  # ???
                                    node_to_base[succ] = start_offset

            node_by_offset = defaultdict(set)

            for labels, succ in path_and_successors:
                last_label = labels[-1] if labels else None
                if isinstance(last_label, HasField):
                    if succ in node_to_base:
                        node_by_offset[node_to_base[succ]].add(succ)
                    else:
                        node_by_offset[last_label.offset].add(succ)

            for offset, child_nodes in node_by_offset.items():
                sol = self._determine(equivalent_classes, the_typevar, sketch, solution, nodes=child_nodes)
                if isinstance(sol, TopType):
                    sol = int_type(min(candidate_bases[offset]) * 8)
                fields[offset] = sol

            if not fields:
                result = Top_
                for node in nodes:
                    self._solution_cache[node.typevar] = result
            else:
                # back-patch
                struct_type.fields = fields
                for node in nodes:
                    solution[node.typevar] = result

        if not path_and_successors or result in {Top_, None}:
            # this is probably a primitive variable
            lower_bound = Bottom_
            upper_bound = Top_

            for node in nodes:
                lower_bound = self.join(lower_bound, node.lower_bound)
                upper_bound = self.meet(upper_bound, node.upper_bound)
                # TODO: Support variables that are accessed via differently sized pointers

            result = lower_bound if not isinstance(lower_bound, BottomType) else upper_bound
            for node in nodes:
                solution[node.typevar] = result
                self._solution_cache[node.typevar] = result

        # import pprint

        # print("Solution")
        # pprint.pprint(result)
        return result

    @staticmethod
    def _collect_sketch_paths(node: SketchNodeBase, sketch: Sketch) -> list[tuple[list[BaseLabel], SketchNodeBase]]:
        """
        Collect all paths that go from `typevar` to its leaves.
        """
        paths = []
        visited: set[SketchNodeBase] = set()
        queue: list[tuple[list[BaseLabel], SketchNodeBase]] = [([], node)]

        while queue:
            curr_labels, curr_node = queue.pop(0)
            if curr_node in visited:
                continue
            visited.add(curr_node)

            out_edges = sketch.graph.out_edges(curr_node, data=True)
            for _, succ, data in out_edges:
                if isinstance(succ, RecursiveRefNode):
                    ref = succ
                    succ: SketchNode | None = sketch.lookup(succ.target)
                    if succ is None:
                        # failed to resolve...
                        _l.warning(
                            "Failed to resolve reference node to a real sketch node for type variable %s", ref.target
                        )
                        continue
                label = data["label"]
                if isinstance(label, ConvertTo):
                    # drop conv labels for now
                    continue
                if isinstance(label, IsArray):
                    continue
                new_labels = curr_labels + [label]
                succ: SketchNode
                if isinstance(succ.typevar, DerivedTypeVariable) and isinstance(succ.typevar.labels[-1], (Load, Store)):
                    queue.append((new_labels, succ))
                else:
                    paths.append((new_labels, succ))

        return paths

    def _pointer_class(self) -> type[Pointer32] | type[Pointer64]:
        if self.bits == 32:
            return Pointer32
        elif self.bits == 64:
            return Pointer64
        raise NotImplementedError("Unsupported bits %d" % self.bits)
