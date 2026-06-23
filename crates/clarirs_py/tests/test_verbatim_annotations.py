from __future__ import annotations

import unittest

import claripy


class RelocAnnotation(claripy.Annotation):
    """A relocatable annotation: it propagates from a child to the nodes built
    on top of it."""

    relocatable = True
    eliminatable = False

    def __init__(self, tag):
        self.tag = tag

    def __hash__(self):
        return hash(("RelocAnnotation", self.tag))

    def __eq__(self, other):
        return isinstance(other, RelocAnnotation) and other.tag == self.tag


class OtherAnnotation(claripy.Annotation):
    def __init__(self, tag):
        self.tag = tag

    def __hash__(self):
        return hash(("OtherAnnotation", self.tag))

    def __eq__(self, other):
        return isinstance(other, OtherAnnotation) and other.tag == self.tag


class TestVerbatimAnnotations(unittest.TestCase):
    """The annotation-management methods set a node's annotation tuple
    verbatim (matching claripy), so an explicit replace/remove/clear can drop
    an annotation that a child also carries. Building new nodes still
    propagates children's relocatable annotations."""

    def setUp(self):
        # A child carrying a relocatable annotation, and a parent that inherits
        # it through ordinary construction.
        self.child = claripy.BVS("x", 32, explicit_name=True).annotate(RelocAnnotation("a"))
        self.parent = self.child + 1

    def test_operations_propagate_child_relocatable_annotations(self):
        # The propagating wrapper is preserved: a freshly built node still picks
        # up its children's relocatable annotations.
        self.assertTrue(any(isinstance(a, RelocAnnotation) for a in self.parent.annotations))
        self.assertTrue(any(isinstance(a, RelocAnnotation) for a in (self.child * 2).annotations))

    def test_clear_annotations_is_verbatim(self):
        # Clearing empties the set even though the child still carries the
        # relocatable annotation (it is not re-collected).
        cleared = self.parent.clear_annotations()
        self.assertEqual(cleared.annotations, [])

    def test_remove_annotation_drops_inherited_annotation(self):
        inherited = next(a for a in self.parent.annotations if isinstance(a, RelocAnnotation))
        removed = self.parent.remove_annotation(inherited)
        self.assertFalse(any(isinstance(a, RelocAnnotation) for a in removed.annotations))

    def test_replace_annotations_is_verbatim(self):
        # The result carries exactly the given annotations, not the union with
        # the child's relocatable annotation.
        replaced = self.parent.replace_annotations((OtherAnnotation("z"),))
        self.assertEqual(
            sorted(type(a).__name__ for a in replaced.annotations),
            ["OtherAnnotation"],
        )


class TestVerbatimConstruction(unittest.TestCase):
    """Simplification is the job of the paths that *create* ASTs (operators and
    factory functions). The paths that merely wrap an existing op keep it
    verbatim: the `__new__` constructor (used e.g. when unpickling) faithfully
    reconstructs a node without re-simplifying."""

    def test_operators_simplify(self):
        x = claripy.BVS("x", 64, explicit_name=True)
        self.assertEqual((x + claripy.BVV(0, 64)).op, "BVS")

    def test_factory_functions_simplify(self):
        x = claripy.BVS("x", 64, explicit_name=True)
        self.assertEqual(claripy.ast.bv.Add(x, claripy.BVV(0, 64)).op, "BVS")

    def test_new_constructor_is_verbatim(self):
        x = claripy.BVS("x", 64, explicit_name=True)
        raw = claripy.ast.bv.BV("__add__", [x, claripy.BVV(0, 64)])
        self.assertEqual(raw.op, "__add__")

    def test_pickle_round_trip_preserves_op(self):
        import pickle

        x = claripy.BVS("x", 64, explicit_name=True)
        expr = x + claripy.BVV(5, 64)
        self.assertEqual(pickle.loads(pickle.dumps(expr)).op, expr.op)


if __name__ == "__main__":
    unittest.main()
