from __future__ import annotations

import unittest

import claripy as claripy
from claripy.annotation import EmptyStridedIntervalAnnotation


class CustomAnnotation(claripy.Annotation):
    """A user-defined annotation, used to exercise the unknown/pickle path."""

    def __init__(self, payload):
        self.payload = payload


class CustomRelocatableAnnotation(claripy.Annotation):
    relocatable = False
    eliminatable = False

    def __init__(self, tag):
        self.tag = tag


class TestAnnotationClasses(unittest.TestCase):
    def test_base_class_flags(self):
        self.assertFalse(claripy.Annotation.relocatable)
        self.assertTrue(claripy.Annotation.eliminatable)

    def test_builtin_subclasses_are_annotations(self):
        for anno in (
            claripy.SimplificationAvoidanceAnnotation(),
            claripy.StridedIntervalAnnotation(1, 2, 3),
            EmptyStridedIntervalAnnotation(),
            claripy.RegionAnnotation("global", 0),
            claripy.UninitializedAnnotation(),
        ):
            self.assertIsInstance(anno, claripy.Annotation)

    def test_flags(self):
        cases = {
            claripy.SimplificationAvoidanceAnnotation(): (False, False),
            claripy.StridedIntervalAnnotation(1, 2, 3): (False, False),
            EmptyStridedIntervalAnnotation(): (False, False),
            claripy.RegionAnnotation("global", 0): (False, False),
            claripy.UninitializedAnnotation(): (True, False),
        }
        for anno, (relocatable, eliminatable) in cases.items():
            self.assertEqual(anno.relocatable, relocatable)
            self.assertEqual(anno.eliminatable, eliminatable)

    def test_repr(self):
        self.assertEqual(
            repr(claripy.SimplificationAvoidanceAnnotation()),
            "SimplificationAvoidanceAnnotation()",
        )
        self.assertEqual(
            repr(claripy.StridedIntervalAnnotation(1, 2, 3)),
            "StridedIntervalAnnotation(stride=1, lower_bound=2, upper_bound=3)",
        )
        self.assertEqual(
            repr(EmptyStridedIntervalAnnotation()),
            "EmptyStridedIntervalAnnotation()",
        )
        self.assertEqual(
            repr(claripy.RegionAnnotation("global", 0)),
            "RegionAnnotation(region_id=global, region_base_addr=0)",
        )
        self.assertEqual(
            repr(claripy.UninitializedAnnotation()),
            "UninitializedAnnotation()",
        )

    def test_strided_interval_fields(self):
        anno = claripy.StridedIntervalAnnotation(2, 4, 8)
        self.assertEqual(anno.stride, 2)
        self.assertEqual(anno.lower_bound, 4)
        self.assertEqual(anno.upper_bound, 8)

    def test_region_fields(self):
        anno = claripy.RegionAnnotation("stack", 0x1000)
        self.assertEqual(anno.region_id, "stack")
        self.assertEqual(anno.region_base_addr, 0x1000)


class TestAnnotationRoundtrip(unittest.TestCase):
    def test_builtin_roundtrip(self):
        bv = claripy.BVS("x", 32)
        annotated = bv.annotate(claripy.StridedIntervalAnnotation(3, 0, 9))

        annotations = annotated.annotations
        self.assertEqual(len(annotations), 1)
        anno = annotations[0]
        self.assertIsInstance(anno, claripy.StridedIntervalAnnotation)
        self.assertEqual(anno.stride, 3)
        self.assertEqual(anno.lower_bound, 0)
        self.assertEqual(anno.upper_bound, 9)

    def test_has_and_get_annotation(self):
        bv = claripy.BVS("x", 32).annotate(claripy.RegionAnnotation("heap", 0x20))

        self.assertTrue(bv.has_annotation_type(claripy.RegionAnnotation))
        self.assertFalse(bv.has_annotation_type(claripy.UninitializedAnnotation))

        anno = bv.get_annotation(claripy.RegionAnnotation)
        self.assertIsInstance(anno, claripy.RegionAnnotation)
        self.assertEqual(anno.region_id, "heap")

    def test_append_and_remove(self):
        si = claripy.StridedIntervalAnnotation(1, 0, 1)
        uninit = claripy.UninitializedAnnotation()

        bv = claripy.BVS("x", 32).append_annotations([si, uninit])
        self.assertEqual(len(bv.annotations), 2)

        cleared = bv.clear_annotations()
        self.assertEqual(len(cleared.annotations), 0)

    def test_user_annotation_roundtrip(self):
        bv = claripy.BVS("x", 32).annotate(CustomAnnotation("payload"))

        annotations = bv.annotations
        self.assertEqual(len(annotations), 1)
        anno = annotations[0]
        self.assertIsInstance(anno, CustomAnnotation)
        self.assertEqual(anno.payload, "payload")
        # Defaults inherited from the base class.
        self.assertFalse(anno.relocatable)
        self.assertTrue(anno.eliminatable)

    def test_user_annotation_overridden_flags(self):
        anno = CustomRelocatableAnnotation("t")
        self.assertFalse(anno.relocatable)
        self.assertFalse(anno.eliminatable)

        bv = claripy.BVS("x", 32).annotate(anno)
        roundtripped = bv.annotations[0]
        self.assertIsInstance(roundtripped, CustomRelocatableAnnotation)
        self.assertEqual(roundtripped.tag, "t")

    def test_user_annotation_identity_preserved(self):
        # While the original Python object is alive, retrieval returns it
        # verbatim rather than an unpickled copy, so `is` holds.
        anno = CustomRelocatableAnnotation("t")
        bv = claripy.BVS("x", 32).annotate(anno)
        self.assertIs(bv.annotations[0], anno)
        self.assertIs(bv.annotations[0], bv.annotations[0])

    def test_user_annotation_reconstructed_after_original_gc(self):
        # Once the original is gone, retrieval falls back to unpickling a fresh
        # equal copy (the cache holds only a weak reference).
        import gc

        bv = claripy.BVS("x", 32).annotate(CustomRelocatableAnnotation("t"))
        gc.collect()
        roundtripped = bv.annotations[0]
        self.assertIsInstance(roundtripped, CustomRelocatableAnnotation)
        self.assertEqual(roundtripped.tag, "t")

    def test_builtin_annotation_identity_preserved(self):
        # Identity preservation is not limited to user-defined annotations: a
        # built-in annotation that is still alive is also handed back verbatim,
        # so `is` holds both against the original and across repeated reads.
        for anno in (
            claripy.SimplificationAvoidanceAnnotation(),
            claripy.StridedIntervalAnnotation(3, 0, 9),
            EmptyStridedIntervalAnnotation(),
            claripy.RegionAnnotation("heap", 0x20),
            claripy.UninitializedAnnotation(),
        ):
            with self.subTest(annotation=anno):
                bv = claripy.BVS("x", 32).annotate(anno)
                self.assertIs(bv.annotations[0], anno)
                self.assertIs(bv.annotations[0], bv.annotations[0])

    def test_builtin_annotation_reconstructed_after_original_gc(self):
        # Once the original built-in annotation is gone, retrieval falls back to
        # reconstructing a fresh equal copy from the stored core value.
        import gc

        bv = claripy.BVS("x", 32).annotate(claripy.RegionAnnotation("heap", 0x20))
        gc.collect()
        roundtripped = bv.annotations[0]
        self.assertIsInstance(roundtripped, claripy.RegionAnnotation)
        self.assertEqual(roundtripped.region_id, "heap")
        self.assertEqual(roundtripped.region_base_addr, 0x20)
