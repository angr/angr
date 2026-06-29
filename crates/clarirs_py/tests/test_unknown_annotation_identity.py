from __future__ import annotations

import unittest

import claripy


class KeyedAnnotation(claripy.Annotation):
    """A user-defined annotation whose identity is content-based via a custom
    __hash__/__eq__: only ``key`` matters. ``extra`` varies fields the pickled
    bytes include without changing identity."""

    def __init__(self, key, extra=None):
        self.key = key
        self.extra = extra

    def __hash__(self):
        return hash(("KeyedAnnotation", self.key))

    def __eq__(self, other):
        return isinstance(other, KeyedAnnotation) and other.key == self.key


class TestUnknownAnnotationIdentity(unittest.TestCase):
    """Unknown (Python-defined) annotations are identified by the Python
    object's hash, mirroring claripy's use of annotation __hash__/__eq__ — not
    by their (non-canonical) pickled bytes."""

    def setUp(self):
        self.base = claripy.BVS("v", 32, explicit_name=True)

    def test_custom_hash_content_equal_are_identical(self):
        a = self.base.annotate(KeyedAnnotation("a"))
        b = self.base.annotate(KeyedAnnotation("a"))
        self.assertEqual(a.hash(), b.hash())

    def test_custom_hash_distinct_keys_differ(self):
        a = self.base.annotate(KeyedAnnotation("a"))
        b = self.base.annotate(KeyedAnnotation("b"))
        self.assertNotEqual(a.hash(), b.hash())

    def test_custom_hash_ignores_fields_outside_identity(self):
        # Two annotations equal by __eq__/__hash__ but pickling to different
        # bytes (extra differs) still hash equal: identity follows the object's
        # hash, not the pickled bytes.
        a = self.base.annotate(KeyedAnnotation("a", extra=1))
        b = self.base.annotate(KeyedAnnotation("a", extra=2))
        self.assertEqual(a.hash(), b.hash())

    def test_same_object_is_stable(self):
        anno = KeyedAnnotation("a")
        self.assertEqual(self.base.annotate(anno).hash(), self.base.annotate(anno).hash())
