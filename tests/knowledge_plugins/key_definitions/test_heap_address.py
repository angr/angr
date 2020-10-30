from unittest import TestCase

from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress


class TestHeapAddress(TestCase):
    def test_expose_its_value_as_a_property(self):
        address = HeapAddress(0x42)
        self.assertEqual(address.value, 0x42)
