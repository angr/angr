from unittest import TestCase

from angr.knowledge_plugins.key_definitions.dataset import DataSet, dataset_from_datasets
from angr.knowledge_plugins.key_definitions.unknown_size import UNKNOWN_SIZE


class TestDataSet(TestCase):
    def test_dataset_from_datasets(self):
        datasets = [
            DataSet({1}   , 4),
            DataSet({2, 3}, 4),
        ]

        result = dataset_from_datasets(datasets)

        self.assertSetEqual(result.data, {1, 2, 3})
        self.assertEqual(result._bits, 4)

    def test_dataset_from_datasets_with_different_sizes(self):
        datasets = [
            DataSet({1}   , 4),
            DataSet({2, 3}, 8),
        ]

        result = dataset_from_datasets(datasets)

        self.assertSetEqual(result.data, {1, 2, 3})
        self.assertEqual(result._bits, UNKNOWN_SIZE)
