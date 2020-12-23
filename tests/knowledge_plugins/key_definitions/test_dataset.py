from unittest import TestCase

from angr.knowledge_plugins.key_definitions.dataset import DataSet, dataset_from_datasets, size_of_datasets
from angr.knowledge_plugins.key_definitions.undefined import UNDEFINED
from angr.knowledge_plugins.key_definitions.unknown_size import UNKNOWN_SIZE


class TestDataSet(TestCase):
    def test_size_of_datasets_with_inputs_of_same_size(self):
        datasets = [
            DataSet(set(), 4),
            DataSet(set(), 4),
        ]

        self.assertEqual(size_of_datasets(datasets), 4)

    def test_size_of_datasets_with_inputs_of_different_size(self):
        datasets = [
            DataSet(set(), 2),
            DataSet(set(), 4),
        ]

        self.assertEqual(size_of_datasets(datasets), UNKNOWN_SIZE)

    def test_size_of_datasets_with_empty_list_of_datasets(self):
        datasets = []

        self.assertEqual(size_of_datasets(datasets), UNKNOWN_SIZE)

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

    def test_dataset_from_datasets_with_empty_list_of_datasets(self):
        datasets = []
        result = dataset_from_datasets(datasets)

        self.assertSetEqual(result.data, {UNDEFINED})
        self.assertEqual(result._bits, UNKNOWN_SIZE)

    def test_representation_shortens_content_with_repeated_character(self):
        size = 30
        long_string = 'test: ' + 'a' * size + 'b' * size
        dataset = DataSet({long_string}, len(long_string))

        self.assertEqual(
            "%s" % dataset,
            "DataSet<%s>: ['test: a...(repeats 30 times)b...(repeats 30 times)']" % (len(long_string))
        )

    def test_representation_does_not_shorten_content_of_reasonable_length(self):
        string = 'not too long'
        dataset = DataSet({string}, len(string))

        self.assertEqual(
            "%s" % dataset,
            "DataSet<%s>: ['not too long']" % (len(string))
        )
