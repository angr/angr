from unittest import TestCase

from angr.knowledge_plugins.key_definitions.atoms import SpOffset
from angr.knowledge_plugins.key_definitions.dataset import DataSet
from angr.knowledge_plugins.key_definitions.environment import Environment
from angr.knowledge_plugins.key_definitions.undefined import UNDEFINED
from angr.knowledge_plugins.key_definitions.unknown_size import UNKNOWN_SIZE


class TestEnvironment(TestCase):
    def setUp(self):
        self.pointer_length = 8
        self.pointer = SpOffset(self.pointer_length * 8, -0xff)

    def test_get_returns_the_pointer_associated_with_an_existing_environment_variable(self):
        name = 'variable_name'
        data = DataSet({self.pointer}, self.pointer_length)
        environment = Environment(environment={ name: data })

        variable_names = DataSet({name}, len(name))

        result_values, _ = environment.get(variable_names)
        self.assertEqual(result_values, data)

    def test_get_returns_a_dataset_with_UNDEFINED_when_the_environment_variable_is_not_set(self):
        environment = Environment(environment={})

        name = 'variable_name'
        variable_names = DataSet({name}, len(name))

        result_values, _ = environment.get(variable_names)
        self.assertEqual(result_values, DataSet({UNDEFINED}, UNKNOWN_SIZE))

    def test_get_returns_values_associated_with_all_possible_given_names(self):
        environment_data = {
            'variable_name': DataSet({self.pointer}, self.pointer_length),
            UNDEFINED: DataSet({UNDEFINED}, UNKNOWN_SIZE)
        }
        environment = Environment(environment=environment_data)

        variable_names = DataSet({'variable_name', UNDEFINED}, UNKNOWN_SIZE)
        expected_result = DataSet({self.pointer, UNDEFINED}, UNKNOWN_SIZE)

        result_values, _ = environment.get(variable_names)
        self.assertEqual(result_values, expected_result)

    def test_get_fails_when_called_with_wrong_type_of_name(self):
        environment = Environment(environment={})
        variable_names = DataSet({0x42}, 8)

        self.assertRaises(TypeError, environment.get, variable_names)

    def test_get_result_tells_if_environment_knows_about_all_the_variables(self):
        name = 'variable_name'
        data = DataSet({self.pointer}, self.pointer_length)
        environment = Environment(environment={ name: data })

        name = 'variable_name'
        variable_names = DataSet({name}, UNKNOWN_SIZE)

        _, has_unknown = environment.get(variable_names)
        self.assertFalse(has_unknown)

    def test_get_result_tells_if_environment_does_not_know_about_one_of_the_variable(self):
        name = 'variable_name'
        data = DataSet({'value'}, 6)
        environment = Environment(environment={ name: data })

        name = 'variable_name'
        variable_names = DataSet({name, 'unknown_name'}, UNKNOWN_SIZE)

        _, has_unknown = environment.get(variable_names)
        self.assertTrue(has_unknown)

    def test_set_sets_associates_data_to_a_given_variable_name(self):
        environment = Environment(environment={})

        data = DataSet({'value'}, 6)
        environment.set('variable_name', data)

        # Testing internal attribute which is not ideal, but I am trying to not rely on any other behavior
        # (e.g. without using `get`).
        self.assertDictEqual(environment._environment, { 'variable_name': data })

    def test_set_sets_can_associate_data_to_UNDEFINED(self):
        environment = Environment(environment={})

        data = DataSet({'value'}, 6)
        environment.set(UNDEFINED, data)

        # Testing internal attribute which is not ideal, but I am trying to not rely on any other behavior
        # (e.g. without using `get`).
        self.assertDictEqual(environment._environment, { UNDEFINED: data })

    def test_set_fails_when_wvariable_name_is_of_wrong_type(self):
        environment = Environment(environment={})

        data = DataSet({'value'}, 6)

        self.assertRaises(TypeError, environment.set, 0x42, data)
