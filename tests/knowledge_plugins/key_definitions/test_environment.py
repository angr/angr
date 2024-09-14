#!/usr/bin/env python3
from __future__ import annotations
from unittest import main, TestCase

import claripy

from angr.knowledge_plugins.key_definitions.environment import Environment
from angr.knowledge_plugins.key_definitions.undefined import UNDEFINED


class TestEnvironment(TestCase):
    def setUp(self):
        self.pointer_length = 8
        self.pointer = 0x7FFFFFFFF00 - 0xFF

    def test_get_returns_the_pointer_associated_with_an_existing_environment_variable(self):
        name = "variable_name"
        data = {claripy.BVV(self.pointer, self.pointer_length)}
        environment = Environment(environment={name: data})

        variable_names = {name}

        result_values, _ = environment.get(variable_names)
        self.assertEqual(result_values, data)

    def test_get_returns_a_dataset_with_UNDEFINED_when_the_environment_variable_is_not_set(self):
        environment = Environment(environment={})

        name = "variable_name"
        variable_names = {name}

        result_values, _ = environment.get(variable_names)
        self.assertEqual(result_values, {UNDEFINED})

    def test_get_returns_values_associated_with_all_possible_given_names(self):
        environment_data = {
            "variable_name": {claripy.BVV(self.pointer, self.pointer_length)},
            UNDEFINED: {UNDEFINED},
        }
        environment = Environment(environment=environment_data)

        variable_names = {"variable_name", UNDEFINED}
        expected_result = {claripy.BVV(self.pointer, self.pointer_length), UNDEFINED}

        result_values, _ = environment.get(variable_names)
        self.assertEqual(result_values, expected_result)

    def test_get_fails_when_called_with_wrong_type_of_name(self):
        environment = Environment(environment={})
        variable_names = {claripy.BVV(0x42, 8 * 8)}

        self.assertRaises(TypeError, environment.get, variable_names)

    def test_get_result_tells_if_environment_knows_about_all_the_variables(self):
        name = "variable_name"
        data = {claripy.BVV(self.pointer, self.pointer_length)}
        environment = Environment(environment={name: data})

        name = "variable_name"
        variable_names = {name}

        _, has_unknown = environment.get(variable_names)
        self.assertFalse(has_unknown)

    def test_get_result_tells_if_environment_does_not_know_about_one_of_the_variable(self):
        name = "variable_name"
        data = {claripy.BVV(b"value\x00", 6 * 8)}
        environment = Environment(environment={name: data})

        name = "variable_name"
        variable_names = {name, "unknown_name"}

        _, has_unknown = environment.get(variable_names)
        self.assertTrue(has_unknown)

    def test_set_sets_associates_data_to_a_given_variable_name(self):
        environment = Environment(environment={})

        data = {claripy.BVV(b"value\x00", 6 * 8)}
        environment.set("variable_name", data)

        # Testing internal attribute which is not ideal, but I'am trying to not rely on any other behavior
        # (e.g. without using `get`).
        self.assertDictEqual(environment._environment, {"variable_name": data})

    def test_set_sets_can_associate_data_to_UNDEFINED(self):
        environment = Environment(environment={})

        data = {claripy.BVV(b"value\x00", 6 * 8)}
        environment.set(UNDEFINED, data)

        # Testing internal attribute which is not ideal, but I'am trying to not rely on any other behavior
        # (e.g. without using `get`).
        self.assertDictEqual(environment._environment, {UNDEFINED: data})

    def test_set_fails_when_wvariable_name_is_of_wrong_type(self):
        environment = Environment(environment={})

        data = {claripy.BVV(b"value\x00", 6 * 8)}

        self.assertRaises(TypeError, environment.set, 0x42, data)

    def test_merge_fails_when_merging_with_a_non_Environment_instance(self):
        environment = Environment(environment={"variable_name": {claripy.BVV(b"value1\x00", 7 * 8)}})
        other_environment = 0x42

        self.assertRaises(TypeError, environment.merge, other_environment)

    def test_merge_two_environments_merge_data_associated_with_each_variable(self):
        first = "variable_name"
        second = "other_variable_name"
        environment = Environment(environment={first: {claripy.BVV(b"value1\x00", 7 * 8)}})
        other_environment = Environment(environment={first: {claripy.BVV(b"value2\x00", 7 * 8)}, second: {UNDEFINED}})

        expected_environment = Environment(
            environment={
                first: {claripy.BVV(b"value1\x00", 7 * 8), claripy.BVV(b"value2\x00", 7 * 8)},
                second: {UNDEFINED},
            }
        )

        env, _ = environment.merge(other_environment)
        self.assertEqual(env, expected_environment)


if __name__ == "__main__":
    main()
