
class TestData(object):
    def __init__(self, input_args, expected_output_args, expected_return_val, max_steps, preloaded_stdin=None,
                 expected_stdout=None):
        assert isinstance(input_args, (list, tuple))
        assert isinstance(expected_output_args, (list, tuple))
        if preloaded_stdin is None:
            preloaded_stdin = ""
        if expected_stdout is None:
            expected_stdout = ""
        for i, v in enumerate(input_args):
            if type(v) is str:
                input_args[i] = v.encode('latin-1')  # py3k transition hack :/

        self.input_args = input_args
        self.expected_output_args = expected_output_args
        self.expected_return_val = expected_return_val
        self.preloaded_stdin = preloaded_stdin
        self.expected_stdout = expected_stdout
        self.max_steps = max_steps


class Func(object):
    def __init__(self):
        pass

    def get_name(self):
        raise NotImplementedError()

    def num_args(self):
        raise NotImplementedError()

    def gen_input_output_pair(self):
        raise NotImplementedError()

    def var_args(self): #pylint disable=no-self-use
        return False

    def can_call_other_funcs(self): #pylint disable=no-self-use
        return True

    def pre_test(self, func, runner): #pylint disable=no-self-use,unused-argument
        """
        custom tests run before, return False if it for sure is not the function
        Use tests here to pick which version of the function
        :arg func: the cfg function it will be compared against
        :arg runner: a runner to run the tests with
        :return: True if we should continue testing
        """

        return True
