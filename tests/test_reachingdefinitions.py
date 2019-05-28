import logging
import os

import nose

import angr


l = logging.getLogger('test_reachingdefinitions')


TESTS_LOCATION = str(os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', 'binaries', 'tests'
))


def run_reaching_definition_analysis(project, func, result_path):
    tmp_kb = angr.KnowledgeBase(project)
    rd = project.analyses.ReachingDefinitions(func, init_func=True, kb=tmp_kb, observe_all=True)

    result = "%s\n" % rd.observed_results

    with open(result_path, 'r') as result_file:
        expected_result = result_file.read()

    nose.tools.assert_equals(result, expected_result)


def test_reaching_definition_analysis():
    def _binary_path(binary_name):
        return os.path.join(TESTS_LOCATION, 'x86_64', binary_name)
    def _result_path(binary_name):
        return 'tests/reachingdefinitions_results/x86_64/' + binary_name + '.txt'

    binaries_and_results = list(map(
        lambda binary: (_binary_path(binary), _result_path(binary)),
        ['all', 'fauxware', 'loop']
    ))

    for binary, result_path in binaries_and_results:
        project = angr.Project(binary, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()

        yield run_reaching_definition_analysis, project, cfg.kb.functions['main'], result_path


def main():
    test_functions = list(filter(
        lambda f: f[0].startswith('test_') and hasattr(f[1], '__call__'),
        globals().items()
    ))

    for func_name, func in test_functions:
        print(func_name)
        for testfunc_and_args in func():
            testfunc, args = testfunc_and_args[0], testfunc_and_args[1:]
            testfunc(*args)


if __name__ == '__main__':
    l.setLevel(logging.DEBUG)
    logging.getLogger('angr.analyses.reaching_definitions').setLevel(logging.DEBUG)

    main()
