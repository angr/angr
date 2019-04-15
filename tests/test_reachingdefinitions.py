
import os
import logging

import angr


l = logging.getLogger('test_reachingdefinitions')


test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                 '..', '..', 'binaries', 'tests'
                                 )
                    )


def run_reaching_definition_analysis(project, func, groundtruth):  # pylint:disable=unused-argument

    # Create a temporary KnowledgeBase instance
    tmp_kb = angr.KnowledgeBase(project)

    _ = project.analyses.ReachingDefinitions(func, kb=tmp_kb)


# def test_reaching_definition_analysis():
def disabled_reaching_definition_analysis():

    # FIXME: Rewrite test cases for ReachingDefinitionAnalysis

    binary_path = os.path.join(test_location, 'x86_64', 'all')
    project = angr.Project(binary_path, load_options={'auto_load_libs': False})
    cfg = project.analyses.CFG()

    groundtruth = {
        'main': {

        },
    }

    for func_name, truth in groundtruth.items():
        yield run_reaching_definition_analysis, project, cfg.kb.functions[func_name], truth


def main():
    g = globals()
    for func_name, func in g.items():
        if func_name.startswith('test_') and hasattr(func, '__call__'):
            print(func_name)
            for testfunc_and_args in func():
                testfunc, args = testfunc_and_args[0], testfunc_and_args[1:]
                testfunc(*args)


if __name__ == '__main__':
    l.setLevel(logging.DEBUG)
    logging.getLogger('angr.analyses.reaching_definitions').setLevel(logging.DEBUG)

    main()
