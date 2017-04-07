
import os

import nose

import angr

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                 '..', '..', 'binaries', 'tests'
                                 )
                    )

def smoketest():
    binary_path = os.path.join(test_location, 'x86_64', 'fauxware')

    project = angr.Project(binary_path, load_options={'auto_load_libs': False})

    cfg = project.analyses.CFG()

    authenticate = cfg.kb.functions['authenticate']

    vr = project.analyses.VariableRecovery(authenticate)

    import ipdb; ipdb.set_trace()


def main():
    smoketest()


if __name__ == '__main__':
    main()
