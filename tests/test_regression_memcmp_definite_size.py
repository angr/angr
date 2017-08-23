import os

import angr
import simuvex
import claripy as cp
import logging

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def regression_test_memcmp_strlen_simprocedure_interaction():
    logging.getLogger('angr.manager').setLevel(logging.DEBUG)

    bin_path = os.path.join(test_location, 'i386/cpp_regression_test_ch25')
    p = angr.Project(bin_path)
    argv1 = cp.Concat(*[cp.BVS('argv%d' % i, 8) for i in range(48)])

    state = p.factory.full_init_state(args=[bin_path, argv1],
            add_options=simuvex.o.unicorn,
            remove_options={simuvex.o.LAZY_SOLVES})

    sm = p.factory.simgr(state)
    x = sm.explore(find=0x8048b9b, num_find=3)

    print x
    for s in x.found:
        solution = s.state.se.eval_one(argv1, cast_to=str)
        print solution

if __name__ == '__main__':
    regression_test_memcmp_strlen_simprocedure_interaction()
