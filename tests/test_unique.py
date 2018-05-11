import os

import angr
import nose

location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

archs = ['x86_64']

find = {
    'x86_64': {
        'veritesting_a': 0x40066a
    }
}

def run_unique(arch, binary):
    proj = angr.Project(os.path.join(os.path.join(location, arch), binary),
                        auto_load_libs=False)
    simgr = proj.factory.simgr()
    technique = angr.exploration_techniques.UniqueSearch()
    simgr.use_technique(technique)

    def found(simgr):
        return simgr.active[0].addr == find[arch][binary]
    simgr.run(until=found)
    nose.tools.assert_equal(simgr.active[0].addr, find[arch][binary])

def test_unique():
    for arch in find:
        for binary in find[arch]:
            yield run_unique, arch, binary

if __name__ == "__main__":
    for test_func, arch, binary in test_unique():
        test_func(arch, binary)
