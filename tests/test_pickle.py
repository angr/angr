from claripy import BVS
from angr.storage import SimFile
import pickle
import shutil
import nose
import angr
import gc
import os

tests_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def load_pickles():
    # This is the working case
    f = open("pickletest_good", 'rb')
    print(pickle.load(f))
    f.close()

    # This will not work
    f = open("pickletest_bad", 'rb')
    print(pickle.load(f))
    f.close()

def make_pickles():
    p = angr.Project(os.path.join(tests_location, 'i386', 'fauxware'))

    fs = {
        '/dev/stdin': SimFile('/dev/stdin'),
        '/dev/stdout': SimFile('/dev/stdout'),
        '/dev/stderr': SimFile('/dev/stderr'),
        #'/dev/urandom': SimFile('/dev/urandom', 0),
    }

    MEM_SIZE = 1024
    mem_bvv = {}
    for f in fs:
        mem = BVS(f, MEM_SIZE * 8)
        mem_bvv[f] = mem
        # debug_wait()

    f = open("pickletest_good", "wb")
    #fname = f.name
    pickle.dump(mem_bvv, f, -1)
    f.close()

    # If you do not have a state you cannot write
    entry_state = p.factory.entry_state(fs=fs) #pylint:disable=unused-variable
    for f in fs:
        mem = mem_bvv[f]
        fs[f].write(0, mem, MEM_SIZE)

    f = open("pickletest_bad", "wb")
    #fname = f.name
    pickle.dump(mem_bvv, f, -1)
    f.close()
    #print "Test case generated run '%s <something>' to execute the test" % sys.argv[0]

def setup():
    pass

def teardown():
    # pylint: disable=bare-except
    try:
        shutil.rmtree('pickletest')
    except:
        pass
    try:
        shutil.rmtree('pickletest2')
    except:
        pass
    try:
        os.remove('pickletest_good')
    except:
        pass
    try:
        os.remove('pickletest_bad')
    except:
        pass

@nose.with_setup(setup, teardown)
def test_pickling():
    make_pickles()
    load_pickles()
    gc.collect()
    load_pickles()


def test_project_pickling():

    # AnalysesHub should not be pickled together with the project itself
    p = angr.Project(os.path.join(tests_location, 'i386', 'fauxware'))

    # make a copy of the active_preset so that we do not touch the global preset object. this is only for writing this
    # test case.
    p.analyses._active_preset = pickle.loads(pickle.dumps(p.analyses._active_preset, -1))
    assert len(p.analyses._active_preset._default_plugins) > 0
    p.analyses._active_preset = p.analyses._active_preset
    p.analyses._active_preset._default_plugins = {}
    assert len(p.analyses._active_preset._default_plugins) == 0

    s = pickle.dumps(p, -1)

    p1 = pickle.loads(s)
    assert len(p1.analyses._active_preset._default_plugins) > 0


if __name__ == '__main__':
    test_pickling()
    test_project_pickling()
