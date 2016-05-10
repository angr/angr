from claripy import BVS
from simuvex import SimFile
import pickle
import nose
import angr
import ana
import gc

def load_pickles():
    # This is the working case
    f = open("/tmp/pickletest_good", 'r')
    print pickle.load(f)
    f.close()

    # This will not work
    f = open("/tmp/pickletest_bad", 'r')
    print pickle.load(f)
    f.close()

def make_pickles():
    p = angr.Project("/bin/bash")

    fs = {
        '/dev/stdin': SimFile('/dev/stdin', 0),
        '/dev/stdout': SimFile('/dev/stdout', 0),
        '/dev/stderr': SimFile('/dev/stderr', 0),
        #'/dev/urandom': SimFile('/dev/urandom', 0),
    }

    MEM_SIZE = 1024
    mem_bvv = {}
    for f in fs:
        mem = BVS(f, MEM_SIZE * 8)
        mem_bvv[f] = mem
        # debug_wait()

    f = open("/tmp/pickletest_good", "w")
    #fname = f.name
    pickle.dump(mem_bvv, f)
    f.close()

    # If you do not have a state you cannot write
    entry_state = p.factory.entry_state(fs=fs) #pylint:disable=unused-variable
    for f in fs:
        mem = mem_bvv[f]
        fs[f].write(mem, MEM_SIZE)
        fs[f].seek(0)

    f = open("/tmp/pickletest_bad", "w")
    #fname = f.name
    pickle.dump(mem_bvv, f)
    f.close()
    #print "Test case generated run '%s <something>' to execute the test" % sys.argv[0]

def test_pickling():
    # set up ANA and make the pickles
    ana.set_dl(ana.DirDataLayer('/tmp/pickletest'))
    make_pickles()

    # make sure the pickles work in the same "session"
    load_pickles()

    # reset ANA, and load the pickles
    ana.set_dl(ana.DirDataLayer('/tmp/pickletest'))
    gc.collect()
    load_pickles()

    # purposefully set the wrong directory to make sure this excepts out
    ana.set_dl(ana.DirDataLayer('/tmp/pickletest2'))
    gc.collect()
    #load_pickles()
    nose.tools.assert_raises(Exception, load_pickles)

if __name__ == '__main__':
    test_pickling()
