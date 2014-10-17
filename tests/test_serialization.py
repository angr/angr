import pickle
import nose
import angr
import ana
import os

def save(binary, state):
    # reset the dl
    ana.set_dl(pickle_dir='/tmp/ana')

    p = angr.Project(binary)
    e = angr.surveyors.Explorer(p).run(10)
    pickle.dump(e.active[0].last_run, open(state, 'w'), -1)

def load(binary, state):
    # reset the dl
    ana.set_dl(pickle_dir='/tmp/ana')

    s = pickle.load(open(state))
    p = angr.Project(binary)
    e2 = angr.surveyors.Explorer(p, start=p.exit_to(0x400958, state=s.initial_state)).run(10)
    nose.tools.assert_equals(e2.active[0].last_run.addr, 0x40075c)

def test_surveyor_resume():
    binary = os.path.dirname(__file__) + "/blob/mips/fauxware"
    state = "/tmp/test_angr.p"

    save(binary, state)
    load(binary, state)

if __name__ == '__main__':
    test_surveyor_resume()
