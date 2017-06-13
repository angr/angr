import angr
import resource
import time

import os


b = angr.Project(os.path.join(
    os.path.dirname(__file__),
    "../../binaries-private/cgc_scored_event_2/cgc/0b32aa01_01"
))

start = time.time()
#s = b.factory.blank_state(add_options={"COMPOSITE_SOLVER"})
s = b.factory.blank_state(add_options={"COMPOSITE_SOLVER"}, remove_options={"LAZY_SOLVES"})
pg = b.factory.path_group(s)
angr.path_group.l.setLevel("DEBUG")
pg.step(300)
end = time.time()
print "MB:", resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024
print "time:", end-start
#assert len(pg.active) == 1538
#assert len(pg.deadended) == 27
