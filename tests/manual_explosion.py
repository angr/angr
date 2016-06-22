import angr
import resource
import time
import simuvex
start = time.time()
b = angr.Project("/home/salls/Projects/angr/binaries-private/cgc_scored_event_2/cgc/0b32aa01_01")
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


