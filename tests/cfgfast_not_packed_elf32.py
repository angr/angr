import os
import nose
import subprocess

import avatar2 as avatar2

import angr
import angrutils



from angr_targets import AvatarGDBConcreteTarget



GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999


BINARY_OEP = 0x804874F
BINARY_DECISION_ADDRESS = 0x8048879 

DROP_STAGE2_V1 = 0x8048901
DROP_STAGE2_V2 = 0x8048936

VENV_DETECTED = 0x8048948
FAKE_CC = 0x8048962


BINARY_EXECUTION_END = 0x8048992

binary_x86 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          os.path.join('..','..', 'binaries','tests','i386','not_packed_elf32'))


p = angr.Project(binary_x86, use_sim_procedures=True)
entry_state = p.factory.entry_state()
cfg = p.analyses.CFGFast(regions=[(BINARY_OEP, BINARY_EXECUTION_END)], base_state=entry_state)
print("It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))
angrutils.plot_cfg(cfg, "/home/degrigis/Desktop/malware_graph", asminst=True, remove_imports=True, remove_path_terminator=True)

