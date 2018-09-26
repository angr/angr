import subprocess
import os
#import nose

import avatar2 as avatar2

import angr
import angrutils
import claripy


from angr_targets import AvatarGDBConcreteTarget





binary_x64 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries', 'tests', 'x86_64', 'packed_elf64'))


GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999

UNPACKING_STUB = 0x45b97f
UNPACKING_BINARY = 0x85b853
BINARY_OEP = 0x400b95
BINARY_DECISION_ADDRESS = 0x400CD6 
DROP_STAGE2_V1 = 0x400D6A
DROP_STAGE2_V2 = 0x400D99
VENV_DETECTED = 0x400DA5
FAKE_CC = 0x400DB9
BINARY_EXECUTION_END = 0x400DE6


def setup_x64():
    print("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary_x64))
    subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary_x64),stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, shell=True)


def teardown():
    global avatar_gdb
    avatar_gdb.exit()
    import time
    time.sleep(1)


#@nose.with_setup(setup_x64,teardown)
def test_concrete_engine_linux_x64_no_simprocedures():
    print("test_concrete_engine_linux_x64_no_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x64 ,concrete_target=avatar_gdb, support_selfmodifying_code=True,  use_sim_procedures=False)
    entry_state = p.factory.entry_state()
    solv_concrete_engine_linux_x64(p,entry_state)


def test_concrete_engine_linux_x64_simprocedures():
    print("test_concrete_engine_linux_x64_no_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x64 ,concrete_target=avatar_gdb, support_selfmodifying_code=True, use_sim_procedures=True)
    entry_state = p.factory.entry_state()
    solv_concrete_engine_linux_x64(p,entry_state)


#@nose.with_setup(setup_x64,teardown)
def test_concrete_engine_linux_x64_unicorn_no_simprocedures():
    print("test_concrete_engine_linux_x64_unicorn_no_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x64, concrete_target=avatar_gdb, support_selfmodifying_code=True, use_sim_procedures=False)
    entry_state = p.factory.entry_state(add_options=angr.options.unicorn)
    solv_concrete_engine_linux_x64(p, entry_state)


def execute_concretly(project, state, address, concretize):
    simgr = project.factory.simgr(state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[address], concretize=concretize))
    exploration = simgr.run()
    return exploration.stashes['found'][0]


def solv_concrete_engine_linux_x64(p,entry_state):
    print "[1]Executing binary concretely until address: " + hex(UNPACKING_STUB)
    # until unpacking of stub
    new_concrete_state = execute_concretly(p, entry_state, UNPACKING_STUB, [])
    # now until stub instructions
    for i in xrange(0,4):
        new_concrete_state = execute_concretly(p, new_concrete_state, UNPACKING_BINARY, [])

    new_concrete_state = execute_concretly(p, new_concrete_state, BINARY_DECISION_ADDRESS, [])

    cfg = p.analyses.CFGFast(regions=[(0x400b95, 0x400DE6)], base_state=new_concrete_state)
    print "It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges()))
    angrutils.plot_cfg(cfg, "/home/degrigis/Desktop/packed_elf64", asminst=True, remove_imports=True, remove_path_terminator=True)


setup_x64()
test_concrete_engine_linux_x64_no_simprocedures()
teardown()