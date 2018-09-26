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

def setup_x86():
    print("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary_x86))
    subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary_x86),stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, shell=True)


def teardown():
    global avatar_gdb
    avatar_gdb.exit()
    import time
    time.sleep(2)
    print("---------------------------\n")

@nose.with_setup(setup_x86, teardown)
def test_concrete_engine_linux_x86_simprocedures():
    print("test_concrete_engine_linux_x86_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP ,GDB_SERVER_PORT)
    p = angr.Project(binary_x86 ,concrete_target=avatar_gdb, use_sim_procedures=True)
    entry_state = p.factory.entry_state()
    #cfg = p.analyses.CFGAccurate(context_sensitivity_level=1, fail_fast=True)
    #import sys; sys.exit()
    #cfg = p.analyses.CFGFast()
    #print(dir(cfg.kb))
    #print(cfg.kb.functions())

    solv_concrete_engine_linux_x86(p, entry_state)

@nose.with_setup(setup_x86,teardown)
def test_concrete_engine_linux_x86_no_simprocedures():
    print("test_concrete_engine_linux_x86_no_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86, concrete_target=avatar_gdb, support_selfmodifying_code=True, use_sim_procedures=False)
    entry_state = p.factory.entry_state()
    solv_concrete_engine_linux_x86(p, entry_state)



@nose.with_setup(setup_x86,teardown)
def test_concrete_engine_linux_x86_unicorn_simprocedures():
    print("test_concrete_engine_linux_x86_unicorn_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=True)
    entry_state = p.factory.entry_state(add_options=angr.options.unicorn)
    solv_concrete_engine_linux_x86(p, entry_state)

@nose.with_setup(setup_x86,teardown)
def test_concrete_engine_linux_x86_unicorn_no_simprocedures():
    print("test_concrete_engine_linux_x86_unicorn_no_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86 ,load_options={"auto_load_libs":False}, concrete_target=avatar_gdb, use_sim_procedures=False)
    entry_state = p.factory.entry_state(add_options = angr.options.unicorn)
    solv_concrete_engine_linux_x86(p,entry_state)


def execute_concretly(p,state,address,concretize):
    simgr = p.factory.simgr(state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[address], concretize = concretize))
    exploration = simgr.run()
    return exploration.stashes['found'][0]

def solv_concrete_engine_linux_x86(p,entry_state):
    print "[1]Executing binary concretely until address: " + hex(BINARY_DECISION_ADDRESS)
    new_concrete_state = execute_concretly(p, entry_state, BINARY_DECISION_ADDRESS,[])
    cfg = p.analyses.CFGFast(regions=[(BINARY_OEP, BINARY_EXECUTION_END)], base_state=new_concrete_state )
    print "It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges()))
    angrutils.plot_cfg(cfg, "/home/degrigis/Desktop/not_packed_elf32", asminst=True, remove_imports=True, remove_path_terminator=True)


setup_x86()
test_concrete_engine_linux_x86_no_simprocedures()
teardown()

