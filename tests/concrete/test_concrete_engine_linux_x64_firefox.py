#gdbserver 127.0.0.1:9999 /home/degrigis/Projects/Symbion/angr_tests/MalwareTest/dummy_malware
import angr
import claripy
import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
import os
import subprocess
import nose
binary_x64 = "/home/r0rshark/mozilla-central/obj-x86_64-pc-linux-gnu/dist/bin/firefox"
GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 1234
CHARACTER_PARSING = 0x7f0fcf7d9bf5 #Breakpoint /home/r0rshark/mozilla-central/parser/html/nsHtml5Tokenizer.cpp:528
TAG_OPEN = 0x7f0fcf7d1f80          # / home / r0rshark / mozilla - central / parser / html / nsHtml5Tokenizer.cpp:569.

avatar_gdb =  None


def setup_x64():
    print("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary_x64))
    subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary_x64),stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, shell=True)


def teardown():
    global avatar_gdb
    avatar_gdb.exit()
    import time
    time.sleep(2)
    print("---------------------------\n")

    
# -------------------------------- X64 tests ----------------------------------

@nose.with_setup(setup_x64,teardown)
def test_concrete_engine_linux_x64_no_simprocedures():
    print("test_concrete_engine_linux_x64_no_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x64 ,load_options={'auto_load_libs': True},concrete_target=avatar_gdb, use_sim_procedures=False)
    entry_state = p.factory.entry_state()
    solv_concrete_engine_linux_x64(p,entry_state)




@nose.with_setup(setup_x64, teardown)
def test_concrete_engine_linux_x64_simprocedures():
    print("test_concrete_engine_linux_x64_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP ,GDB_SERVER_PORT)
    p = angr.Project(binary_x64 ,load_options={'auto_load_libs': True},concrete_target=avatar_gdb, use_sim_procedures=True)
    entry_state = p.factory.entry_state()
    solv_concrete_engine_linux_x64(p, entry_state)



def solv_concrete_engine_linux_x64(p,entry_state):
    simgr = p.factory.simgr(entry_state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x7f0fcf7d9bf5], concretize = []))
    exploration = simgr.run()
    state = exploration.found[0]
    print("After concrete execution")
    pwd = claripy.BVS('pwd', 8 * 2)
    sym_addr = state.regs.rsi + state.regs.rax*2
    state.memory.store(sym_addr, pwd)

    simgr = p.factory.simulation_manager(state)

    exploration = simgr.explore(find=0x7f1a97303e03)
    state = exploration.found[0]
    value_1 = state.se.eval(pwd, cast_to=str)
    print("solution %s" % (value_1))





test_concrete_engine_linux_x64_simprocedures()
teardown()

