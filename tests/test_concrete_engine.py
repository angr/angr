#gdbserver 127.0.0.1:9999 /home/degrigis/Projects/Symbion/angr_tests/MalwareTest/dummy_malware
import angr
import claripy
import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
import os
import subprocess
import ipdb

BINARY = "/home/degrigis/Projects/Symbion/angr-dev/binaries/tests/x86_64/fauxware"
GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999

AFTER_READS = 0x4007A4
AUTH_OK = 0x4007BD
END = 0x4007D3

def setup():
    print("gdbserver %s:%s %s" % (GDB_SERVER_IP, GDB_SERVER_PORT,BINARY))
    subprocess.Popen("gdbserver %s:%s %s " % (GDB_SERVER_IP, GDB_SERVER_PORT, BINARY), stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, shell=True)

def test_concrete_engine():

    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)

    p = angr.Project(BINARY, load_options={'auto_load_libs': True}, concrete_target=avatar_gdb)
    simgr = p.factory.simgr(p.factory.entry_state())
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[AFTER_READS], concretize=[]))
    exploration = simgr.run()
    state = exploration.found[0]

    pwd = claripy.BVS('pwd', 8 * 12)
    state.memory.store(state.regs.rbp - 0x20, pwd)

    simgr = p.factory.simgr(state)

    exploration = simgr.explore(find=AUTH_OK)
    new_state = exploration.stashes['found'][0]

    simgr = p.factory.simgr(new_state)

    simgr.use_technique(angr.exploration_techniques.Symbion(find=[END], concretize=[(new_state.regs.rbp - 0x20, pwd)]))
    exploration = simgr.run()


setup()
test_concrete_engine()