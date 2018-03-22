#gdbserver 127.0.0.1:9999 /home/degrigis/Projects/Symbion/angr_tests/MalwareTest/dummy_malware
import angr
import claripy
import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
import os
import subprocess
import ipdb
binary = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries','tests','x86_64','fauxware'))


GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999
AFTER_USERNAME_PRINT = 0x400739
AFTER_PWD_READ = 0x4007A4
WIN = 0x4007BD


def setup():
    print("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary))
    subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary),stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, shell=True)

def test_concrete_engine():
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP ,GDB_SERVER_PORT)

    p = angr.Project(binary ,load_options={'auto_load_libs': True, 'concrete_target': avatar_gdb})
    simgr = p.factory.simgr(p.factory.entry_state())
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[AFTER_USERNAME_PRINT], concretize = []))
    exploration = simgr.run()
    state = exploration.found[0]
    print("AFTER FIRST EXPLORATION")


    # explore_simulated
    simgr = p.factory.simulation_manager(state)
    pwd = claripy.BVS('pwd', 8 * 12)

    exploration = simgr.explore(find=AFTER_PWD_READ)
    state = exploration.found[0]
    state.memory.store(state.regs.rbp - 0x20, pwd)
    print("AFTER SECOND EXPLORATION")

    simgr = p.factory.simulation_manager(state)
    win_exploration = simgr.explore(find=WIN)
    win_state = win_exploration.found[0]
    value_1 = win_state.se.eval(pwd,cast_to=str)
    print("----------- %s"%(value_1))





setup()
test_concrete_engine()