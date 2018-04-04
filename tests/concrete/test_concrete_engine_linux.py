#gdbserver 127.0.0.1:9999 /home/degrigis/Projects/Symbion/angr_tests/MalwareTest/dummy_malware
import angr
import claripy
import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
import os
import subprocess
import nose
binary = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..','..', '..', 'binaries','tests','x86_64','fauxware'))

GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999
AFTER_USERNAME_PRINT_X64 = 0x40073E
AFTER_PWD_READ_X64 = 0x4007A4
WIN_X64 = 0x4007BD


def setup():
    print("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary))
    subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary),stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, shell=True)

def test_concrete_engine_linux_x64():
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP ,GDB_SERVER_PORT)

    p = angr.Project(binary ,load_options={'auto_load_libs': True},concrete_target=avatar_gdb)
    simgr = p.factory.simgr(p.factory.entry_state())
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[AFTER_USERNAME_PRINT_X64], concretize = []))
    exploration = simgr.run()
    state = exploration.found[0]
    print("After concrete execution")

    #p = angr.Project(binary ,load_options={'auto_load_libs': True})

    # explore_simulated
    #simgr = p.factory.simulation_manager(p.factory.entry_state())
    simgr = p.factory.simulation_manager(state)
    pwd = claripy.BVS('pwd', 8 * 8)

    exploration = simgr.explore(find=AFTER_PWD_READ_X64)
    state = exploration.found[0]
    sym_addr = state.regs.rbp - 0x20
    state.memory.store(sym_addr, pwd)
    print("After symbolic execution")

    simgr = p.factory.simulation_manager(state)
    win_exploration = simgr.explore(find=WIN_X64)
    win_state = win_exploration.found[0]
    value_1 = win_state.se.eval(pwd,cast_to=str)
    print("solution %s"%(value_1))
    nose.tools.assert_true(value_1 == "SOSNEAKY")
    print("Executed until WIN")




'''
    To run this test execute echo "test\n\ntest\n\n"  | gdbserver 127.0.0.1:1234 path/to/fauxware
def manual_test_concrete_engine_linux_x64():
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP ,GDB_SERVER_PORT)

    p = angr.Project(binary ,load_options={'auto_load_libs': True},concrete_target=avatar_gdb)
    simgr = p.factory.simgr(p.factory.entry_state())
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[AFTER_PWD_READ], concretize = []))
    exploration = simgr.run()
    state = exploration.found[0]
    print("AFTER FIRST EXPLORATION")


    pwd = claripy.BVS('pwd', 8 * 12)
    state.memory.store(state.regs.rbp - 0x20, pwd)

    simgr = p.factory.simulation_manager(state)
    win_exploration = simgr.explore(find=WIN)
    win_state = win_exploration.found[0]
    value_1 = win_state.se.eval(pwd,cast_to=str)
    print("AFTER SIMULATED")
    print("Solution is  %s"%(value_1))

    simgr = p.factory.simulation_manager(win_state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[WIN], concretize=[(win_state.regs.rbp-0x20, pwd)]))
    simgr.run()
    print("Executed until WIN address %x"%(avatar_gdb.read_register("pc")))
'''

#setup()
