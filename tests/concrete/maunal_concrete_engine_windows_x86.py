#gdbserver 127.0.0.1:9999 /home/degrigis/Projects/Symbion/angr_tests/MalwareTest/dummy_malware
import angr
import claripy
import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
import os
import nose
import ipdb

binary_x86 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..','..', '..', 'binaries','tests','x86','windows','simple_crackme_x86.exe'))

GDB_SERVER_IP = '192.168.57.3'
#GDB_SERVER_IP = '192.168.56.101'
#GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999

BEFORE_STRCMP_X86 = 0x40155B
WIN_BLOCK_X86 = 0x401564
END_X86 = 0x4015F2

avatar_gdb = None


def setup_x86():
    print("Configure a windows machine with a static IP  %s. "
          "Check windows firewall configurations to be sure that the connections to %s:%s are not blocked\n"
          "Install gdbserver on the machine, b"
          "e careful the architecture (x86 or x64) of gdbserver should be the same as the debugged binary.\n"
          "Currently using MinGW for 32 bit gdbserver and Cygwin for 64 bit gdbserver"% (GDB_SERVER_IP,GDB_SERVER_IP,GDB_SERVER_PORT))
    print("On windows machine execute gdbserver %s:%s path/to/simple_crackme.exe" % (GDB_SERVER_IP,GDB_SERVER_PORT))
    #raw_input("Press enter when gdbserver has been executed")


def teardown():
    global avatar_gdb
    avatar_gdb.exit()
    print("--------------\n")


@nose.with_setup(setup_x86,teardown)
def test_concrete_engine_windows_x86_no_simprocedures():
    global avatar_gdb
    print("test_concrete_engine_windows_x86_no_simprocedures")
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86, concrete_target=avatar_gdb,use_sim_procedures=False)
    entry_state = p.factory.entry_state()
    solv_concrete_engine_windows_x86(p,entry_state)


@nose.with_setup(setup_x86, teardown)
def test_concrete_engine_windows_x86_simprocedures():
    global avatar_gdb
    print("test_concrete_engine_windows_x86_simprocedures")
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=True)
    entry_state = p.factory.entry_state()
    solv_concrete_engine_windows_x86(p, entry_state)

@nose.with_setup(setup_x86, teardown)
def test_concrete_engine_windows_x86_unicorn_no_simprocedures():
    global avatar_gdb
    print("test_concrete_engine_windows_x86_unicorn_no_simprocedures")
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=False)
    entry_state = p.factory.entry_state(add_options = angr.options.unicorn)
    solv_concrete_engine_windows_x86(p, entry_state)


@nose.with_setup(setup_x86, teardown)
def test_concrete_engine_windows_x86_unicorn_simprocedures():
    global avatar_gdb
    print("test_concrete_engine_windows_x86_unicorn_simprocedures")
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=True)
    entry_state = p.factory.entry_state(add_options = angr.options.unicorn)
    solv_concrete_engine_windows_x86(p, entry_state)

def solv_concrete_engine_windows_x86(p,entry_state):
    simgr = p.factory.simgr(entry_state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[BEFORE_STRCMP_X86], concretize=[]))
    exploration = simgr.run()
    state = exploration.found[0]
    print("After concrete execution")

    pwd = claripy.BVS('pwd', 8 * 8)
    addr = state.regs.ebp - 0x15
    state.memory.store(addr, pwd)

    simgr = p.factory.simulation_manager(state)
    win_exploration = simgr.explore(find=WIN_BLOCK_X86)
    win_state = win_exploration.found[0]
    value_1 = win_state.se.eval(pwd, cast_to=str)
    print("After simultated execution")
    print("Solution is \"%s\"" % (value_1))
    nose.tools.assert_true(value_1 == "password")

    simgr = p.factory.simgr(win_state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[END_X86], concretize=[(addr, pwd)]))
    simgr.run()
    print("Finished")
    avatar_gdb.exit()


