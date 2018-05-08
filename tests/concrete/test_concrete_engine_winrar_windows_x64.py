#gdbserver 127.0.0.1:9999 /home/degrigis/Projects/Symbion/angr_tests/MalwareTest/dummy_malware
import angr
import claripy
import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
import os
import nose
import ipdb
binary_x64 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..','..', '..', 'binaries','tests','x86_64','windows','simple_crackme_x64.exe'))


GDB_SERVER_IP = '192.168.56.101'
#GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999



avatar_gdb = None


def setup():
    print("Configure a windows machine with a static IP  %s. "
          "Check windows firewall configurations to be sure that the connections to %s:%s are not blocked\n"
          "Install gdbserver on the machine, be careful the architecture (x86 or x64) of gdbserver should be the same as the debugged binary.\n"
          "Currently using MinGW for 32 bit gdbserver and Cygwin for 64 bit gdbserver"% (GDB_SERVER_IP,GDB_SERVER_IP,GDB_SERVER_PORT))
    print("On windows machine execute gdbserver %s:%s path/to/simple_crackme.exe" % (GDB_SERVER_IP,GDB_SERVER_PORT))
    #raw_input("Press enter when gdbserver has been executed")


def teardown():
    global avatar_gdb
    avatar_gdb.exit()
    print("--------------\n")



@nose.with_setup(setup,teardown)
def test_concrete_engine_windows_x64_no_simprocedures():
    print("test_concrete_engine_windows_x64_no_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x64, load_options={'auto_load_libs': True}, concrete_target=avatar_gdb, use_sim_procedures=False)
    entry_state = p.factory.entry_state()
    solv_concrete_engine_windows_x64(p, entry_state)


@nose.with_setup(setup,teardown)
def test_concrete_engine_windows_x64_simprocedures():
    print("test_concrete_engine_windows_x64_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x64, load_options={'auto_load_libs': True}, concrete_target=avatar_gdb, use_sim_procedures=True)
    entry_state = p.factory.entry_state()
    solv_concrete_engine_windows_x64(p, entry_state)


@nose.with_setup(setup,teardown)
def test_concrete_engine_windows_x64_unicorn_no_simprocedures():
    print("test_concrete_engine_windows_x64_unicorn_no_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x64, load_options={'auto_load_libs': True}, concrete_target=avatar_gdb, use_sim_procedures=False)
    entry_state = p.factory.entry_state(add_options = angr.options.unicorn)
    solv_concrete_engine_windows_x64(p, entry_state)

@nose.with_setup(setup,teardown)
def test_concrete_engine_windows_x64_unicorn_simprocedures():
    print("test_concrete_engine_windows_x64_unicorn_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x64, load_options={'auto_load_libs': True}, concrete_target=avatar_gdb, use_sim_procedures=True)
    entry_state = p.factory.entry_state(add_options = angr.options.unicorn)
    solv_concrete_engine_windows_x64(p, entry_state)




CHECK_REGISTRATION = 0x1400A10C1
REMEMBER_MESSAGE = 0x1400A12D6
OUTER_FUNC_ADDRESS = 0x01400DB6BA

def solv_concrete_engine_windows_x64(p,entry_state):

    simgr = p.factory.simgr(entry_state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[CHECK_REGISTRATION], concretize=[]))
    exploration = simgr.run()
    state = exploration.found[0]
    print("After concrete execution")

    dword_140146E04 = claripy.BVS('dword_140146E04', 8 * 4)
    state.memory.store(0X140146E04, dword_140146E04)

    dword_1401748E4 = claripy.BVS('dword_1401748E4', 8 * 1) # registration_key
    state.memory.store(0X1401748E4, dword_1401748E4)

    dword_14013CEB0 = claripy.BVS('dword_14013CEB0', 8 * 4)
    state.memory.store(0x14013CEB0, dword_14013CEB0)

    dword_14013CEC8 = claripy.BVS('dword_14013CEC8', 8 * 4) # remshown_flag
    state.memory.store(0x14013CEC8, dword_14013CEC8)

    dword_14013CFCC = claripy.BVS('dword_14013CFCC', 8 * 4) # expremshown_flag
    state.memory.store(0x14013CFCC, dword_14013CFCC)

    simgr = p.factory.simulation_manager(state)
    win_exploration = simgr.explore(find=OUTER_FUNC_ADDRESS,avoid=REMEMBER_MESSAGE)
    win_state = win_exploration.found[0]
    value_1 = win_state.se.eval(dword_140146E04, cast_to=str)
    value_2 = win_state.se.eval(dword_1401748E4, cast_to=str)
    value_3 = win_state.se.eval(dword_14013CEB0, cast_to=str)
    value_4 = win_state.se.eval(dword_14013CEC8, cast_to=str)
    value_5 = win_state.se.eval(dword_14013CFCC, cast_to=str)

    print("After simultated execution")
    print("Solution is \"%s, %s, %s, %s,%s\"" % (value_1,value_2,value_3,value_4,value_5))
    '''
    nose.tools.assert_true(value_1 == "password")

    simgr = p.factory.simgr(win_state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[END_X64], concretize=[(win_state.regs.rbp-0x20, pwd)]))
    simgr.run()
    print("Finished")
    '''
setup()
test_concrete_engine_windows_x64_simprocedures()
teardown()

'''
@nose.with_setup(setup,teardown)
def test_concrete_engine_windows_x64_simprocedures():
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)

    p = angr.Project(binary_x64, concrete_target=avatar_gdb)
    simgr = p.factory.simgr(p.factory.entry_state())
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[BEFORE_STRCMP_X64], concretize=[]))
    exploration = simgr.run()
    state = exploration.found[0]
    print("After concrete execution")

    pwd = claripy.BVS('pwd', 8 * 8)
    addr = state.regs.rbp - 0x20
    state.memory.store(addr, pwd)

    simgr = p.factory.simulation_manager(state)
    win_exploration = simgr.explore(find=WIN_BLOCK_X64,avoid=0x4015D2)
    win_state = win_exploration.found[0]
    value_1 = win_state.se.eval(pwd, cast_to=str)
    print("After simultated execution")
    print("Solution is \"%s\"" % (value_1))
    nose.tools.assert_true(value_1 == "SOSNEAKY")

    simgr = p.factory.simgr(win_state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[END_X64], concretize=[(win_state.regs.rbp-0x20, pwd)]))
    simgr.run()
    print("Finished")
    avatar_gdb.exit()


def test_gdbtarget_windows_x86():
    setup()
    test_concrete_engine_windows_x86_simprocedures()

def test_gdbtarget_windows_x64():
    setup()
    test_concrete_engine_windows_x64_simprocedures()


test_gdbtarget_windows_x64()
'''