#gdbserver 127.0.0.1:9999 /home/degrigis/Projects/Symbion/angr_tests/MalwareTest/dummy_malware
import angr
import claripy
import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
import os
import nose
import ipdb
binary_x64 = "/home/r0rshark/Documents/SharedFolder/Winrar_patched.exe"


#GDB_SERVER_IP = '192.168.56.101'
GDB_SERVER_IP = '127.0.0.1'
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



CALL_CHECK_REGISTRATION = 0x1400DB6B5
CHECK_REGISTRATION = 0x1400A10C1
REMEMBER_MESSAGE = 0x1400A1401
GET_TICKCOUNT = 0x1400A126A
OUTER_FUNC_ADDRESS = 0x01400DB6BA

def solv_concrete_engine_windows_x64(p,entry_state):
    simgr = p.factory.simgr(entry_state)

    '''
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[CALL_CHECK_REGISTRATION], concretize=[]))

    exploration = simgr.run()
    state = exploration.found[0]
    print("After concrete execution")
    simgr = p.factory.simulation_manager(state)
    win_exploration = simgr.explore(find=0x1400A10F6, avoid=0x1400A1447)
    win_state = win_exploration.found[0]
    print("success %s"%(win_state))

    '''
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x1400A10ED], concretize=[]))
    exploration = simgr.run()
    state = exploration.found[0]
    print("After concrete execution")
    
    dword_140146E04 = claripy.BVS('dword_140146E04', 8 * 4)
    dword_140146E04_addr = 0x140146E04
    state.memory.store(dword_140146E04_addr, dword_140146E04)

    byte_14013D220 = claripy.BVS('byte_14013D220', 8 * 1)
    byte_14013D220_addr = 0x14013D220
    state.memory.store(byte_14013D220_addr, byte_14013D220)

    dword_1401748E4 = claripy.BVS('dword_1401748E4', 8 * 1) # registration_key
    dword_1401748E4_addr = 0x1401748E4
    state.memory.store(dword_1401748E4_addr, dword_1401748E4)

    dword_14013CEB0 = claripy.BVS('dword_14013CEB0', 8 * 4)
    dword_14013CEB0_addr = 0x14013CEB0
    state.memory.store(dword_14013CEB0_addr, dword_14013CEB0)



    dword_14013CEC8 = claripy.BVS('dword_14013CEC8', 8 * 4) # remshown_flag
    dword_14013CEC8_addr = 0x14013CEC8
    state.memory.store(dword_14013CEC8_addr, dword_14013CEC8)

    dword_14013CFCC = claripy.BVS('dword_14013CFCC', 8 * 4) # expremshown_flag
    dword_14013CFCC_addr = 0x14013CFCC
    state.memory.store(dword_14013CFCC_addr, dword_14013CFCC)


    dword_014013D0D0 = claripy.BVS('dword_014013D0D0', 8 * 1) #regremoveshown
    dword_014013D0D0_addr = 0x014013D0D0
    state.memory.store(dword_014013D0D0_addr, dword_014013D0D0)


    byte_14013D0D4 = claripy.BVS('byte_14013D0D4', 8 * 1)
    byte_14013D0D4_addr = 0x14013D0D4
    state.memory.store(byte_14013D0D4_addr, byte_14013D0D4)

    simgr = p.factory.simulation_manager(state)
    win_exploration = simgr.explore(find=OUTER_FUNC_ADDRESS,avoid=[REMEMBER_MESSAGE,GET_TICKCOUNT,0x1400A1447])
    win_state = win_exploration.found[0]
    value_1 = win_state.se.eval(dword_140146E04, cast_to=int)
    value_1_5 = win_state.se.eval(byte_14013D220, cast_to=int)
    value_2 = win_state.se.eval(dword_1401748E4, cast_to=int)
    value_3 = win_state.se.eval(dword_14013CEB0, cast_to=int)
    value_4 = win_state.se.eval(dword_14013CEC8, cast_to=int)
    value_5 = win_state.se.eval(dword_14013CFCC, cast_to=int)
    value_6 = win_state.se.eval(dword_014013D0D0, cast_to=int)
    value_7 = win_state.se.eval(byte_14013D0D4, cast_to=int)


    print("After simultated execution")
    print("Solution is \"%x,%x,%x,%x,%x,%x,%x,%x\"" % (value_1,value_1_5,value_2,value_3,value_4,value_5,value_6,value_7))
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[], concretize=[(dword_140146E04_addr,value_1),
                                                                                 (byte_14013D220,value_1_5),
                                                                                 (dword_1401748E4_addr,value_2),
                                                                                 (dword_14013CEB0_addr,value_3),
                                                                                 (dword_14013CEC8_addr,value_4),
                                                                                 (dword_14013CFCC_addr,value_5),
                                                                                 (dword_014013D0D0, value_6),
                                                                                 (byte_14013D0D4, value_7)

                                                                                 ]))


    print("resumed execution")

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