#gdbserver 127.0.0.1:9999 /home/degrigis/Projects/Symbion/angr_tests/MalwareTest/dummy_malware
import angr
import claripy
import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
import os
import subprocess
import nose
binary_x64 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..','..', '..', 'binaries','tests','x86_64','fauxware'))
binary_x86 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..','..','binaries','tests','i386','fauxware'))
binary_checkbyte_x86 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..','..','binaries','tests','i386','checkbyte'))
GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999
AFTER_USERNAME_PRINT_X64 = 0x40073E
AFTER_PWD_READ_X64 = 0x4007A4
WIN_X64 = 0x4007BD
AVOID_FILE_OPEN_X64 = 0x400699
END_X64 = 0x4007D3

AFTER_USERNAME_PRINT_X86 = 0x8048629
AFTER_PWD_READ_X86 = 0x80486B2
WIN_X86 = 0x80486CA
AVOID_FILE_OPEN_X86 = 0x8048564
END_X86 = 0x80486E8
import logging
#logging.getLogger().setLevel(logging.DEBUG)

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

    

@nose.with_setup(setup_x64,teardown)
def test_concrete_engine_linux_x64_no_simprocedures():
    print("test_concrete_engine_linux_x64_no_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x64 ,concrete_target=avatar_gdb, use_sim_procedures=False)
    entry_state = p.factory.entry_state()
    solv_concrete_engine_linux_x64(p,entry_state)




@nose.with_setup(setup_x64, teardown)
def test_concrete_engine_linux_x64_simprocedures():
    print("test_concrete_engine_linux_x64_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP ,GDB_SERVER_PORT)
    p = angr.Project(binary_x64 ,concrete_target=avatar_gdb, use_sim_procedures=True)
    entry_state = p.factory.entry_state()
    solv_concrete_engine_linux_x64(p, entry_state)

@nose.with_setup(setup_x64,teardown)
def test_concrete_engine_linux_x64_unicorn_no_simprocedures():
    print("test_concrete_engine_linux_x64_unicorn_no_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x64 , concrete_target=avatar_gdb, use_sim_procedures=False)
    entry_state = p.factory.entry_state(add_options = angr.options.unicorn)
    solv_concrete_engine_linux_x64(p,entry_state)

@nose.with_setup(setup_x64,teardown)
def test_concrete_engine_linux_x64_unicorn_simprocedures():
    print("test_concrete_engine_linux_x64_unicorn_simprocedures")
    global avatar_gdb
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x64, concrete_target=avatar_gdb, use_sim_procedures=True)
    entry_state = p.factory.entry_state(add_options=angr.options.unicorn)
    solv_concrete_engine_linux_x64(p, entry_state)

def solv_concrete_engine_linux_x64(p,entry_state):
    simgr = p.factory.simgr(entry_state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[AFTER_USERNAME_PRINT_X64], concretize = []))
    exploration = simgr.run()
    state = exploration.found[0]
    print("After concrete execution")

    simgr = p.factory.simulation_manager(state)
    pwd = claripy.BVS('pwd', 8 * 8)

    exploration = simgr.explore(find=AFTER_PWD_READ_X64)
    state = exploration.found[0]
    sym_addr = state.regs.rbp - 0x20
    state.memory.store(sym_addr, pwd)
    print("After symbolic execution")

    simgr = p.factory.simulation_manager(state)

    win_exploration = simgr.explore(find=WIN_X64, avoid=AVOID_FILE_OPEN_X64)
    try:
        win_state = win_exploration.found[0]
        value_1 = win_state.se.eval(pwd,cast_to=str)
        print("solution %s"%(value_1))
        nose.tools.assert_true(value_1 == "SOSNEAKY")
        print("Executed until WIN")

    except IndexError:
        print(win_exploration)
        for succ in win_exploration.all_successors:
            print(succ)
        raise Exception("No state found")

#setup_x64()
#test_concrete_engine_linux_x64_simprocedures()


