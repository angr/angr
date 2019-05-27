import angr
import avatar2
import claripy
import os

from angr_targets import AvatarGDBConcreteTarget


binary_x86 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          os.path.join('..', '..', 'binaries', 'tests', 'x86',
                                       'windows', 'not_packed_pe32.exe'))

GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999

STARTING_DECISION_ADDRESS = 0x401775
DROP_V1 = 0x401807
DROP_V2 = 0x401839
MALWARE_EXECUTION_END = 0x401879
FAKE_CC = 0x401861
VENV_DETECTED = 0x401847


avatar_gdb = None

'''
def setup_x86():
    print("Configure a windows machine with a static IP  %s. "
          "Check windows firewall configurations to be sure that the connections to %s:%s are not blocked\n"
          "Install gdbserver on the machine, b"
          "e careful the architecture (x86 or x64) of gdbserver should be the same as the debugged binary.\n"
          "Currently using Cygwin for 32 bit gdbserver and Cygwin for 64 bit gdbserver" % (GDB_SERVER_IP,
                                                                                           GDB_SERVER_IP,
                                                                                           GDB_SERVER_PORT))

    print("On windows machine execute gdbserver %s:%s path/to/simple_crackme.exe" % (GDB_SERVER_IP, GDB_SERVER_PORT))
    input("Press enter when gdbserver has been executed")
'''

def teardown():
    global avatar_gdb
    if avatar_gdb:
        avatar_gdb.exit()


def test_concrete_engine_windows_x86_no_simprocedures():
    global avatar_gdb
    try:
        # pylint: disable=no-member
        avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
        p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=False,
                         page_size=0x1000)
        entry_state = p.factory.entry_state()
        solv_concrete_engine_windows_x86(p, entry_state)
    except ValueError:
        #print("Failing executing test")
        pass


def test_concrete_engine_windows_x86_simprocedures():
    global avatar_gdb
    try:
        # pylint: disable=no-member
        avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
        p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=True,
                         page_size=0x1000)
        entry_state = p.factory.entry_state()
        solv_concrete_engine_windows_x86(p, entry_state)
    except ValueError:
        #print("Failing executing test")
        pass


def test_concrete_engine_windows_x86_unicorn_no_simprocedures():
    global avatar_gdb
    try:
        # pylint: disable=no-member
        avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
        p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=False,
                         page_size=0x1000)
        entry_state = p.factory.entry_state(add_options=angr.options.unicorn)
        solv_concrete_engine_windows_x86(p, entry_state)
    except ValueError:
        #print("Failing executing test")
        pass

def test_concrete_engine_windows_x86_unicorn_simprocedures():
    global avatar_gdb
    try:
        # pylint: disable=no-member
        avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
        p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=True,
                         page_size=0x1000)
        entry_state = p.factory.entry_state(add_options=angr.options.unicorn)
        solv_concrete_engine_windows_x86(p, entry_state)
    except ValueError:
        #print("Failing executing test")
        pass


def execute_concretly(p, state, address, concretize):
    simgr = p.factory.simgr(state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[address], concretize=concretize))
    exploration = simgr.run()
    return exploration.stashes['found'][0]


def solv_concrete_engine_windows_x86(p, entry_state):

    #print("[1]Executing malware concretely until address: " + hex(STARTING_DECISION_ADDRESS))
    new_concrete_state = execute_concretly(p, entry_state, STARTING_DECISION_ADDRESS, [])

    # declaring symbolic buffer
    arg0 = claripy.BVS('arg0', 8 * 32)
    symbolic_buffer_address = new_concrete_state.regs.esp + 0x18
    new_concrete_state.memory.store(new_concrete_state.solver.eval(symbolic_buffer_address), arg0)

    #print("[2]Symbolically executing malware to find dropping of second stage [ address:  " + hex(DROP_V1) + " ]")
    simgr = p.factory.simgr(new_concrete_state)
    exploration = simgr.explore(find=DROP_V1, avoid=[FAKE_CC, DROP_V2, VENV_DETECTED])
    new_symbolic_state = exploration.stashes['found'][0]

    #print("[3]Executing malware concretely with solution found until the end " + hex(MALWARE_EXECUTION_END))
    execute_concretly(p, new_symbolic_state, MALWARE_EXECUTION_END, [(symbolic_buffer_address, arg0)])

    #print("[4]Malware execution ends, the configuration value is: " + hex(
    #    new_symbolic_state.solver.eval(arg0, cast_to=int)))
