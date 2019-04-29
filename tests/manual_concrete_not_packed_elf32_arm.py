import angr
import avatar2
import claripy
import nose
import os

from angr_targets import AvatarGDBConcreteTarget

GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999


BINARY_DECISION_ADDRESS = 0x00010478
DROP_STAGE2_V1 = 0x104C4
DROP_STAGE2_V2 = 0x104E0
VENV_DETECTED = 0x10484
FAKE_CC = 0x104A4
BINARY_EXECUTION_END = 0x104E8


binary_arm = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          os.path.join('..', '..', 'binaries', 'tests', 'armhf', 'not_packed_elf32'))

gdbserver_proc = None
avatar_gdb = None

'''
def setup_armhf():
    #print("On an ARM machine execute gdbserver %s:%s path/to/simple_crackme" % (GDB_SERVER_IP, GDB_SERVER_PORT))
    #input("Press enter when gdbserver has been executed")
'''

def teardown():
    global avatar_gdb
    if avatar_gdb:
        avatar_gdb.exit()
    if gdbserver_proc is not None:
        gdbserver_proc.kill()


def test_concrete_engine_linux_arm_no_unicorn_simprocedures():
    #print("test_concrete_engine_linux_x86_unicorn_simprocedures")
    global avatar_gdb
    # pylint: disable=no-member
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.ARM, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_arm, concrete_target=avatar_gdb, use_sim_procedures=True)


    entry_state = p.factory.entry_state()
    solv_concrete_engine_linux_arm(p, entry_state)


def execute_concretly(p, state, address, concretize):
    simgr = p.factory.simgr(state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[address], concretize=concretize))
    exploration = simgr.run()
    return exploration.stashes['found'][0]


def solv_concrete_engine_linux_arm(p, entry_state):
    new_concrete_state = execute_concretly(p, entry_state, BINARY_DECISION_ADDRESS, [])

    arg0 = claripy.BVS('arg0', 5 * 32)
    symbolic_buffer_address = new_concrete_state.regs.r3
    new_concrete_state.memory.store(symbolic_buffer_address, arg0)
    simgr = p.factory.simgr(new_concrete_state)

    #print("Symbolically executing BINARY to find dropping of second stage [ address:  " + hex(DROP_STAGE2_V1) + " ]")
    exploration = simgr.explore(find=DROP_STAGE2_V2, avoid=[DROP_STAGE2_V1, VENV_DETECTED, FAKE_CC])

    if not exploration.stashes['found'] and exploration.errored and type(exploration.errored[0].error) is angr.errors.SimIRSBNoDecodeError:
        raise nose.SkipTest()

    new_symbolic_state = exploration.stashes['found'][0]

    #print("Executing BINARY concretely with solution found until the end " + hex(BINARY_EXECUTION_END))
    execute_concretly(p, new_symbolic_state, BINARY_EXECUTION_END, [(symbolic_buffer_address, arg0)])

    #print("BINARY execution ends, the configuration to reach your BB is: " + hex(binary_configuration))



test_concrete_engine_linux_arm_no_unicorn_simprocedures()
teardown()
