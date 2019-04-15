import angr
import avatar2
import claripy
import nose
import os
import subprocess

from angr_targets import AvatarGDBConcreteTarget

GDB_SERVER_IP = '192.168.60.3'
GDB_SERVER_PORT = 9999


BINARY_DECISION_ADDRESS = 0x0001045C

binary_arm = "/home/degrigis/Desktop/prova_arm"


gdbserver_proc = None
avatar_gdb = None



def teardown():
    global avatar_gdb
    if avatar_gdb:
        avatar_gdb.exit()
    if gdbserver_proc is not None:
        gdbserver_proc.kill()


def test_concrete_engine_linux_arm_no_unicorn_simprocedures():
    print("test_concrete_engine_linux_x86_unicorn_simprocedures")
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
    import IPython
    IPython.embed()

test_concrete_engine_linux_arm_no_unicorn_simprocedures()
teardown()