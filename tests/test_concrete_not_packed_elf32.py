import angr
import claripy
import nose
import os
import subprocess

try:
    import avatar2
    from angr_targets import AvatarGDBConcreteTarget
except ImportError:
    raise nose.SkipTest()

GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999
BINARY_OEP = 0x804874F
BINARY_DECISION_ADDRESS = 0x8048879
DROP_STAGE2_V1 = 0x8048901
DROP_STAGE2_V2 = 0x8048936
VENV_DETECTED = 0x8048948
FAKE_CC = 0x8048962
BINARY_EXECUTION_END = 0x8048992

binary_x86 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          os.path.join('..', '..', 'binaries', 'tests', 'i386', 'not_packed_elf32'))


def setup_x86():
    global gdbserver_proc
    #print("gdbserver %s:%s '%s'" % (GDB_SERVER_IP, GDB_SERVER_PORT, binary_x86))
    gdbserver_proc = subprocess.Popen("gdbserver %s:%s '%s'" % (GDB_SERVER_IP, GDB_SERVER_PORT, binary_x86),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)


gdbserver_proc = None
avatar_gdb = None


def teardown():
    global avatar_gdb
    if avatar_gdb:
        avatar_gdb.exit()
    if gdbserver_proc is not None:
        gdbserver_proc.kill()


@nose.with_setup(setup_x86, teardown)
def test_concrete_engine_linux_x86_simprocedures():
    #print("test_concrete_engine_linux_x86_simprocedures")
    global avatar_gdb
    # pylint: disable=no-member
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=True)
    entry_state = p.factory.entry_state()
    solv_concrete_engine_linux_x86(p, entry_state)


@nose.with_setup(setup_x86, teardown)
def test_concrete_engine_linux_x86_no_simprocedures():
    #print("test_concrete_engine_linux_x86_no_simprocedures")
    global avatar_gdb
    # pylint: disable=no-member
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=False)
    entry_state = p.factory.entry_state()
    solv_concrete_engine_linux_x86(p, entry_state)


@nose.with_setup(setup_x86, teardown)
def test_concrete_engine_linux_x86_unicorn_simprocedures():
    #print("test_concrete_engine_linux_x86_unicorn_simprocedures")
    global avatar_gdb
    # pylint: disable=no-member
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=True)
    entry_state = p.factory.entry_state(add_options=angr.options.unicorn)
    solv_concrete_engine_linux_x86(p, entry_state)


@nose.with_setup(setup_x86, teardown)
def test_concrete_engine_linux_x86_unicorn_no_simprocedures():
    #print("test_concrete_engine_linux_x86_unicorn_no_simprocedures")
    global avatar_gdb
    # pylint: disable=no-member
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=False)
    entry_state = p.factory.entry_state(add_options=angr.options.unicorn)
    solv_concrete_engine_linux_x86(p, entry_state)


def execute_concretly(p, state, address, concretize):
    simgr = p.factory.simgr(state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[address], concretize=concretize))
    exploration = simgr.run()
    return exploration.stashes['found'][0]


def solv_concrete_engine_linux_x86(p, entry_state):
    new_concrete_state = execute_concretly(p, entry_state, BINARY_DECISION_ADDRESS, [])

    arg0 = claripy.BVS('arg0', 8*32)

    symbolic_buffer_address = new_concrete_state.regs.ebp-0xa0
    new_concrete_state.memory.store(symbolic_buffer_address, arg0)

    # symbolic exploration
    simgr = p.factory.simgr(new_concrete_state)
    #print("[2]Symbolically executing BINARY to find dropping of second stage [ address:  " + hex(DROP_STAGE2_V1) + " ]")
    exploration = simgr.explore(find=DROP_STAGE2_V1, avoid=[DROP_STAGE2_V2, VENV_DETECTED, FAKE_CC])
    if not exploration.stashes['found'] and exploration.errored and type(exploration.errored[0].error) is angr.errors.SimIRSBNoDecodeError:
        raise nose.SkipTest()
    new_symbolic_state = exploration.stashes['found'][0]

    binary_configuration = new_symbolic_state.solver.eval(arg0, cast_to=int)

    #print("[3]Executing BINARY concretely with solution found until the end " + hex(BINARY_EXECUTION_END))
    execute_concretly(p, new_symbolic_state, BINARY_EXECUTION_END, [(symbolic_buffer_address, arg0)])

    #print("[4]BINARY execution ends, the configuration to reach your BB is: " + hex(binary_configuration))

    correct_solution = 0xa000000f9ffffff000000000000000000000000000000000000000000000000
    nose.tools.assert_true(binary_configuration == correct_solution)

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            if hasattr(all_functions[f], 'setup'):
                all_functions[f].setup()
            try:
                all_functions[f]()
            finally:
                if hasattr(all_functions[f], 'teardown'):
                    all_functions[f].teardown()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
