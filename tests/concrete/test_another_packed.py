
import angr
import avatar2 as avatar2
import claripy

from angr_targets import AvatarGDBConcreteTarget

MALWARE_PATH = "/home/degrigis/Projects/Symbion/angr-symbion-beta/binaries/tests/x86_64/packed_binary"

GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999

UNPACKING_STUB = 0x45b97f
UNPACKING_MALWARE = 0x85b853
MALWARE_OEP = 0x400b95
MALWARE_DECISION_ADDRESS = 0x400CD6
DROP_STAGE2_V1 = 0x400D6A
DROP_STAGE2_V2 = 0x400D99
VENV_DETECTED = 0x400DA5
FAKE_CC = 0x400DB9
MALWARE_EXECUTION_END = 0x400DE6

avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP ,GDB_SERVER_PORT)
p = angr.Project(MALWARE_PATH, load_options={'auto_load_libs': False}, concrete_target=avatar_gdb,
                 use_sim_procedures=True)


def execute_concretly(state, address, concretize):
    simgr = p.factory.simgr(state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[address], concretize=concretize))
    exploration = simgr.run()
    return exploration.stashes['found'][0]


print "[1]Executing malware concretely until address: " + hex(UNPACKING_STUB)

# until unpacking of stub
new_concrete_state = execute_concretly(p.factory.entry_state(), UNPACKING_STUB, [])

# now until stub instructions
for i in xrange(0, 4):
    new_concrete_state = execute_concretly(new_concrete_state, UNPACKING_MALWARE, [])

new_concrete_state = execute_concretly(new_concrete_state, MALWARE_DECISION_ADDRESS, [])

arg0 = claripy.BVS('arg0', 8 * 32)
symbolic_buffer_address = new_concrete_state.regs.rbp - 0xc0
new_concrete_state.memory.store(symbolic_buffer_address, arg0)

# symbolic exploration
simgr = p.factory.simgr(new_concrete_state)
print "[2]Symbolically executing malware to find dropping of second stage [ address:  " + hex(DROP_STAGE2_V2) + " ]"
exploration = simgr.explore(find=DROP_STAGE2_V2, avoid=[DROP_STAGE2_V1, VENV_DETECTED, FAKE_CC])
new_symbolic_state = exploration.stashes['found'][0]

print "[3]Executing malware concretely with solution found until the end " + hex(MALWARE_EXECUTION_END)
execute_concretly(new_symbolic_state, MALWARE_EXECUTION_END, [(symbolic_buffer_address, arg0)])

malware_configuration = hex(new_symbolic_state.se.eval(arg0, cast_to=int))

print "[4]Malware execution ends, the configuration to reach your BB is: " + malware_configuration

assert (malware_configuration == hex(0xa00000006000000f6ffffff0000000000000000000000000000000000000000))

avatar_gdb.exit()


