#gdbserver 127.0.0.1:9999 /home/degrigis/Projects/Symbion/angr_tests/MalwareTest/dummy_malware
import angr
import nose
import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
import os
import subprocess
import ipdb
binary = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries','tests','x86_64','fauxware'))


GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999
DROPPING_MALWARE_ADDRESS = 0x400734


def setup():
    print("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary))
    subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary),stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, shell=True)

def test_concrete_engine():
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP ,GDB_SERVER_PORT)

    p = angr.Project(binary ,load_options={'auto_load_libs': False, 'concrete_target': avatar_gdb})
    simgr = p.factory.simgr(p.factory.entry_state())
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[DROPPING_MALWARE_ADDRESS], concretize = []))
    exploration = simgr.run()
    ipdb.set_trace()

    new_state = exploration.found[0]
    username = new_state.mem[0x400915]


setup()
test_concrete_engine()