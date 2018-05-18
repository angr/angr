#gdbserver 127.0.0.1:9999 /home/degrigis/Projects/Symbion/angr_tests/MalwareTest/dummy_malware
import angr
import claripy
import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
import os
import subprocess


GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999


AFTER_AUTH_LOGIN = 0x4007AB
LOGIN_SUCCESS = 0x4007BD
LOGIN_REJECTED = 0x4007C9
END_OF_PROGRAM = 0x4007D3
USELESS_OPEN = 0x400699

binary_x86 = "/home/degrigis/Projects/Symbion/angr-dev/binaries/tests/x86_64/fauxware"


avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)

p = angr.Project(binary_x86, load_options={'auto_load_libs': True}, concrete_target=avatar_gdb)

entry_state = p.factory.entry_state()


import ipdb
ipdb.set_trace()