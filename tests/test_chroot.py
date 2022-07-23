import angr
from angr.state_plugins.posix import Flags

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def test_chroot():
    project = angr.Project(os.path.join(test_location, 'x86_64', 'chroot_test'))
    initial_state = project.factory.entry_state()
    
    simgr = project.factory.simgr(initial_state)

    simgr.run()

    #Try and read the files stat size from new chrooted dir
    try:
        fd = simgr.deadended[0].posix.open('/test.txt', Flags.O_RDONLY)
        stat = simgr.deadended[0].posix.fstat(fd)
        print(f"File's Stat Size: {stat.st_size}")
    except:
        print("Error while trying to open the file")

if __name__ == "__main__":
    test_chroot()