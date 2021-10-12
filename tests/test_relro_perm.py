import logging
l = logging.getLogger("angr.tests")
import os

import angr
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

target_arches = {
    'i386',
    'x86_64',
    'ppc',
    'armel',
    'mips'
}

def run_fauxware_relro(arch):
    p = angr.Project(os.path.join(test_location, arch, 'fauxware'), use_sim_procedures=False)
    s = p.factory.full_init_state(add_options={angr.options.STRICT_PAGE_ACCESS})

    relro_segment = next((s for s in p.loader.main_object.segments if s.relro), None)
    if relro_segment is None:
        # No relro on this arch
        return

    assert not relro_segment.is_writable, "The RELRO segment should not be writable"

    try:
        s.memory.store(relro_segment.min_addr, b'\x42')
        assert False, "The RELRO segment should not be writable"
    except angr.errors.SimSegfaultException:
        pass

def test_fauxware_relro():
    for arch in target_arches:
        yield run_fauxware_relro, arch

if __name__ == "__main__":
    for r,a in test_fauxware_relro():
        r(a)
