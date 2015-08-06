from setuptools import setup

setup(
    name='simuvex',
    version='1.00',
    packages=['simuvex', 'simuvex.plugins', 'simuvex.storage', 'simuvex.vex', 'simuvex.vex.statements', 'simuvex.vex.expressions', 'simuvex.procedures', 'simuvex.procedures.cgc', 'simuvex.procedures.ld-linux-x86-64___so___2', 'simuvex.procedures.testing', 'simuvex.procedures.stubs', 'simuvex.procedures.syscalls', 'simuvex.procedures.ld-uClibc___so___0', 'simuvex.procedures.libc___so___6'],
    install_requires=[
        'dpkt-fix',
        'pyvex',
        'archinfo',
        'claripy',
        'cooldict',
        'ana',
    ],
    dependency_links=[
        'git+https://github.com/angr/pyvex.git#egg=pyvex-4.0',
        'git+https://github.com/angr/archinfo.git#egg=archinfo-4.0',
        'git+https://github.com/angr/claripy.git#egg=claripy-0.1',
        'git+https://github.com/zardus/cooldict#egg=cooldict-0.1',
        'git+https://github.com/zardus/ana#egg=ana-0.1',
    ],
)
