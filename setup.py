from setuptools import setup

setup(
    name='simuvex',
    version='4.5.9.29',
    packages=['simuvex', 'simuvex.plugins', 'simuvex.storage', 'simuvex.vex', 'simuvex.vex.statements', 'simuvex.vex.expressions', 'simuvex.procedures', 'simuvex.procedures.cgc', 'simuvex.procedures.ld-linux-x86-64___so___2', 'simuvex.procedures.testing', 'simuvex.procedures.stubs', 'simuvex.procedures.syscalls', 'simuvex.procedures.ld-uClibc___so___0', 'simuvex.procedures.libc___so___6'],
    install_requires=[
        'dpkt-fix',
        'pyvex',
        'archinfo',
        'claripy',
        'cooldict',
        'ana',
    ],
)
