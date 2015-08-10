from distutils.core import setup

setup(
    name='angr',
    version='0.8.0',
    packages=['angr', 'angr.surveyors', 'angr.analyses'],
    install_requires=[
        'capstone',
        'networkx',
        'futures',
        'progressbar',
        'mulpyplexer',
        'cooldict',
        'ana',
        'archinfo',
        'pyvex',
        'claripy',
        'simuvex',
        'cle',
    ],
    dependency_links=[
        'git+https://github.com/zardus/mulpyplexer#egg=mulpyplexer-0.1',
        'git+https://github.com/zardus/cooldict#egg=cooldict-0.1',
        'git+https://github.com/zardus/ana#egg=ana-0.1',
        'git+https://github.com/angr/archinfo.git#egg=archinfo-4.0',
        'git+https://github.com/angr/pyvex.git#egg=pyvex-4.0',
        'git+https://github.com/angr/claripy.git#egg=claripy-0.1',
        'git+https://github.com/angr/simuvex.git#egg=simuvex-0.1',
        'git+https://github.com/angr/cle.git#egg=cle-4.0',
    ],
)
