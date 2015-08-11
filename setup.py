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
)
