from distutils.core import setup

setup(
    name='angr',
    version='4.5.9.29',
    description='The next-generation binary analysis platform from UC Santa Barbara\'s Seclab!',
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
