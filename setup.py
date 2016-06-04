from distutils.core import setup

setup(
    name='angr',
    version='4.6.6.4',
    description='The next-generation binary analysis platform from UC Santa Barbara\'s Seclab!',
    packages=['angr', 'angr.surveyors', 'angr.analyses', 'angr.knowledge'],
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
        'cachetools',
    ],
)
