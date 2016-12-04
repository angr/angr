from distutils.core import setup

setup(
    name='angr',
    version='5.6.12.3',
    description='The next-generation binary analysis platform from UC Santa Barbara\'s Seclab!',
    packages=['angr', 'angr.surveyors', 'angr.analyses', 'angr.knowledge', 'angr.exploration_techniques'],
    install_requires=[
        'capstone',
        'networkx',
        'futures',
        'progressbar',
        'mulpyplexer',
        'cooldict',
        'ana',
        'archinfo>=5.6.12.3',
        'pyvex>=5.6.12.3',
        'claripy>=5.6.12.3',
        'simuvex>=5.6.12.3',
        'cle>=5.6.12.3',
        'cachetools',
    ],
)
