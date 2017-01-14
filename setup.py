try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    import os
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

setup(
    name='angr',
    version='6.7.1.13',
    description='The next-generation binary analysis platform from UC Santa Barbara\'s Seclab!',
    packages=packages,
    install_requires=[
        'capstone',
        'networkx',
        'futures',
        'progressbar',
        'mulpyplexer',
        'cooldict',
        'ana',
        'archinfo>=6.7.1.13',
        'pyvex>=6.7.1.13',
        'claripy>=6.7.1.13',
        'simuvex>=6.7.1.13',
        'cle>=6.7.1.13',
        'cachetools',
    ],
)
