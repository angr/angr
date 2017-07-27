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
    version='6.7.7.27',
    description='The next-generation binary analysis platform from UC Santa Barbara\'s Seclab!',
    packages=packages,
    install_requires=[
        'capstone>=3.0.5rc2',
        'networkx',
        'futures',
        'progressbar',
        'mulpyplexer',
        'cooldict',
        'ana',
        'archinfo>=6.7.7.27',
        'pyvex>=6.7.7.27',
        'claripy>=6.7.7.27',
        'simuvex>=6.7.7.27',
        'cle>=6.7.7.27',
        'cachetools',
    ],
)
