from distutils.core import setup

setup(
    name='angr',
    version='1.00',
    packages=['angr', 'angr.surveyors', 'angr.analyses'],
    install_requires=[i.strip() for i in open('requirements.txt').readlines() if 'git' not in i]
)
