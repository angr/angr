from distutils.core import setup

setup(
    name='angr',
    version='0.8.0',
    packages=['angr', 'angr.surveyors', 'angr.analyses'],
    install_requires=[i.strip() for i in open('requirements.txt').readlines()],
)
