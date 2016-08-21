from setuptools import setup

setup(
    name='tracer', version='0.1', description="Symbolically trace concrete inputs.",
    packages=['tracer', 'tracer.cachemanager', 'tracer.simprocedures'],
    install_requires=[ 'shellphish-qemu' ],
)
