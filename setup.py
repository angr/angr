import os
import shutil
import subprocess
from distutils.errors import LibError
from distutils.core import setup
from distutils.command.build import build as _build

QEMU_REPO_PATH = "tracer-qemu"
BIN_PATH = "bin"
QEMU_PATH = os.path.join("bin", "tracer-qemu-cgc")

if not os.path.exists(QEMU_REPO_PATH):
    TRACER_QEMU_REPO = "git@git.seclab.cs.ucsb.edu:cgc/qemu.git"
    if subprocess.call(['git', 'clone', TRACER_QEMU_REPO, QEMU_REPO_PATH]) != 0:
        raise LibError("Unable to retrieve tracer qemu")
    if subprocess.call(['git', 'checkout', 'base_tracer'], cwd=QEMU_REPO_PATH) != 0:
        raise LibError("Unable to checkout tracer branch")

if subprocess.call(['git', 'pull'], cwd=QEMU_REPO_PATH) != 0:
    raise LibError("Unable to retrieve tracer qemu")

if not os.path.exists(BIN_PATH):
    try:
        os.makedirs(BIN_PATH)
    except OSError:
        raise LibError("Unable to create bin directory")

def _build_qemu():
    if subprocess.call(['./tracer-config'], cwd=QEMU_REPO_PATH) != 0:
        raise LibError("Unable to configure tracer-qemu")

    if subprocess.call(['make'], cwd=QEMU_REPO_PATH) != 0:
        raise LibError("Unable to build tracer qemu")

    shutil.copyfile(os.path.join(QEMU_REPO_PATH, "i386-linux-user", "qemu-i386"), QEMU_PATH)
    os.chmod(QEMU_PATH, 0755)

class build(_build):
    def run(self):
            self.execute(_build_qemu, (), msg="Building Tracer QEMU")
            _build.run(self)
cmdclass = {'build': build}


setup(
    name='tracer', version='0.1', description="Symbolically trace concrete inputs.",
    packages=['tracer'], 
    data_files=[
        ('bin', ('bin/tracer-qemu-cgc',),),
    ],
    cmdclass=cmdclass,
)
