TOC:
=============================
### A. Installation instructions
### B. Troubleshooting


A. INSTALLATION INSTRUCTIONS
=============================
Thank you for your desire to install Angr. Unfortunately, this is impossible.

Script
------
If you feel lucky, you may want to try the autoinstall script:
bash angr/install.sh [target] (make sure you use bash)

Manual installation
------------------
First, install the following packages:
    $ apt-get install virtualenvwrapper binutils-multiarch binutils-dev
build-essential python-dev screen python-radare2 qemu checkinstall python2.7
git 

Then, in a *new* shell:

Make a python virtualenv to contain the custom stuff:
    $ mkvirtualenv --system-site-packages angr

### Install various libs:
    $ pip install rpyc
    $ pip install networkx
    $ pip install git+https://github.com/zardus/cooldict.git

Go to the directory where you'll have all the angr crap:
    $ cd ~/code/angr
    $ git clone git@git.seclab.cs.ucsb.edu:yans/simuvex.git
    $ git clone git@git.seclab.cs.ucsb.edu:yans/angr.git
    $ git clone git@git.seclab.cs.ucsb.edu:yans/symexec.git
    $ ln -s $PWD/simuvex/simuvex $VIRTUAL_ENV/lib/python2.7/
    $ ln -s $PWD/angr $VIRTUAL_ENV/lib/python2.7/
    $ ln -s $PWD/symexec/symexec $VIRTUAL_ENV/lib/python2.7/

### Install PyBFD:
    $ git clone https://github.com/Groundworkstech/pybfd
    $ cd pybfd
    $ python setup.py install
    $ cd ..

### Install VEX and PyVEX:
    $ mkdir ~/valgrind
    $ cd ~/valgrind
    $ wget http://valgrind.org/downloads/valgrind-3.8.1.tar.bz2
    $ tar xvjf valgrind-3.8.1.tar.bz2
    $ cd ~/code/angr
    $ git clone https://github.com/zardus/pyvex
    $ cd ~/valgrind/valgrind-3.8.1
    $ patch -p1 < ~/code/angr/pyvex/valgrind_static_3.8.1.patch
    $ CFLAGS=-fPIC ./configure --prefix=$HOME/valgrind/inst
    $ make; make install
    $ cd ~/code/angr/pyvex

Now, edit setup.py to change your vgprefix to wherever you *installed* valgrind
    $ python setup.py install

### Install IDALink:
    $ git clone https://github.com/zardus/idalink
    $ cd idalink/idalink
    $ rm idal idal64
    $ ln -s /path/to/idal .
    $ ln -s /path/to/idal64 .
    $ cd ../../
    $ ln -s $PWD/idalink/idalink $VIRTUAL_ENV/lib/python2.7/

### Launch IDA, accept the license, and quit:
    $ /path/to/idal
    $ /path/to/idal64

### Install Z3:
    $ mkdir z3
    $ cd z3
    $ git init
    $ git git remote add origin https://git01.codeplex.com/z3
    $ git pull
    $ git fsck
    $ git checkout a5335270042c3eeb7128e36c41790825053c93f6
    $ python scripts/mk_make.py
    $ cp bin/*.pyc $VIRTUAL_ENV/lib/python2.7/
    $ cd ../../
    $ cp symexec/libz3_no_gc.so $VIRTUAL_ENV/lib/libz3.so


B. TROUBLESHOOTING
==================

### IDA/32 bits libs
Note that IDA requires 32bit libraries (yes, even the 64 bit version). 
Make sure you check ida's binaries and resolve dependencies issues:
    $ ldd idal
    $ ldd idal64
On Debian based systems, you'll probably need to switch to multiarch and
install libc6 and libstdc++6 for i386:
    $ dpkg --add-architecture i386 ; apt-get update
    $ apt-get install libc6-i386 and lib32stdc++6

### IDA/Python
Also, IDA runs its own python, which may result in issues with idalink. Make
sure you got a symlink to idalink in your ida's python libs directory:
    $ ln -s idalink ida/ida-version/python/lib/python-version/

### IDA/idalink
IDA leaves database files in the current directory after each run,
leading to all sort of issues when running several angr sessions with the same
binary. you may want to remove these files between two runs:
    $ rm -f *.id0 *.id1 *.nam *.idb *.i64
If you experience idalink related issues, check idalink's log
in /tmp/idalink.log

