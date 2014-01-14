# Installation Instructions

Thank you for your desire to install Angr. Unfortunately, this is impossible.

First, install the following packages:
# apt-get install virtualenvwrapper binutils-multiarch binutils-dev build-essential python-dev

Then, in a *new* shell:

Make a python virtualenv to contain the custom stuff:
# mkvirtualenv angr

Install various libs:
# pip install rpyc
# pip install networkx
# pip install git+https://github.com/zardus/cooldict.git

Go to the directory where you'll have all the angr crap:
# cd ~/code/angr
# git clone git@git.seclab.cs.ucsb.edu:yans/simuvex.git
# git clone git@git.seclab.cs.ucsb.edu:yans/angr.git
# git clone git@git.seclab.cs.ucsb.edu:yans/symexec.git
# ln -s $PWD/simuvex/simuvex $VIRTUAL_ENV/lib/python2.7/
# ln -s $PWD/angr $VIRTUAL_ENV/lib/python2.7/
# ln -s $PWD/symexec/symexec $VIRTUAL_ENV/lib/python2.7/

Install PyBFD:
# git clone https://github.com/Groundworkstech/pybfd
# cd pybfd
# python setup.py install
# cd ..

Install VEX and PyVEX:
# mkdir ~/valgrind
# cd ~/valgrind
# wget http://valgrind.org/downloads/valgrind-3.8.1.tar.bz2
# tar xvjf valgrind-3.8.1.tar.bz2
# cd ~/code/angr
# git clone https://github.com/zardus/pyvex
# cd ~/valgrind/valgrind-3.8.1
# patch -p1 < ~/code/angr/pyvex/valgrind_static_3.8.1.patch
# CFLAGS=-fPIC ./configure --prefix=$HOME/valgrind/inst
# make; make install
# cd ~/code/angr/pyvex
# python setup.py install

Install IDALink:
# git clone https://github.com/zardus/idalink
# cd idalink/idalink
# rm idal idal64
# ln -s /path/to/idal .
# ln -s /path/to/idal64 .
# cd ../../
# ln -s $PWD/idalink/idalink $VIRTUAL_ENV/lib/python2.7/

Launch IDA, accept the license, and quit:
# /path/to/idal
# /path/to/idal64

Install Z3:
# mkdir z3
# cd z3
# wget "
http://download-codeplex.sec.s-msft.com/Download/Release?ProjectName=z3&DownloadId=768911&FileTime=130317387265130000&Build=20841"
-O z3.zip
# unzip z3.zip
# cd z3-4.3.2.a5335270042c-x64-ubuntu-12.04/
# cp bin/*.pyc $VIRTUAL_ENV/lib/python2.7/
# cd ../../
# cp symexec/libz3_no_gc.so $VIRTUAL_ENV/lib/libz3.so