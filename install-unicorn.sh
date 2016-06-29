#!/bin/bash -e

if [ ! -e unicorn ]
then
	git clone git@git.seclab.cs.ucsb.edu:cgc/unicorn.git
else
	cd unicorn
	git pull || echo "WARNING: unable to pull unicorn"
	cd ..
fi

make -j install PREFIX=$VIRTUAL_ENV
cd bindings/python
make -j install PREFIX=$VIRTUAL_ENV
cd ../../..

if [ -e $VIRTUAL_ENV/lib/python2.7/site-packages/unicorn ]
then
	cd $VIRTUAL_ENV/lib/python2.7/site-packages/unicorn
	ln -sf ../../../libunicorn.so .
else
	cd $VIRTUAL_ENV/site-packages/unicorn
	ln -sf ../../lib/libunicorn.so .
fi
cd -

python -c "import unicorn; print 'Unicorn successfully imported.'"
