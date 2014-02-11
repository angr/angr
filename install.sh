#!/bin/bash
# Installs tools and dependencies required for firmware analysis project.

# Todo:
#   git.seclab or github ? (2)

#set -e

# Update these if needed 

# Root of the project - set it to whichever folder you like.
if [ -z $1 ] ; then
    echo "Usage: \`install.sh project_directory\` will create a new directory and setup the framework."
    exit 0
fi

export PROJ_DIR=$1

# Get full path of project directory
echo $1 | egrep -e '^/' > /dev/null
if [ $? -eq 0 ] ; then
    PROJ_DIR=$1
else
    PROJ_DIR=$PWD/$1
fi

LOG_FILE="$PROJ_DIR/install.log"

#PROJ_DIR="/home/chris/binary_project"
if [ -z $CONCURRENCY_LEVEL ] ; then
    export CONCURRENCY_LEVEL=`nproc` # cc threads, speeds up compilation times
fi

# Download URLs
valgrind_url="http://valgrind.org/downloads/valgrind-3.8.1.tar.bz2"
z3_commit="a5335270042c3eeb7128e36c41790825053c93f6"

python_version="python2.7"
valgrind_patch=$PROJ_DIR/angr/pyvex/valgrind_static_3.8.1.patch

#IDA
idal="$PROJ_DIR/ida/idal"
idal64="$PROJ_DIR/ida/idal64"

# Dependencies (32 bits dependencies required by IDA)
required_packages="realpath python-radare2 unzip checkinstall wget lib32stdc++6 libc6-i386 git $python_version virtualenvwrapper binutils-multiarch binutils-dev build-essential python-dev screen"


# Create project directory
if [ ! -d $PROJ_DIR ] ; then
    mkdir $PROJ_DIR
fi

echo "==`date`==" > $LOG_FILE

cd $PROJ_DIR


# Interactive colors
echo_green () 
{
    str="\033[0;32m$1\033[0m"

    if [ ''''$2'' == '-n' ] ; then
        echo -ne $str
    else
        echo -e $str
    fi
}

echo_red () 
{
echo -e "\033[1;31m$1\033[0m"
}


# Logging and error management
try ()
{
    ${1} >>$LOG_FILE #2&>1
    err=$?
    if [ $err -ne 0 ] ; then
        echo_red "Error $err executing the following command: \`$1\`"
        exit $err
    else
        echo_green "[ok]"
    fi
}

# 1) Install required dependencies (Debian)
echo_green "--> 1) Install required dependencies"
uname -a | egrep -e '(Debian|Ubuntu)' > /dev/null
if [ $? -ne 0 ] ; then
    echo_red "You don't appear to be running Debian or Ubuntu. Please install the following packages and press enter to continue:"
    echo_red $required_packages
    read x

else
    echo "(Sudo will prompt for root password)"
    sudo apt-get -qq install $required_packages
fi



# 2) Add extra git repos here
echo_green "--> 2) Cloning git repos"
for i in angr simuvex symexec ; do
    if [ ! -d $i ] ; then
        try "git clone git@git.seclab.cs.ucsb.edu:yans/$i.git"
    fi
done

# Pybfd
if [ ! -d pybfd ] ; then
    try "git clone https://github.com/Groundworkstech/pybfd"
fi

# idalink
if [ ! -d idalink ] ; then
    try "git clone https://github.com/zardus/idalink"
fi

# ida
if [ ! -d ida ] ; then
    try "git clone git@git.seclab.cs.ucsb.edu:seclab/ida.git"
fi

# 3) Make virtual env
echo_green "--> 3) Make virtual environment (virtualenvwrapper)"
#export WORKON_HOME=$PROJ_DIR
export VIRTUAL_ENV="$WORKON_HOME/angr"
try "source /etc/bash_completion.d/virtualenvwrapper"
try "mkvirtualenv --system-site-packages angr"
#workon angr

#if [ $? -ne 0 ] ; then
#    echo_red "(3) There was an error creating the virtual env :(".
#    exit 3
#fi

# 4) Install various libs
echo_green "--> 4) Installing various libs."

try "pip install rpyc"
try "pip install networkx"
try "pip install git+https://github.com/zardus/cooldict.git"
try "pip install virtualenvwrapper"
try "pip install nose"


# Symlinks
echo_green "--> Symlinks..."
ln -sf $PROJ_DIR/simuvex/simuvex $VIRTUAL_ENV/lib/$python_version/
ln -sf $PROJ_DIR/angr $VIRTUAL_ENV/lib/$python_version/
ln -sf $PROJ_DIR/symexec/symexec $VIRTUAL_ENV/lib/$python_version/

cd idalink/idalink
    rm idal idal64
    ln -sf $PROJ_DIR/ida/idal64 .
    ln -sf $PROJ_DIR/ida/idal .
    ln -sf $PROJ_DIR/idalink/idalink $VIRTUAL_ENV/lib/$python_version/
cd $PROJ_DIR


# 5) Setup pybfd
echo_green "--> 5) Setup pybfd"
cd pybfd
    try "python setup.py install"
cd ..

# 6) Pyvex
echo_green "--> 6) Get Pyvex"
if [ ! -d angr/pyvex ] ; then
    cd angr
     try "git clone https://github.com/zardus/pyvex"
    cd ..
fi

# 7) Get valgrind, patch it and make a Debian package
echo_green "--> 7) Fetch valgrind"
if [ ! -d valgrind ] ; then
    mkdir valgrind
    cd valgrind
        try "wget -c -q "$valgrind_url" -O valgrind.tar.bz2"
        try "tar xvjf valgrind.tar.bz2"

        valgrind_version=`echo $valgrind_url | egrep -o -E 'valgrind-[0-9].[0-9].[0-9]'`
        cd $valgrind_version

        echo_green "......Patch valgrind"
        try "patch -p1 -i $valgrind_patch"
        echo_green "......Compile valgrind"
        export CFLAGS=-fPIC
        try "./configure --prefix=/usr"
        try "make -j $CONCURRENCY_LEVEL"
        #Debian package
        echo_green "......Make Debian valgrind package and install it"

        valgrind_release=`echo $valgrind_version | egrep -o -E '[0-9].[0-9].[0-9]'`
        try "sudo checkinstall -y --install=no --fstrans --nodoc --backup -D --pkgrelease $valgrind_release --pkgname valgrind make install"
        try "sudo dpkg -i valgrind*.deb"

        # Valgrind prefix
        cd $PROJ_DIR
        echo_green "--> 8) Check Valgrind installation prefix"

        cd angr/pyvex

        echo "--> FYI: This script installed Valgrind with a /usr prefix (./configure --prefix=/usr). If you prefer to install valgrind in another location, remove the generated Debian package (i.e., dpkg -r valgrind), install Valgrind in you preferred location and then edit $PROJ_DIR/angr/pyvex/setup.py to update the vgprefix variable."
        echo "Press any key to continue"
        read x

        try "python setup.py build"
        cp build/lib.linux-x86_64-2.7/pyvex.so $VIRTUAL_ENV/lib/python2.7/site-packages/
        cd $PROJ_DIR

else
    echo_green "(Already installed)"
fi

#9) Setup IDALink
echo_green "--> 9) Setup IDALink"
cd idalink/idalink
rm idal idal64
ln -sf $PROJ_DIR/ida/idal64 .
ln -sf $PROJ_DIR/ida/idal .
ln -sf $PROJ_DIR/idalink/idalink $VIRTUAL_ENV/lib/$python_version/

#10) Install Z3
echo_green "--> 10) Install Z3"
cd $PROJ_DIR
if [ ! -d z3 ] ; then
    mkdir z3
    cd z3
    # This is a workaround (avoids git hanging after resolving deltas)
    echo_green "(.....fetch)"
    git init
    git remote add origin https://git01.codeplex.com/z3
    git pull 
    git fsck
    git checkout $z3_commit

    try "python scripts/mk_make.py"
    cd build
    echo_green "(.....build)"
    try "make -j $CONCURRENCY_LEVEL"

    echo_green "(.....create Debian package)"
    try "sudo checkinstall -y --pkgrelease=$z3_commit --pkgname=z3 make install"

    cp *.pyc $VIRTUAL_ENV/lib/$python_version/
    cd ..

    cd $PROJ_DIR
    cp symexec/libz3_no_gc.so $VIRTUAL_ENV/lib/libz3.so
else
    echo_green "(Already installed)"
fi


#12) Accept IDA License
echo_green "I will now launch IDA, accept the license and quit. Press any key to continue."
read x

uname -a | grep amd64 > /dev/null
if [ $? -eq 0 ] ; then
    sh -c "exec $idal64"
else
    sh -c "exec $idal"
fi

echo_green "--> If you reached this point, things will hopefully work ! :)"
echo "A new *angr* environment has been created, you can use it by invoking \`workon angr\` in the shell."
