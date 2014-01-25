#!/bin/bash

source /etc/bash_completion.d/virtualenvwrapper

if [ -z $1 ] ; then
    echo "Usage: \`uninstall.sh project_directory\` will remove the installation of the framework"
    exit 0
fi

export PROJ_DIR=$1


cd $PROJ_DIR
rm -f install.log
rm -rf angr ida idalink pybfd simuvex symexec z3
rm -rf valgrind
rmvirtualenv angr
sudo dpkg -r valgrind z3
