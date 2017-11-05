from ubuntu:trusty
maintainer audrey@rhelmot.io

run apt-get update &&									\
	apt-get install -y virtualenvwrapper python2.7-dev build-essential libxml2-dev libxslt1-dev git libffi-dev cmake libreadline-dev libtool debootstrap debian-archive-keyring libglib2.0-dev libpixman-1-dev

run useradd -s /bin/bash -m angr

run su - angr -c "git clone https://github.com/angr/angr-dev && cd angr-dev && ./setup.sh -e angr"
run su - angr -c "echo 'workon angr' >> /home/angr/.bashrc"
cmd su - angr
