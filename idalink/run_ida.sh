#!/bin/bash

export TERM=xterm

FILE=$1
shift
LOGFILE=$1
shift
SCRIPT=$1
shift
ARGS="$@"

echo "Launching IDA with script: $SCRIPT" >> $LOGFILE
echo "... arguments: $ARGS" >> $LOGFILE
/opt/analrepo/bin/idal64 -A -S"$SCRIPT $ARGS" -L$LOGFILE $FILE
