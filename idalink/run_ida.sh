#!/bin/bash

export TERM=xterm

IDADIR=$1
shift
FILE=$1
shift
LOGFILE=$1
shift
SCRIPT=$1
shift
ARGS="$@"

echo "Launching IDA on file $FILE with script: $SCRIPT" >> $LOGFILE
echo "... log: $LOGFILE" >> $LOGFILE
echo "... arguments: $ARGS" >> $LOGFILE

( file $FILE | egrep -q "[^[:digit:]]64[^[:digit:]]" ) && IDABIN=idal64
( file $FILE | egrep -q "[^[:digit:]]32[^[:digit:]]" ) && IDABIN=idal

echo "... detected executable: $IDABIN" >> $LOGFILE

$IDADIR/$IDABIN -A -S"$SCRIPT $ARGS" -L$LOGFILE $FILE
