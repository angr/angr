#
# Functions for reporting fsck progress in usplash
#
# (C) 2008 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#

# convert a "pass cur max" progress triple from fsck to a progress percentage
# based on calc_percent() from e2fsck
fsck_progress_to_percent() {
    if [ $1 = 1 ]; then
        PERCENT=$(($2 * 70 / $3))
    elif [ $1 = 2 ]; then
        PERCENT=$(($2 * 20 / $3 + 70))
    elif [ $1 = 3 ]; then
        PERCENT=$(($2 * 2 / $3 + 90))
    elif [ $1 = 4 ]; then
        PERCENT=$(($2 * 3 / $3 + 92))
    elif [ $1 = 5 ]; then
        PERCENT=$(($2 * 5 / $3 + 95))
    else
        PERCENT=100
    fi
}

# read current fsck status ($PASS, $CUR, $MAX) from file descriptor 4
# this assumes that fsck was started in the background ($!)
get_fsck_status()
{
        local a b c S

        unset a
        # only consider the last line
        while true; do
            PASS=$a
            CUR=$b
            MAX=$c
            read a b c rest <&4
            if [ -n "$PASS" ] && [ -z "$a" ]; then
                break;
            fi

            # if we did not read anything, check if the process is still
            # actually running, or just waiting to be reaped
            if [ -z "$PASS" ] && [ -z "$a" ]; then
                S=`ps -o state --no-headers -p $!` || break
                [ "$S" != "Z" ] || break
                # do not spin while waiting for fsck to start up
                sleep 0.1
            fi
        done
}

# Set $NAME to a human readable description of which partitions are currently
# being checked. Set $CLEAN if this is only a routine check on clean
# partitions which can be skipped.
get_checked_names ()
{
        local DEVS DUMP LABEL

        FSCKPROCS=$(ps --no-headers -C 'fsck.ext2 fsck.ext3 fsck.ext4 fsck.ext4dev' -o pid,args | grep /dev)
        DEVS=$(echo "$FSCKPROCS" | sed 's_^.*\(/dev/[^[:space:]]*\).*$_\1_')
        FSCKPIDS=$(echo "$FSCKPROCS" | sed 's_^[[:space:]]*\([[:digit:]]\+\).*$_\1_')

        if [ -z "$DEVS" ]; then
            unset NAME
            return 0
        fi

        CLEAN=1
        unset NAME
        for DEV in $DEVS; do
            DUMP=$(dumpe2fs -h $DEV)
            if ! echo "$DUMP" | grep -q 'state:[[:space:]]*clean$'; then
                unset CLEAN
            fi

            LABEL=$(blkid $DEV | sed -rn '/LABEL="([^"]+)"/ { s/^.*LABEL="//; s/".*$//; p }')
            [ -z "$NAME" ] || NAME="$NAME, "
            if [ -n "$LABEL" ]; then
                NAME="$NAME$LABEL ($DEV)"
            else
                NAME="$NAME$DEV"
            fi
        done
}

# Return true if usplash is active
usplash_running() {
    if pidof usplash ; then
	return 0
    else
	return 1
    fi
}

# Read fsck progress from file $1 and display progress in usplash.
usplash_progress() {
        exec 4<$1
        unset CANCEL
        ESCAPE=`/bin/echo -ne "\x1B"`
        FIRST=1
        PREVPERCENT=0

        while true; do
            sleep 0.5
            get_fsck_status
            [ -n "$PASS" ] || break

            fsck_progress_to_percent "$PASS" "$CUR" "$MAX"

            # check if fsck advanced to the next drive
            if [ "$PREVPERCENT" -gt "$PERCENT" ]; then
                if [ -n "$CANCEL" ]; then
                    usplash_write "STATUS skip                                                        "
                else
                    usplash_write "STATUS                                                             "
                fi
                FIRST=1
            fi
            PREVPERCENT=$PERCENT

            # lazy initialization of output and progress report on the first
            # progress line that we receive; this avoids starting the output
            # for clean or non-ext[234] partitions
            if [ -n "$FIRST" ]; then
                usplash_write "TIMEOUT 0"

                # show which device is being checked
                get_checked_names
                [ -n "$NAME" ] || break

                usplash_write "VERBOSE on"
                if [ "$CLEAN" ]; then
                    usplash_write "TEXT Routine check of drives: $NAME..."
                    usplash_write "TEXT Press ESC to skip"
                else
                    usplash_write "TEXT Unclean shutdown, checking drives:"
                    usplash_write "TEXT $NAME..."
                fi

                unset FIRST
            fi

            usplash_write "STATUS $PERCENT% (stage $PASS/5, $CUR/$MAX)                       "
            echo "Checking drive $NAME: $PERCENT% (stage $PASS/5, $CUR/$MAX)" >/dev/console

            # ESC interrupts check for clean drives
            if [ -n "$CLEAN" ]; then
                if FAIL_NO_USPLASH=1 usplash_write "INPUTCHAR"; then
                    read ch < /dev/.initramfs/usplash_outfifo
                    if [ "$ch" = "$ESCAPE" ]; then
                        kill $FSCKPIDS
                        CANCEL=1
                        continue # there might be more drives, so do not break
                    fi
                fi
            fi
        done

        if [ -n "$CANCEL" ]; then
            usplash_write "STATUS skip                                                        "
        else
            usplash_write "STATUS                                                             "
        fi
        usplash_write "VERBOSE default"
        usplash_write "TEXT Drive checks finished."
        usplash_write "TIMEOUT 15"
        wait %1 # to collect fsck's exit code
        EXITCODE=$?
        [ -n "$CANCEL" ] && FSCKCODE=0 || FSCKCODE=$EXITCODE
        if [ "$FSCKCODE" -gt 1 ]; then
            # non-correctable failure which requires sulogin: quit usplash and
            # restore stdin/out/err
            usplash_write "QUIT"
            exec </dev/console >/dev/console 2>/dev/console
        fi
}
