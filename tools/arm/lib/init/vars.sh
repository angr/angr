#
# Set rcS vars
#

# Source conffile
if [ -f /etc/default/rcS ]; then
    . /etc/default/rcS
fi

# Parse kernel command line
if [ -r /proc/cmdline ]; then
    for ARG in $(cat /proc/cmdline); do
        case $ARG in

            # check for bootoption 'noswap' and do not activate swap
            # partitions/files when it is set.
            noswap)
		NOSWAP=yes
		break
		;;

            # Accept the same 'quiet' option as the kernel, but only
            # during boot and shutdown.  Only use this rule when the
            # variables set by init.d/rc is present.
            quiet)
		if [ "$RUNLEVEL" ] && [ "$PREVLEVEL" ] ; then
		    VERBOSE="no"
		fi
		break
		;;
	esac
    done
fi

# But allow both rcS and the kernel options 'quiet' to be overrided
# when INIT_VERBOSE=yes is used as well.
if [ "$INIT_VERBOSE" ] ; then
    VERBOSE="$INIT_VERBOSE"
fi
