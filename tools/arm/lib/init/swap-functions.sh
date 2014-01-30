#
# Functions that assist in turning on swap.
#

# $1 is a string used to log the type of swap expected to be activated
swaponagain() {
	#
	# Execute swapon command again to pick up any swap partitions
	# that have shown up since the last swapon.
	#
	# Ignore 255 status due to swap already being enabled
	#
	if [ "$NOSWAP" = yes ]
	then
		[ "$VERBOSE" = no ] || log_warning_msg "Not activating swap as requested via bootoption noswap."
	else
		if [ "$VERBOSE" = no ]
		then
			log_action_begin_msg "Activating $1 swap"
			swapon -a -e 2>/dev/null || :  # Stifle "Device or resource busy"
			log_action_end_msg 0
		else
			log_daemon_msg "Will now activate $1 swap"
			swapon -a -e -v
			log_action_end_msg $?
		fi
	fi
}
