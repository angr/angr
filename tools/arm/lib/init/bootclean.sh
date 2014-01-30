#!/bin/sh
#
# bootclean
#
# Clean /tmp.  Clean /var/run and /var/lock if not mounted as tmpfs
#
# DO NOT RUN AFTER S:55bootmisc.sh and do not run this script directly
# in runlevel S. Instead write an initscript to call it.
#

. /lib/init/vars.sh

. /lib/lsb/init-functions

# Should be called outside verbose message block
mkflagfile()
{
	# Prevent symlink attack  (See #264234.)
	[ -L "$1" ] && log_warning_msg "bootclean: Deleting symbolic link '$1'."
	rm -f "$1" || { log_failure_msg "bootclean: Failure deleting '$1'." ; return 1 ; }
	# No user processes should be running, so no one should be able to introduce
	# a symlink here.  As an extra precaution, set noclobber.
	set -o noclobber
	:> "$1" || { log_failure_msg "bootclean: Failure creating '$1'." ; return 1 ; }
	return 0
}

clean_tmp() {
	cd /tmp || { log_failure_msg "bootclean: Could not cd to /tmp." ; return 1 ; }

	#
	# Only clean out /tmp if it is world-writable. This ensures
	# it really is a/the temp directory we're cleaning.
	#
	[ "$(find . -maxdepth 0 -perm -002)" = "." ] || return 0

	if [ ! "$TMPTIME" ]
	then
		log_warning_msg "Using default TMPTIME 0."
		TMPTIME=0
	fi

	[ "$VERBOSE" = no ] || log_action_begin_msg "Cleaning /tmp"

	#
	# Remove regardless of TMPTIME setting
	#
	rm -f .X*-lock

	#
	# Don't clean remaining files if TMPTIME is negative or 'infinite'
	#
	case "$TMPTIME" in
	  -*|infinite|infinity)
		[ "$VERBOSE" = no ] || log_action_end_msg 0 "skipped"
		return 0
		;;
	esac

	#
	# Wipe /tmp, excluding system files, but including lost+found
	#
	# If TMPTIME is set to 0, we do not use any ctime expression
	# at all, so we can also delete files with timestamps
	# in the future!
	#
	if [ "$TMPTIME" = 0 ] 
	then
		TEXPR=""
		DEXPR=""
	else
		TEXPR="-mtime +$TMPTIME -ctime +$TMPTIME -atime +$TMPTIME"
		DEXPR="-mtime +$TMPTIME -ctime +$TMPTIME"
	fi

	EXCEPT='! -name .
		! ( -path ./lost+found -uid 0 )
		! ( -path ./quota.user -uid 0 )
		! ( -path ./aquota.user -uid 0 )
		! ( -path ./quota.group -uid 0 )
		! ( -path ./aquota.group -uid 0 )
		! ( -path ./.journal -uid 0 )
		! ( -path ./.clean -uid 0 )
		! ( -path './...security*' -uid 0 )'

	mkflagfile /tmp/.clean || return 1

	report_err()
	{
		if [ "$VERBOSE" = no ]
		then
			log_failure_msg "bootclean: Failure cleaning /tmp."
		else
			log_action_end_msg 1 "bootclean: Failure cleaning /tmp"
		fi
	}

	#
	# First remove all old files...
	#
	find . -depth -xdev $TEXPR $EXCEPT ! -type d -delete \
		|| { report_err ; return 1 ; }

	#
	# ...and then all empty directories
	#
	find . -depth -xdev $DEXPR $EXCEPT -type d -empty -delete \
		|| { report_err ; return 1 ; }

	[ "$VERBOSE" = no ] || log_action_end_msg 0
	return 0
}

clean_lock() {
	if [ yes = "$RAMLOCK" ] ; then
	    return 0
	fi

	cd /var/lock || { log_failure_msg "bootclean: Could not cd to /var/lock." ; return 1 ; }

	[ "$VERBOSE" = no ] || log_action_begin_msg "Cleaning /var/lock"
	report_err()
	{
		if [ "$VERBOSE" = no ]
		then
			log_failure_msg "bootclean: Failure cleaning /var/lock."
		else
			log_action_end_msg 1 "bootclean: Failure cleaning /var/lock"
		fi
	}
	find . ! -type d -delete \
		|| { report_err ; return 1 ; }
	[ "$VERBOSE" = no ] || log_action_end_msg 0
	mkflagfile /var/lock/.clean || return 1
	return 0
}

clean_run() {
	if [ yes = "$RAMRUN" ] ; then
	    return 0
	fi

	cd /var/run || { log_action_end_msg 1 "bootclean: Could not cd to /var/run." ; return 1 ; }

	[ "$VERBOSE" = no ] || log_action_begin_msg "Cleaning /var/run"
	report_err()
	{
		if [ "$VERBOSE" = no ]
		then
			log_failure_msg "bootclean: Failure cleaning /var/run."
		else
			log_action_end_msg 1 "bootclean: Failure cleaning /var/run"
		fi
	}
	find . ! -xtype d ! -name utmp ! -name innd.pid -delete \
		|| { report_err ; return 1 ; }
	[ "$VERBOSE" = no ] || log_action_end_msg 0
	mkflagfile /var/run/.clean || return 1
	return 0
}

which find >/dev/null 2>&1 || exit 1
log_begin_msg "Cleaning up temporary files..."

# If there are flag files that have not been created by root
# then remove them
for D in /tmp /var/run /var/lock
do
	if [ -f $D/.clean ]
	then
		which stat >/dev/null 2>&1 && cleanuid="$(stat -c %u $D/.clean)"
		# Poor's man stat %u, since stat (and /usr) might not be
		# available in some bootup stages
		[ "$cleanuid" ] || cleanuid="$(find $D/.clean -printf %U)"
		[ "$cleanuid" ] || { log_failure_msg "bootclean: Could not stat '$D/.clean'." ; exit 1 ; }
		if [ "$cleanuid" -ne 0 ]
		then
			rm -f $D/.clean || { log_failure_msg "bootclean: Could not delete '$D/.clean'." ; exit 1 ; }
		fi
	fi
done

[ -f /tmp/.clean ] && [ -f /var/run/.clean ] && [ -f /var/lock/.clean ] && { log_end_msg 0 ; exit 0 ; }

ES=0
[ -d /tmp ] && ! [ -f /tmp/.clean ] && { clean_tmp || ES=1 ; }
[ -d /var/run ] && ! [ -f /var/run/.clean ] && { clean_run || ES=1 ; }
[ -d /var/lock ] && ! [ -f /var/lock/.clean ] && { clean_lock || ES=1 ; }
log_end_msg $ES
exit $ES
