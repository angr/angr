#
# Functions used by several mount* scripts in initscripts package
#
# Sourcer must source /lib/lsb/init-functions.sh

# $1: directory
is_empty_dir() {
	for FILE in $1/* $1/.*
	do
		case "$FILE" in
		  "$1/.*") return 0 ;;
		  "$1/*"|"$1/."|"$1/..") continue ;;
		  *) return 1 ;;
		esac
	done
	return 0
}


selinux_enabled () {
	which selinuxenabled >/dev/null 2>&1 && selinuxenabled
}


# Called before mtab is writable to mount kernel and device file systems.
# $1: file system type
# $2: alternative file system type (or empty string if none)
# $3: mount point
# $4: mount device name
# $5... : extra mount program options
domount () {
	MTPT="$3"
	KERNEL="$(uname -s)"
	# Figure out filesystem type
	FSTYPE=
	if [ "$1" = proc ]
	then
		case "$KERNEL" in
			Linux|GNU) FSTYPE=proc ;;
			*FreeBSD)  FSTYPE=linprocfs ;;
			*)         FSTYPE=procfs ;;
		esac
	elif [ "$1" = tmpfs ]
	then # always accept tmpfs, to mount /lib/init/rw before /proc
		FSTYPE=$1
	elif grep -E -qs "$1\$" /proc/filesystems
	then
		FSTYPE=$1
	elif grep -E -qs "$2\$" /proc/filesystems
	then
		FSTYPE=$2
	fi

	if [ ! "$FSTYPE" ]
	then
		if [ "$2" ]
		then
			log_warning_msg "Filesystem types '$1' and '$2' are not supported. Skipping mount."
		else
			log_warning_msg "Filesystem type '$1' is not supported. Skipping mount."
		fi
		return
	fi

	# We give file system type as device name if not specified as
	# an argument
	if [ "$4" ] ; then
	    DEVNAME=$4
	else
	    DEVNAME=$FSTYPE
	fi

	# Get the options from /etc/fstab.
	OPTS=
	if [ -f /etc/fstab ]
	then
		exec 9<&0 </etc/fstab

		while read TAB_DEV TAB_MTPT TAB_FSTYPE TAB_OPTS TAB_REST
		do
			case "$TAB_DEV" in (""|\#*) continue ;; esac
			[ "$MTPT" = "$TAB_MTPT" ] || continue
			[ "$FSTYPE" = "$TAB_FSTYPE" ] || continue
			case "$TAB_OPTS" in
			  noauto|*,noauto|noauto,*|*,noauto,*)
				exec 0<&9 9<&-
				return
				;;
			  ?*)
				OPTS="-o$TAB_OPTS"
				;;
			esac
			break
		done

		exec 0<&9 9<&-
	fi

	if [ ! -d "$MTPT" ]
	then
		log_warning_msg "Mount point '$MTPT' does not exist. Skipping mount."
		return
	fi

	if mountpoint -q "$MTPT"
	then
		return # Already mounted
	fi

	if [ "$VERBOSE" != "no" ]; then
		is_empty_dir "$MTPT" >/dev/null 2>&1 || log_warning_msg "Files under mount point '$MTPT' will be hidden."
	fi
	mount -n -t $FSTYPE $5 $OPTS $DEVNAME $MTPT
	if [ "$FSTYPE" = "tmpfs" -a -x /sbin/restorecon ]; then
		/sbin/restorecon $MTPT
	fi
}

#
# Preserve /var/run and /var/lock mountpoints
#
pre_mountall ()
{
	# We may end up mounting something over top of /var, either directly
	# or because /var is a symlink to something that's mounted.  So keep
	# copies of the /var/run and /var/lock mounts elsewhere on the root
	# filesystem so they can be moved back.
	if [ yes = "$RAMRUN" ] ; then
		mkdir /lib/init/rw/var.run
		mount -n --bind /var/run /lib/init/rw/var.run
	fi
	if [ yes = "$RAMLOCK" ] ; then
		mkdir /lib/init/rw/var.lock
		mount -n --bind /var/lock /lib/init/rw/var.lock
	fi
}

#
# Restore /var/run and /var/lock mountpoints if something was mounted
# as /var/.  Avoid mounting them back over themselves if nothing was
# mounted as /var/ by checking if /var/run/ and /var/lock/ are still
# mount points.  Enabling RAMRUN and RAMLOCK while listing /var/run or
# /var/lock in /etc/fstab is not supported.
#
post_mountall ()
{
	if [ yes = "$RAMRUN" ] ; then
		[ -d /var/run ] || mkdir /var/run
		if mountpoint -q /var/run ; then
			umount /lib/init/rw/var.run
		else
			mount -n --move /lib/init/rw/var.run /var/run
		fi
		rmdir /lib/init/rw/var.run
	fi
	if [ yes = "$RAMLOCK" ] ; then
		[ -d /var/lock ] || mkdir /var/lock
		if mountpoint -q /var/lock ; then
			umount /lib/init/rw/var.lock
		else
			mount -n --move /lib/init/rw/var.lock /var/lock
		fi
		rmdir /lib/init/rw/var.lock
	fi
}
