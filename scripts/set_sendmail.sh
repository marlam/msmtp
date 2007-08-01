#! /bin/bash
# Created   : Tue 03 Jul 2007 11:54:53 PM EDT
# Modified  : Wed 04 Jul 2007 01:27:09 PM EDT
# Author    : Gautam Iyer <gi1242@users.sourceforge.net>
#
# Selects an msmtp account based on users current network. Type -h for a more
# detailed description.


#
# User settings
#

# Default setting used if the domain name can not be found, or if something goes
# wrong.
default='/usr/sbin/sendmail -oem -oi'

# Regexp matching the host name of the machine this script should run on. (Other
# machines get the default above).
run_hosts='^baradur$'

# The domain name is matched against the patterns in the array "patterns". If a
# match is found, the corresponding msmtp account (from the accounts array) is
# used. 
#
# Patterns are matched in the order they are defined. If no pattern matches,
# then the script produces no output.
#
# An account named "ssh" is special. It calls the function ssh_tunnel when such
# an account is selected.
#
# The following are the settings I use on my laptop.

# Use default account if we could not get the domain name.
accounts+=(default)
patterns+=('^$')

# Use account 'stanford' from within the Stanford.EDU domain.
accounts+=(stanford)
patterns+=('^Stanford\.EDU$')

# ri.cox.net seems to have firewalled port 25, so use ssh tunnelling in this
# domain. (The function ssh_tunnel (called automatically) sets up the tunnel)
accounts+=(ssh)
patterns+=('^ri\.cox\.net$')

# From outside the Stanford.EDU domain, use account 'roam' with Kerberos
# authentication. It involves typing my password once a day (when my kerberos
# tickets expire), but is faster than ssh tunneling. (This requires traffic
# through port 25 to not be firewalled)
accounts+=(roam)
patterns+=('.')

# Ignore case while matching.
shopt -s nocasematch

# Function called when account named "ssh" is used
function ssh_tunnel()
{
    # Kill an already running tunnel (connection might be inactive)
    pkill -f '^ssh.*8025:math:25'

    # Create a tunnel to mail server. Forward local port 8025 to remote 25
    ssh -N -f -L 8025:math:25 math &
}

#
# End user settings
#
# {{{1 Script Functions
function print_help()
{
    cat << 'EOF'
USAGE:
    set_sendmail.sh

DESCRIPTION:

    Selects an msmtp account, based on the current host's domain name. This is
    useful for laptop users who move the laptop between networks. Firewall
    settings of your ISP may render your default smtp service useless, and force
    you to use a different msmtp account. This script matches the domain name
    against a given set of regular expressions and sets the msmtp account based
    on that.

    The output of this script is suitable for use in the users .muttrc. For
    instance, this script can be called via

	set sendmail="`~/.mutt/set_sendmail.sh`"

    from the users ~/.muttrc.

    NOTE: The patterns, and msmtp accounts are written directly into the script,
    so edit the source file to define your own. Comments are provided.
EOF
    exit
}

# Check if a host is reachable
function check_host()
{
    if [[ $host_pkg == 'bind' ]]; then
	host $1 >& /dev/null
    elif [[ $host_pkg == 'hostx' ]]; then
	hostx -Q $1 >& /dev/null
    else
	# Fail
	return 1
    fi
}

# Function to get the domain name (in variable domainname).
function get_domainname()
{
    domainname=
    ipaddr=
    host_pkg=

    # We need either 'host' (from bind-tools) or 'hostx' to proceed.
    which host >& /dev/null && host_pkg='bind'
    [[ -z $host_pkg ]] && which hostx >& /dev/null && host_pkg='hostx'

    # See if the internet is up
    check_host whatismyip.org || return

    # Try and get domain name from /etc/resolv.conf.
    domainname=$(egrep -m1 '^(search|domain)' /etc/resolv.conf |	\
		    awk '{ print $2 }')
    [[ -n domainname ]] && return;

    # Get ip address
    #ipaddr=$(/sbin/ifconfig | grep 'inet addr:' | grep -v '127.0.0.1' | \
    #    	cut -d: -f2 | awk '{ print $1}')
    #ipaddr=$(w3m -dump whatismyip.org)
    ipaddr=$(wget -qO- http://whatismyip.org)
    [[ -z $ipaddr ]] && return

    if [[ $host_pkg == bind ]]; then
	domainname=$(host $ipaddr | sed -r 's/^.*pointer [^.]+\.//')
    elif [[ $host_pkg == hostx ]]; then
	domainname=$(hostx -Q $ipaddr | grep -m1 ^Name | sed -r 's/^[^.]+\.//')
    fi
}

# {{{1 Main script
(( $# )) && print_help

# If we can't (or shouldn't) msmtp, then print default and exit
if [[ ! $HOST =~ $run_hosts ]] || ! which msmtp >& /dev/null; then
    echo $default
    exit
fi

# Get the domain name
get_domainname
#echo "ipaddr=$ipaddr, domainname=$domainname"

# Decide which account to use
for ((i=0; i<${#accounts[*]}; i++ )); do
    if [[ $domainname =~ ${patterns[$i]} ]]; then
	[[ ${accounts[$i]} == ssh ]] && ssh_tunnel
	echo "$(which msmtp) -a ${accounts[$i]}"
	break
    fi
done
