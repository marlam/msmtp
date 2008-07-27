#!/usr/bin/env bash
# Created   : Tue 03 Jul 2007 11:54:53 PM EDT
# Modified  : Thu 13 Sep 2007 06:35:56 AM PDT
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
# Script uses bash-3.2. Exit if bash version is lower.
if (( BASH_VERSINFO[0] < 3 || BASH_VERSINFO[1] < 2 )); then
    echo $default
    exit
fi

# {{{1 Script Functions
function debug()
{
    [[ -n $verbose ]] && echo -e "\033[31m$*\033[m" >> /dev/stderr
}

function print_usage()
{
    echo "USAGE:"
    echo "    set_sendmail.sh [-v] -c config_file"
    echo "    set_sendmail.sh -h"
}

function print_help()
{
    print_usage

    cat << 'EOF'

DESCRIPTION:

    Selects an msmtp account, based on the current host's domain name. This is
    useful for laptop users who move the laptop between networks. Firewall
    settings of your ISP may render your default smtp service useless, and force
    you to use a different msmtp account. This script first matches
    /etc/resolv.conf against a given set of (egrep) regular expressions. If a
    match is found, it is used to decide which msmtp account to use.
    
    If no match is found, this script tries to get the domain name. (NOTE: This
    can be time consuming, as it could involve a name server lookup). The domain
    name is then matched against a given set of (bash) regular expressions the
    msmtp account is selected based on that.

    The output of this script is suitable for use in the users .muttrc. For
    instance, this script can be called via

	set sendmail="`~/.mutt/set_sendmail.sh -c ~/.mutt/set_sendmail.conf`"

    from the users ~/.muttrc.

    The patterns, and msmtp accounts should be provided in the config file, and
    are "sourced" directly into the script. Use bash compatible syntax, and look
    at the example.
EOF
    exit
}

# Check if a host is reachable
function check_host()
{
    debug "Checking for host $1"
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
    debug "Getting domain name"

    domainname=
    ipaddr=
    host_pkg=

    if [[ -n $DNSDOMAIN ]]; then
	domainname=$DNSDOMAIN
	return
    fi

    # We need either 'host' (from bind-tools) or 'hostx' to proceed.
    which hostx >& /dev/null && host_pkg='hostx'
    [[ -z $host_pkg ]] && which host >& /dev/null && host_pkg='bind'
    debug "Using host package '$host_pkg'"

    # See if the internet is up
    check_host whatismyip.org || return

    # Try and get domain name from /etc/resolv.conf.
    # 2007-07-10: If a vpn connection is active, then it usually adds the
    # private search domain as the last field.
    domainname=$(egrep -m1 '^(search|domain)' /etc/resolv.conf |	\
		    awk '{ print $NF }')
    debug "Got domain '$domainname' from /etc/resolv.conf"
    [[ -n $domainname ]] && return;

    # Get ip address
    #ipaddr=$(/sbin/ifconfig | grep 'inet addr:' | grep -v '127.0.0.1' | \
    #    	cut -d: -f2 | awk '{ print $1}')
    #ipaddr=$(w3m -dump whatismyip.org)
    ipaddr=$(wget -qO- http://whatismyip.org)
    debug "Got IP address '$ipaddr'"
    [[ -z $ipaddr ]] && return

    if [[ $host_pkg == bind ]]; then
	domainname=$(host $ipaddr | sed -r 's/^.*pointer [^.]+\.(.*)\.$/\1/')
    elif [[ $host_pkg == hostx ]]; then
	domainname=$(hostx -Q $ipaddr | grep -m1 ^Name | sed -r 's/^[^.]+\.//')
    fi
    debug "Got domain name '$domainname'"
}

function do_account()
{
    local account=$1

    [[ $account == ssh ]] && ssh_tunnel
    echo "$(which msmtp) -a $account"
    
    exit 0
}

# {{{1 Main script
while getopts "hvc:" OPT; do
    case $OPT in
	"c") configFile=${OPTARG};;
	"v") verbose=1;;
	"h") print_help;;

	"?") print_usage; exit;;
    esac
done

if [[ -z $configFile || ! -r $configFile ]]; then
    print_usage
    exit
fi
source $configFile

# If we can't (or shouldn't) msmtp, then print default and exit
if [[ ! $HOSTNAME =~ $run_hosts ]] || ! which msmtp >& /dev/null; then
    echo $default
    exit
fi

# See if we can decide on the account based on /etc/resolv.conf
debug "Getting account from /etc/resolv.conf"
for ((i=0; i<${#accounts[*]}; i++ )); do
    if [[ -n ${resolv_regexp[$i]} ]]; then
	regexp=${resolv_regexp[$i]}
	if [[ ${regexp:0:1} != '!' ]]; then
	    egrep -q $regexp /etc/resolv.conf && do_account ${accounts[$i]}
	else
	    egrep -q ${regexp:1} /etc/resolv.conf || do_account ${accounts[$i]}
	fi
    fi
done

# Get the domain name
get_domainname
#echo "ipaddr=$ipaddr, domainname=$domainname."

# Decide which account to use
debug "Getting account from domainname ($domainname)"
for ((i=0; i<${#accounts[*]}; i++ )); do
    if [[ $domainname =~ ${dom_regexp[$i]} ]]; then
	do_account ${accounts[$i]}
    fi
done
