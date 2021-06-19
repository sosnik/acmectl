#!/usr/bin/env bash

# acme-hooked - a script to issue TLS certificates via ACME
# Copyright (C) 2015-2021 The acme-hooked authors.
# Licensed under the MIT license, see LICENSE.

# This script updates an NSD DNS zone file to include ACME challenges. It makes
# the following assumption: all _acme-challenge DNS records are CNAME'd to a
# single _acme-challenge DNS record in a single zone. It is therefore enough to
# add all ACME challenges to this single zone file.
#
# dependencies: sed -i, awk, grep, dig (for checks)

# change this to appropriate values for your setting
declare -r ZONEFILE="/path/to/zonefile"
declare -r NAMESERVER="yournameserver.example.com"
declare -r CHECKTIMEOUT=600 # seconds

die()
{
	echo "$@"
	exit 1
}

update_serial()
{
	date="$(date +%Y%m%d)"
	serial="$(awk '/serial/ {print $1}' "${ZONEFILE}")"
	serialdate="${serial::-2}"
	if [[ "$serialdate" == "$date" ]]; then
		newserial=$(expr ${serial} + 1)
	else
		newserial="${date}00"
	fi
	sed -i "s/${serial}/${newserial}/" "${ZONEFILE}" || die "Could not edit zone file"
}

update_zone()
{
	update_serial
	nsd-control reload >/dev/null || die "Could not reload nsd zone files"
}

setup()
{
	domain="$1"
	token="$2"
	content="$3"

	# add challenge for the given domain
	echo "_acme-challenge IN TXT \"${content}\" ; ${domain}" >> "${ZONEFILE}"
}

activate()
{
	# make challenge(s) accessible to ACSD server
	update_zone
}

check()
{
	domain="$1"
	token="$2"
	content="$3"

	# check that challenge is ready for the ACSD server
	# waiting for the challenge to become ready should be done here
	# exit with 0 if check succeeds, otherwise != 0
	timeout=${CHECKTIMEOUT}
	while [[ timeout -gt 0 ]]; do
		entry="$(dig @${NAMESERVER} -t txt "_acme-challenge.${domain}." | grep "${content}")"
		[[ -z ${entry} ]] || break
		timeout=$(($timeout - 3))
		sleep 3
	done
	[[ ${timeout} -gt 0 ]] || die 'Check did not finish successfully within the timeout!'
}

remove()
{
	domain="$1"
	token="$2"
	content="$3"

	# remove the challenges for the given domain
	sed -i "/${content}/d" "${ZONEFILE}" || die "Could not edit zone file"
}

finish()
{
	# finalize cleanup after all challenges are removed
	update_zone
}

write()
{
	csrfile="$1"

	# read certificate from stdin and process it
	# any output of this function is echoed by acme_hooked
	crtfile="${csrfile%.csr}.crt"
	cat > "${crtfile}"
}

[[ $# -ge 1 ]] || die 'Missing arguments.'
if [[ "$1" == 'setup' ]]; then
	[[ $# == 4 ]] || die 'Wrong number of arguments.'
	setup "$2" "$3" "$4"
elif [[ "$1" == 'activate' ]]; then
	[[ $# == 1 ]] || die 'Wrong number of arguments.'
	activate
elif [[ "$1" == 'check' ]]; then
	[[ $# == 4 ]] || die 'Wrong number of arguments.'
	check "$2" "$3" "$4"
elif [[ "$1" == 'remove' ]]; then
	[[ $# == 4 ]] || die 'Wrong number of arguments.'
	remove "$2" "$3" "$4"
elif [[ "$1" == 'finish' ]]; then
	[[ $# == 1 ]] || die 'Wrong number of arguments.'
	finish
elif [[ "$1" == 'write' ]]; then
	[[ $# == 2 ]] || die 'Wrong number of arguments.'
	write "$2"
else
	die "Unknown command: $1"
fi
