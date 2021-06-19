#!/usr/bin/env bash

# acme-hooked - a script to issue TLS certificates via ACME
# Copyright (C) 2015-2021 The acme-hooked authors.
# Licensed under the MIT license, see LICENSE.

# <ADD SCRIPT DESCRIPTION HERE>
#
# dependencies: <ADD DEPENDENCIES HERE>


die()
{
	echo "$@"
	exit 1
}

setup()
{
	domain="$1"
	token="$2"
	content="$3"

	# add challenge for the given domain
}

activate()
{
	# make challenge(s) accessible to ACSD server
}

check()
{
	domain="$1"
	token="$2"
	content="$3"

	# check that challenge is ready for the ACSD server
	# waiting for the challenge to become ready should be done here
	# exit with 0 if check succeeds, otherwise != 0
}

remove()
{
	domain="$1"
	token="$2"
	content="$3"
	
	# remove the challenges for the given domain
}

finish()
{
	# finalize cleanup after all challenges are removed
}

write()
{
	csrfile="$1"

	# read certificate from stdin and process it
	# any output of this function is echoed by acme_hooked
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
