#!/bin/sh
# test functionality with missing password
set -x
./test_cryptocopy -e in.test out.test
retval=$?
if test $retval != 0 ; then
	echo test_cryptocopy succeded: $retval, expected for missing password
else
	echo test_cryptocopy program succeeded
	exit 0
fi

