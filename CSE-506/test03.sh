#!/bin/sh
# test functionality with invalid option
set -x
./test_cryptocopy -c -m in.test out.test
retval=$?
if test $retval != 0 ; then
	echo test_cryptocopy succeded: $retval, expected for invalid args
else
	echo test_cryptocopy program succeeded
	exit 0
fi

