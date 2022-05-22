#!/bin/sh
# test functionality with password length < 6
set -x
./test_cryptocopy -e -p "hello" in.test out.test
retval=$?
if test $retval != 0 ; then
	echo test_cryptocopy succeded: $retval, Password length should be greater than 6
else
	echo test_cryptocopy program succeeded
	exit 0
fi

