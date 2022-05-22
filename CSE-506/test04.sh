#!/bin/sh
# test functionality with missing outputfile name
set -x
./test_cryptocopy -c  in.test
retval=$?
if test $retval != 0 ; then
	echo test_cryptocopy succeded: $retval, expected for missing output file name
else
	echo test_cryptocopy program succeeded
	exit 0
fi

