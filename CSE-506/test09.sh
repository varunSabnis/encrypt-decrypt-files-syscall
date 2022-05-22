#!/bin/sh
# test encrpyt with input file absent
set -x
/bin/rm -f in.test.1
/bin/rm -f out.test.1
./test_cryptocopy -e -p "Helloworld" in.test.1 out.test.1
retval=$?
if test $retval != 0 ; then
	echo test_cryptocopy succeded: $retval, Cannot encrypt a file that does not exist
	exit 0
else
	echo test_cryptocopy program failed
fi
