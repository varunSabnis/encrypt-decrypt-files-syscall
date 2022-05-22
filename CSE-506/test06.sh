#!/bin/sh
# test basic encrypt decrypt functionality with invalid password
set -x
/bin/rm -f out.test.1
/bin/rm -f in.test.1
/bin/rm -f in.test.2
echo dummy test > in.test.1
./test_cryptocopy -e -p "Helloworld" in.test.1 out.test.1
retval=$?
if test $retval != 0 ; then
	echo test_cryptocopy failed with error: $retval
	exit $retval
else
	echo test_cryptocopy program succeeded: Successfully encrypted file
fi
./test_cryptocopy -d -p "Helloworlder" out.test.1 in.test.2
retval=$?
if test $retval != 0 ; then
        echo test_cryptocopy succeded with error: $retval, Invalid password passed
        exit 0
else
        echo test_cryptocopy program succeeded: Successfully encrypted file
fi

/bin/rm -f out.test.1
/bin/rm -f in.test.1
/bin/rm -f in.test.2
