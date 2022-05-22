#!/bin/sh
# test basic encrypt-decrypt functionality
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
./test_cryptocopy -d -p "Helloworld" out.test.1 in.test.2
if test $retval != 0 ; then
        echo test_cryptocopy failed with error: $retval
        exit $retval
else
        echo test_cryptocopy program succeeded: Successfully encrypted file
fi
# now verify that the two files are the same
if cmp in.test.2 in.test.1 ; then
	echo "test_cryptocopy: Successfully able to encrypt and decrypt file"
	exit 0
else
	echo "test_cryptocopy: input and output files contents DIFFER"
	exit 1
fi

/bin/rm -f in.test.2
/bin/rm -f in.test.1
/bin/rm -f out.test.1

