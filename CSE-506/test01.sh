#!/bin/sh
# test basic copy functionality
set -x
/bin/rm -f out.test
/bin/rm -f in.test
echo dummy test > in.test
./test_cryptocopy -c in.test out.test
retval=$?
if test $retval != 0 ; then
	echo test_cryptocopy failed with error: $retval
	exit $retval
else
	echo test_cryptocopy program succeeded
fi
# now verify that the two files are the same
if cmp in.test out.test ; then
	echo "test_cryptocopy: input and output files contents are the same"
	exit 0
else
	echo "test_cryptocopy: input and output files contents DIFFER"
	exit 1
fi

/bin/rm -f out.test
/bin/rm -f in.test

