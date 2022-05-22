#!/bin/sh
# test encrpyt with output file being hard link of input file 
set -x
/bin/rm -f in.test.1
/bin/rm -f out.test.1

echo dummy test > in.test.1
ln in.test.1 out.test.1
./test_cryptocopy -e -p "Helloworld" in.test.1 out.test.1
retval=$?
if test $retval != 0 ; then
	echo test_cryptocopy succeded: $retval, Cannot encrypt to hard link file of input file 
	exit 0
else
	echo test_cryptocopy program failed: Encrypted output file which is hard link of input file
fi

/bin/rm -f in.test.1
/bin/rm -f out.test.1
