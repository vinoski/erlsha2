#!/usr/bin/env sh

CONFIG_HDR=$1

set -e

tmpfile=`mktemp /tmp/erlsha2.XXXXXX`
tmpcfile=${tmpfile}.c
trap "rm -f $tmpfile $tmpcfile" EXIT
mv $tmpfile $tmpcfile
echo '#include <stdint.h>' > $tmpcfile
if $CC $CFLAGS -c -o /dev/null $tmpcfile 2>/dev/null ; then
    echo '#define HAVE_STDINT_H 1' > $CONFIG_HDR
else
    echo '#include <inttypes.h>' > $tmpcfile
    if $CC $CFLAGS -c -o /dev/null $tmpcfile 2>/dev/null ; then
        echo '#define HAVE_INTTYPES_H 1' > $CONFIG_HDR
    else
        echo 'neither <stdint.h> nor <inttypes.h> found, aborting' 1>&2
        exit 1
    fi
fi

v='16#12345678'
prog="case <<$v:32/native>> of <<$v:32/big>> -> 0; <<$v:32/little>> -> 1 end"
if erl -noinput -noshell -eval "halt($prog)."; then
    echo '#define WORDS_BIGENDIAN 1' >> $CONFIG_HDR
else
    echo '#undef WORDS_BIGENDIAN' >> $CONFIG_HDR
fi

exit 0
