#!/bin/sh

file=/proc/fs/compflt/stat
tmpf=/tmp/compflt_stat
cp $file $tmpf

awk -- '
/^[^[]/ {
        compt=$3+$5;
	ratio=100 - compt/$4*100;
        print "<" $1 ">" "\t" $2 "\t" $4 " -> " compt "\t(" ratio "%)";
}
' $tmpf
