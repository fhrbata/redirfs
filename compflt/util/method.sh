#!/bin/sh

file=/proc/fs/compflt/method

if [ $# -eq 0 ]; then
        cat $file
else
        echo -n "${1}" > $file
fi
