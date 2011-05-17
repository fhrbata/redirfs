#!/bin/bash

# ROOT

modprobe redirfs
modprobe unionflt
echo "a:i:/mnt/union" > /sys/fs/redirfs/filters/unionflt/paths
echo "a:1:/home/petr/skola/BP/sandbox/high" > /sys/fs/redirfs/filters/unionflt/umounts/union/branches 
echo "a:1:/home/petr/skola/BP/sandbox/low" > /sys/fs/redirfs/filters/unionflt/umounts/union/branches 

echo "Union mount established!\n"

cat /mnt/union/dir1/dir2/dir3/dir4/dir5/searched
