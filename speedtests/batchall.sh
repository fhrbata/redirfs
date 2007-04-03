#!/bin/bash

./batch.sh chardev 1000000
./batch.sh netlink 1000000
./batch.sh procfs 1000000
#./batch.sh relay 1000000
./batch.sh syscall 1000000
./batch.sh sysfs 1000000
