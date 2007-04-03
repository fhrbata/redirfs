#!/bin/bash

MINSIZE=64
let MAXSIZE=1024*128*8*4+1

if [ "$1" != chardev -a "$1" != netlink -a "$1" != procfs -a "$1" != relay -a "$1" != syscall -a "$1" != sysfs ];
then
  echo "usage: $0 [chardev/netlink/procfs/relay/syscall/sysfs] [num of iter]"
  exit
fi

if [ "$1" != syscall ];
then
  cd modules/
  insmod $1_test.ko
  cd ..
fi

mkdir -p results
rm -fr results/$1_*_$2.results

cd userspace

if [ "$1" != relay ];
then 
  ./$1_test latency $2 >> ../results/$1_latency_$2.results

  echo "read"
  ITER=$2
  SIZE=$MINSIZE
  while [ $SIZE -lt $MAXSIZE ]; do
    echo "size $SIZE, iter $ITER"
    ./$1_test read $ITER $SIZE >> ../results/$1_read_$2.results
    let SIZE=SIZE*2 
#    let ITER=(ITER/5)*4 
  done
  
  echo "write"
  ITER=$2
  SIZE=$MINSIZE
  while [ $SIZE -lt $MAXSIZE ]; do
    echo "size $SIZE, iter $ITER"
    ./$1_test write $ITER $SIZE >> ../results/$1_write_$2.results
    let SIZE=SIZE*2
#    let ITER=(ITER/5)*4 
  done
else
  ITER=$2
  SIZE=$MINSIZE
  while [ $SIZE -lt $MAXSIZE ]; do
    echo "size $SIZE, iter $ITER"
    ./$1_test $ITER $SIZE >> ../results/$1_read_$2.results
    let SIZE=SIZE*2 
#    let ITER=(ITER/5)*4 
  done
fi

if [ "$1" != syscall ];
then
  rmmod $1_test
fi

COUNT=0
while [ $COUNT -lt 4 ]; do
  echo -e "\007" >/dev/tty10
  sleep 0.15
  let COUNT=COUNT+1 
done
echo "$1 $2 done"
