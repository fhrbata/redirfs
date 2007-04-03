CC = gcc

all: syscall_test procfs_test sysfs_test netlink_test chardev_test relay_test

stopwatch.o: stopwatch.c
	$(CC) -o $@ $^ -c -Wall

briefing.o: briefing.c
	$(CC) -o $@ $^ -c -Wall -D__SHORT_BRIEFING

syscall_test: stopwatch.o briefing.o syscall_test.c
	$(CC) -o $@ $^ -Wall

procfs_test: stopwatch.o briefing.o procfs_test.c
	$(CC) -o $@ $^ -Wall

sysfs_test: stopwatch.o briefing.o sysfs_test.c
	$(CC) -o $@ $^ -Wall

netlink_test: stopwatch.o briefing.o netlink_test.c
	$(CC) -o $@ $^ -Wall

chardev_test: stopwatch.o briefing.o chardev_test.c
	$(CC) -o $@ $^ -Wall

relay_test: stopwatch.o briefing.o relay_test.c
	$(CC) -o $@ $^ -Wall

clean: 
	rm -f *.o *~ *_test
