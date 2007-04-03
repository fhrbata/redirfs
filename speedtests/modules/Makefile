obj-m += procfs_test.o sysfs_test.o netlink_test.o chardev_test.o relay_test.o

KERNEL_PATH = /usr/src/linux

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
