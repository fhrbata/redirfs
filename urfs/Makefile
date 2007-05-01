obj-m += urfs.o
urfs-objs := chrdev.o conn.o ufilter.o

KERNEL_PATH = "/lib/modules/$(shell uname -r)/build"

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
