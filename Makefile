CFLAGS += -g
KDIR = /lib/modules/$(shell uname -r)/build

#obj-m += redirfs/ compflt/ crypto/
obj-m += compflt/ crypto/

#CFLAGS += -DCFLT_DEBUG

all:
	make -C ${KDIR} M=$(shell pwd) modules

install:
	make -C ${KDIR} M=$(shell pwd) modules_install

clean:
	make -C ${KDIR} M=$(shell pwd) clean
