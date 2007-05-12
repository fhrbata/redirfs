CFLAGS += -g
KDIR = /lib/modules/$(shell uname -r)/build

obj-m += compflt/ crypto/

ifdef CFLT_DEBUG
CFLAGS += -DCFLT_DEBUG
endif

all:
	make -C ${KDIR} M=$(shell pwd) modules

install:
	make -C ${KDIR} M=$(shell pwd) modules_install

clean:
	make -C ${KDIR} M=$(shell pwd) clean
