CFLAGS += -g
KDIR = /lib/modules/$(shell uname -r)/build
MISC = test

#obj-m += redirfs/ compflt/ crypto/
obj-m += compflt/ crypto/

#CFLAGS += -DCOMPFLT_DEBUG

all:
	make -C ${KDIR} M=$(shell pwd) modules
	@for subdir in ${MISC}; do \
		(make -C $$subdir) \
	done

install:
	make -C ${KDIR} M=$(shell pwd) modules_install

clean:
	make -C ${KDIR} M=$(shell pwd) clean
	@for subdir in ${MISC}; do \
		(make -C $$subdir clean) \
	done
