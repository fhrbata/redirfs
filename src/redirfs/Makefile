RFS_SRC=$(PWD)
KERN_SRC="/lib/modules/$(shell uname -r)/build"
KERN_VER=$(shell uname -r | cut -c-3)

ifneq "$(KERN_VER)" "2.6"
fail:
	@echo "Just 2.6 kernel is supported for now!";
	@exit
endif

ifdef RFS_DEBUG
EXTRA_CFLAGS += -DRFS_DEBUG
endif

obj-m += redirfs.o
redirfs-objs := path.o rdentry.o rinode.o redir.o rfile.o chain.o filter.o ops.o proc.o redirctl.o

redirfs.ko: *.c *.h
	$(MAKE) -C $(KERN_SRC) SUBDIRS=$(RFS_SRC) modules

.PHONY: clean
clean:
	$(MAKE) -C $(KERN_SRC) SUBDIRS=$(RFS_SRC) clean
