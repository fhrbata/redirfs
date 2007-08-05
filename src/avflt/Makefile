RFS_SRC=$(PWD)
KERN_SRC="/lib/modules/$(shell uname -r)/build"
KERN_VER=$(shell uname -r | cut -c-3)

ifneq "$(KERN_VER)" "2.6"
fail:
	@echo "Just 2.6 kernel is supported for now!";
	@exit
endif

obj-m += avflt.o
avflt-objs := avflt_rfs.o avflt_sys.o avflt_dev.o avflt_mod.o avflt_check.o

avflt.ko: *.c
	$(MAKE) -C $(KERN_SRC) SUBDIRS=$(RFS_SRC) modules

.PHONY: clean
clean:
	$(MAKE) -C $(KERN_SRC) SUBDIRS=$(RFS_SRC) clean
