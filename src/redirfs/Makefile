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
redirfs-objs := rfs_fst.o rfs_path.o rfs_root.o rfs_info.o rfs_file.o \
	rfs_dentry.o rfs_inode.o rfs_dcache.o rfs_chain.o rfs_ops.o \
	rfs_flt.o rfs_sysfs.o rfs.o

redirfs.ko: *.c *.h
	$(MAKE) -C $(KERN_SRC) SUBDIRS=$(RFS_SRC) modules

.PHONY: clean
clean:
	$(MAKE) -C $(KERN_SRC) SUBDIRS=$(RFS_SRC) clean

