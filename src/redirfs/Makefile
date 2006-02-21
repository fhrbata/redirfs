RFS_SRC=$(PWD)
KERN_SRC="/lib/modules/$(shell uname -r)/build"
KERN_VER=$(shell uname -r | cut -c-3)

ifneq "$(KERN_VER)" "2.6"
fail:
	@echo "Just 2.6 kernel is supported for now!";
	@exit
endif
	
obj-m += redirfs.o
redirfs-y := operations.o filter.o root.o redir.o inode.o file.o proc.o

redirfs.ko:
	$(MAKE) -C $(KERN_SRC) M=$(RFS_SRC)

.PHONY: clean
clean:
	$(MAKE) -C $(KERN_SRC) M=$(RFS_SRC) clean
