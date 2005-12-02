obj-m += redirfs.o
redirfs-y := operations.o filter.o root.o redir.o inode.o file.o proc.o

ifdef DEBUG
EXTRA_CFLAGS := -DREDIRFS_DEBUG=1
endif
