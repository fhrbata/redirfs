#ifndef _REDIRFS_INODE_H
#define _REDIRFS_INODE_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include "root.h"

#define redirfs_ihash(ino) (ino % redirfs_ihash_table_size)

struct redirfs_inode_t {
	struct hlist_node inode_hash;
	struct list_head priv;
	struct redirfs_root_t *root;
	spinlock_t lock;
	struct super_block *sb;
	unsigned long ino;
	unsigned int nlink;
	atomic_t ref_cnt;
};

int __init redirfs_init_ihash_table(unsigned int size);
void redirfs_destroy_ihash_table(void);
void __init redirfs_init_icache(void);
void redirfs_destroy_icache(void);
int redirfs_add_inode(struct redirfs_root_t *root, struct inode *inode);
void redirfs_remove_inode(struct inode *inode);
struct redirfs_inode_t *redirfs_iget(struct redirfs_inode_t *rinode);
void redirfs_iput(struct redirfs_inode_t *rinode);
void redirfs_ihash_table_remove(struct redirfs_inode_t *rinode);
struct redirfs_inode_t *redirfs_ifind(struct super_block *sb,
		unsigned long ino);

#endif

