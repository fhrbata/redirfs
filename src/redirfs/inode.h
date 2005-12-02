#ifndef _REDIRFS_INODE_H
#define _REDIRFS_INODE_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include "root.h"

#define redirfs_hash(ino) (ino % redirfs_ihash_size)

struct redirfs_inode_t {
	struct hlist_node inode_hash;
	struct list_head inode_root;
	struct list_head priv;
	struct redirfs_root_t *root;
	spinlock_t lock;
	struct super_block *sb;
	unsigned long ino;
};

int __init redirfs_init_ihash(unsigned int size);
void redirfs_destroy_ihash(void);
void __init redirfs_init_icache(void);
void redirfs_destroy_icache(void);
struct redirfs_inode_t *redirfs_iget(struct super_block *sb, unsigned long ino);
void redirfs_iput(struct redirfs_inode_t *inode);
void redirfs_idel(struct redirfs_inode_t *inode);
struct redirfs_inode_t *redirfs_alloc_inode(struct super_block *sb, unsigned long ino, struct redirfs_root_t *root);
void redirfs_free_inode(struct redirfs_inode_t *inode);
void redirfs_add_inode(struct redirfs_root_t *root, struct dentry *dentry);
void redirfs_remove_inode(struct redirfs_root_t *root, struct dentry *dentry);


#endif
