#ifndef _REDIRFS_FILE_H
#define _REDIRFS_FILE_H

#include <linux/module.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include "root.h"

#define redirfs_fhash(ino) (ino % redirfs_fhash_table_size)

struct redirfs_file_t {
	struct hlist_node file_hash;
	struct list_head priv;
	struct list_head root;
	struct file *file;
	spinlock_t lock;
	atomic_t ref_cnt;
};

struct redirfs_file_t *redirfs_fget(struct redirfs_file_t *rfile);
void redirfs_fput(struct redirfs_file_t *rfile);
int __init redirfs_init_fhash_table(unsigned long size);
void redirfs_destroy_fhash_table(void);
void __init redirfs_init_fcache(void);
void redirfs_destroy_fcache(void);
int redirfs_add_file(struct redirfs_root_t *root, struct file *file);
void redirfs_remove_file(struct redirfs_root_t *root, struct file *file);
void redirfs_fhash_table_remove(struct redirfs_file_t *rfile);

#endif /* _REDIRFS_FILE_H */
