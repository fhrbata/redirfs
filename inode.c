#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include "inode.h"

static struct hlist_head *redirfs_ihash;
spinlock_t redirfs_ihash_lock = SPIN_LOCK_UNLOCKED;
static int redirfs_ihash_size;
static kmem_cache_t *redirfs_icache;

static void redirfs_init_inode(void *foo, kmem_cache_t *cache, unsigned long flags)
{
	struct redirfs_inode_t *inode = (struct redirfs_inode_t *)foo;


	if (flags & SLAB_CTOR_CONSTRUCTOR) {
		INIT_HLIST_NODE(&inode->inode_hash);
		INIT_LIST_HEAD(&inode->inode_root);
		INIT_LIST_HEAD(&inode->priv);
		inode->sb = NULL;
		inode->lock = SPIN_LOCK_UNLOCKED;
	}
}

struct redirfs_inode_t *redirfs_alloc_inode(struct super_block *sb, unsigned long ino, struct redirfs_root_t *root)
{
	struct redirfs_inode_t *inode;

	inode = kmem_cache_alloc(redirfs_icache, SLAB_KERNEL);

	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->sb = sb;
	inode->ino = ino;
	inode->root = root;

	return inode;
}

void redirfs_free_inode(struct redirfs_inode_t *inode)
{
	hlist_del(&inode->inode_hash);
	kmem_cache_free(redirfs_icache, (void *)inode);
}

int __init redirfs_init_ihash(unsigned int size)
{
	int loop;


	redirfs_ihash_size = size;

	redirfs_ihash = kmalloc(sizeof(struct hlist_head) * redirfs_ihash_size, GFP_KERNEL);
	if (!redirfs_ihash)
		return -ENOMEM;

	for (loop = 0; loop < redirfs_ihash_size; loop++)
		INIT_HLIST_HEAD(&redirfs_ihash[loop]);

	return 0;
}

void redirfs_destroy_ihash(void)
{
	kfree(redirfs_ihash);
}

struct redirfs_inode_t *redirfs_iget(struct super_block *sb, unsigned long ino)
{
	struct redirfs_inode_t *res = NULL;
	struct redirfs_inode_t *loop = NULL;
	struct hlist_head *head = redirfs_ihash + redirfs_hash(ino);
	struct hlist_node *pos;


	hlist_for_each_entry(loop, pos, head, inode_hash) {
		if (loop->ino != ino)
			continue;
		if (loop->sb != sb)
			continue;

		res = loop;
		break;
	}

	return res;
}

void redirfs_iput(struct redirfs_inode_t *inode)
{
	struct hlist_head *head = redirfs_ihash + redirfs_hash(inode->ino);

	hlist_add_head(&inode->inode_hash, head);
}

void redirfs_idel(struct redirfs_inode_t *inode)
{
	hlist_del(&inode->inode_hash);
}

void __init redirfs_init_icache(void)
{
	redirfs_icache = kmem_cache_create("redirfs_icache",
			sizeof(struct redirfs_inode_t),
			0,
			SLAB_PANIC,
			redirfs_init_inode,
			NULL);
}

void redirfs_destroy_icache(void)
{
	kmem_cache_destroy(redirfs_icache);
}

void redirfs_add_inode(struct redirfs_root_t *root, struct dentry *dentry)
{
	struct redirfs_inode_t *inode;


	spin_lock(&redirfs_ihash_lock);
	spin_lock(&root->lock);

	inode = redirfs_iget(dentry->d_inode->i_sb, dentry->d_inode->i_ino);
	if (!inode) {
		inode = redirfs_alloc_inode(dentry->d_inode->i_sb, dentry->d_inode->i_ino, root);
		if (!inode)
			BUG_ON(!inode);
		redirfs_iput(inode);
		list_add(&inode->inode_root, &root->inodes);

	} else {
		list_move(&inode->inode_root, &root->inodes);
		inode->root = root;
	}

	spin_unlock(&root->lock);
	spin_unlock(&redirfs_ihash_lock);
}

void redirfs_remove_inode(struct redirfs_root_t *root, struct dentry *dentry)
{
	struct redirfs_inode_t *inode;


	spin_lock(&redirfs_ihash_lock);
	spin_lock(&root->lock);

	inode = redirfs_iget(dentry->d_inode->i_sb, dentry->d_inode->i_ino);
	if (inode) {
		list_del(&inode->inode_root);
		redirfs_free_inode(inode);
	}

	spin_unlock(&root->lock);
	spin_unlock(&redirfs_ihash_lock);
}
