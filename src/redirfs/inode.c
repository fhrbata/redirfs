#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include "inode.h"
#include "debug.h"

static struct hlist_head *redirfs_ihash_table;
static spinlock_t redirfs_ihash_table_lock = SPIN_LOCK_UNLOCKED;
static int redirfs_ihash_table_size;
static kmem_cache_t *redirfs_icache;

struct redirfs_inode_t *redirfs_iget(struct redirfs_inode_t *rinode)
{
	redirfs_debug("started");

	BUG_ON(!atomic_read(&rinode->ref_cnt));

	atomic_inc(&rinode->ref_cnt);

	redirfs_debug("ended");

	return rinode;
}

void redirfs_iput(struct redirfs_inode_t *rinode)
{
	redirfs_debug("started");

	if (atomic_dec_and_test(&rinode->ref_cnt))
	{
		redirfs_rput(rinode->root);
		kmem_cache_free(redirfs_icache, (void *)rinode);
	}

	redirfs_debug("ended");
}

static struct redirfs_inode_t *redirfs_alloc_inode(struct super_block *sb, 
		unsigned long ino, struct redirfs_root_t *parent)
{
	struct redirfs_inode_t *rinode;

	redirfs_debug("started");

	rinode = kmem_cache_alloc(redirfs_icache, SLAB_KERNEL);

	if (!rinode)
		return ERR_PTR(-ENOMEM);

	INIT_HLIST_NODE(&rinode->inode_hash);
	INIT_LIST_HEAD(&rinode->priv);
	rinode->sb = sb;
	rinode->ino = ino;
	rinode->root = redirfs_rget(parent);
	rinode->nlink = 1;
	atomic_set(&rinode->ref_cnt, 1);
	spin_lock_init(&rinode->lock);

	redirfs_debug("ended");

	return rinode;
}

int __init redirfs_init_ihash_table(unsigned int size)
{
	int loop;


	redirfs_debug("started");

	redirfs_ihash_table_size = size;

	redirfs_ihash_table = kmalloc(sizeof(struct hlist_head) * redirfs_ihash_table_size, GFP_KERNEL);
	if (!redirfs_ihash_table)
		return -ENOMEM;

	for (loop = 0; loop < redirfs_ihash_table_size; loop++)
		INIT_HLIST_HEAD(&redirfs_ihash_table[loop]);

	redirfs_debug("ended");

	return 0;
}

void redirfs_destroy_ihash_table(void)
{
	redirfs_debug("started");
	kfree(redirfs_ihash_table);
	redirfs_debug("ended");
}

static struct redirfs_inode_t *__redirfs_ifind(struct super_block *sb, unsigned long ino)
{
	struct redirfs_inode_t *res = NULL;
	struct redirfs_inode_t *loop = NULL;
	struct hlist_head *head = redirfs_ihash_table + redirfs_ihash(ino);
	struct hlist_node *pos;


	redirfs_debug("started");

	hlist_for_each_entry(loop, pos, head, inode_hash) {
		if (loop->ino != ino)
			continue;
		if (loop->sb != sb)
			continue;

		res = redirfs_iget(loop);
		break;
	}

	redirfs_debug("ended");

	return res;
}

struct redirfs_inode_t *redirfs_ifind(struct super_block *sb, unsigned long ino)
{
	struct redirfs_inode_t *rinode;


	redirfs_debug("started");

	spin_lock(&redirfs_ihash_table_lock);

	rinode = __redirfs_ifind(sb, ino);

	spin_unlock(&redirfs_ihash_table_lock);

	redirfs_debug("ended");

	return rinode;
}


static void redirfs_ihash_table_add(struct redirfs_inode_t *rinode)
{
	struct hlist_head *head;
	struct redirfs_inode_t *rinode_new;


	redirfs_debug("started");

	redirfs_debug("ref_cnt: %d", atomic_read(&rinode->ref_cnt));
	spin_lock(&redirfs_ihash_table_lock);

	rinode_new = __redirfs_ifind(rinode->sb, rinode->ino);
	if (rinode_new) {
		spin_lock(&rinode->lock);
		spin_lock(&rinode_new->lock);

		if (rinode_new->root != rinode->root)
			BUG();

		spin_unlock(&rinode->lock);
		spin_unlock(&rinode_new->lock);

		redirfs_iput(rinode_new);

		goto ret;
	}

	head = redirfs_ihash_table + redirfs_ihash(rinode->ino);
	redirfs_debug("ref_cnt: %d", atomic_read(&rinode->ref_cnt));
	redirfs_iget(rinode);
	hlist_add_head(&rinode->inode_hash, head);
ret:
	spin_unlock(&redirfs_ihash_table_lock);

	redirfs_debug("ended");
}

void redirfs_ihash_table_remove(struct redirfs_inode_t *rinode)
{
	redirfs_debug("started");

	spin_lock(&redirfs_ihash_table_lock);
	hlist_del(&rinode->inode_hash);
	spin_unlock(&redirfs_ihash_table_lock);
	redirfs_iput(rinode);

	redirfs_debug("ended");
}

void __init redirfs_init_icache(void)
{
	redirfs_debug("started");

	redirfs_icache = kmem_cache_create("redirfs_icache",
			sizeof(struct redirfs_inode_t),
			0,
			SLAB_PANIC,
			NULL,
			NULL);

	redirfs_debug("ended");
}

void redirfs_destroy_icache(void)
{
	redirfs_debug("started");
	kmem_cache_destroy(redirfs_icache);
	redirfs_debug("ended");
}

int redirfs_add_inode(struct redirfs_root_t *root, struct inode *inode)
{
	struct redirfs_inode_t *rinode;
	int unhashed = 0;


	redirfs_debug("started");

	rinode = redirfs_ifind(inode->i_sb, inode->i_ino);


	if (!rinode) {
		rinode = redirfs_alloc_inode(inode->i_sb, inode->i_ino, root);
		redirfs_debug("ref_cnt: %d", atomic_read(&rinode->ref_cnt));

		if (IS_ERR(rinode)) 
			return PTR_ERR(rinode);

		redirfs_ihash_table_add(rinode);

	} else {
		spin_lock(&rinode->lock);
		if (rinode->root != root) {
			redirfs_rput(rinode->root);
			rinode->root = redirfs_rget(root);
			spin_unlock(&rinode->lock);
		} else {
			rinode->nlink++;
			if (hlist_unhashed(&rinode->inode_hash))
				unhashed = 1;
			spin_unlock(&rinode->lock);
			if (unhashed)
				redirfs_ihash_table_add(rinode);
		}
	}

	redirfs_iput(rinode);

	redirfs_debug("ended");

	return 0;
}

void redirfs_remove_inode(struct inode *inode)
{
	struct redirfs_inode_t *rinode;


	redirfs_debug("started");

	rinode = redirfs_ifind(inode->i_sb, inode->i_ino);
	if (rinode) {
		spin_lock(&rinode->lock);
		rinode->nlink--;
		if (!rinode->nlink) {
			redirfs_ihash_table_remove(rinode);
			INIT_HLIST_NODE(&rinode->inode_hash);
		}
		spin_unlock(&rinode->lock);
		redirfs_iput(rinode);
	}

	redirfs_debug("ended");
}

