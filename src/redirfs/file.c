#include <linux/slab.h>
#include "file.h"
#include "root.h"
#include "debug.h"

static struct hlist_head *redirfs_fhash_table;
static spinlock_t redirfs_fhash_table_lock = SPIN_LOCK_UNLOCKED;
static unsigned long redirfs_fhash_table_size;
static kmem_cache_t *redirfs_fcache;

struct redirfs_file_t *redirfs_fget(struct redirfs_file_t *rfile)
{
	BUG_ON(!atomic_read(&rfile->ref_cnt));
	atomic_inc(&rfile->ref_cnt);
	return rfile;
}

void redirfs_fput(struct redirfs_file_t *rfile)
{
	if (atomic_dec_and_test(&rfile->ref_cnt))
		kmem_cache_free(redirfs_fcache, (void *)rfile);
}

static struct redirfs_file_t *redirfs_alloc_file(struct file *file)
{
	struct redirfs_file_t *rfile;


	rfile = kmem_cache_alloc(redirfs_fcache, SLAB_KERNEL);

	if (!rfile)
		return ERR_PTR(REDIRFS_ERR_NOMEM);

	INIT_HLIST_NODE(&rfile->file_hash);
	INIT_LIST_HEAD(&rfile->priv);
	INIT_LIST_HEAD(&rfile->root);
	rfile->file = file;
	atomic_set(&rfile->ref_cnt, 1);
	spin_lock_init(&rfile->lock);

	return rfile;
}

int __init redirfs_init_fhash_table(unsigned long size)
{
	int loop;


	redirfs_fhash_table_size = size;

	redirfs_fhash_table = kmalloc(sizeof(struct hlist_head) * size,
			GFP_KERNEL);

	if (!redirfs_fhash_table)
		return REDIRFS_ERR_NOMEM;

	for (loop = 0; loop < size; loop++)
		INIT_HLIST_HEAD(&redirfs_fhash_table[loop]);

	return 0;
}

void redirfs_destroy_fhash_table(void)
{
	kfree(redirfs_fhash_table);
}

static void redirfs_fhash_table_add(struct redirfs_file_t *rfile)
{
	unsigned long ino;
	struct hlist_head *head;


	ino = rfile->file->f_dentry->d_inode->i_ino;
	head =  redirfs_fhash_table + redirfs_fhash(ino);

	spin_lock(&redirfs_fhash_table_lock);
	hlist_add_head(&rfile->file_hash, head);
	spin_unlock(&redirfs_fhash_table_lock);
	redirfs_fget(rfile);
}

void redirfs_fhash_table_remove(struct redirfs_file_t *rfile)
{
	spin_lock(&redirfs_fhash_table_lock);
	if (!hlist_unhashed(&rfile->file_hash)) {
		hlist_del(&rfile->file_hash);
		INIT_HLIST_NODE(&rfile->file_hash);
		redirfs_fput(rfile);
	}
	spin_unlock(&redirfs_fhash_table_lock);
}

void __init redirfs_init_fcache(void)
{
	redirfs_fcache = kmem_cache_create("redirfs_fcache",
			sizeof(struct redirfs_file_t),
			0,
			SLAB_PANIC,
			NULL,
			NULL);
}

void redirfs_destroy_fcache(void)
{
	kmem_cache_destroy(redirfs_fcache);
}

static struct redirfs_file_t *redirfs_ffind(struct file *file)
{
	struct redirfs_file_t *res = NULL;
	struct redirfs_file_t *loop = NULL;
	struct hlist_head *head;
	struct hlist_node *pos;
	unsigned long ino;
	
	
	spin_lock(&redirfs_fhash_table_lock);

	ino = file->f_dentry->d_inode->i_ino;
	head = redirfs_fhash_table + redirfs_fhash(ino);

	hlist_for_each_entry(loop, pos, head, file_hash) {
		if (loop->file != file)
			continue;

		res = redirfs_fget(loop);
		break;
	}

	spin_unlock(&redirfs_fhash_table_lock);

	return res;
}

static void redirfs_attach_file(struct redirfs_root_t *root,
		struct redirfs_file_t *rfile)
{
	spin_lock(&root->lock);
	list_add(&rfile->root, &root->files);
	spin_unlock(&root->lock);
	redirfs_fget(rfile);
}

static void redirfs_detach_file(struct redirfs_root_t *root,
		struct redirfs_file_t *rfile)
{
	spin_lock(&root->lock);
	if (!list_empty(&rfile->root)) {
		list_del(&rfile->root);
		INIT_LIST_HEAD(&rfile->root);
		redirfs_fput(rfile);
	}
	spin_unlock(&root->lock);
}


int redirfs_add_file(struct redirfs_root_t *root, struct file *file)
{
	struct redirfs_file_t *rfile;


	rfile = redirfs_alloc_file(file);
	if (IS_ERR(rfile))
		return PTR_ERR(rfile);

	redirfs_fhash_table_add(rfile);
	redirfs_attach_file(root, rfile);
	redirfs_fput(rfile);

	return 0;
}

void redirfs_remove_file(struct redirfs_root_t *root, struct file *file)
{
	struct redirfs_file_t *rfile;


	rfile =  redirfs_ffind(file);
	if (!rfile)
		return;

	redirfs_fhash_table_remove(rfile);
	redirfs_detach_file(root, rfile);
	redirfs_fput(rfile);
}

