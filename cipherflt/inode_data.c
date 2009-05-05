/*
 * cipherflt - RedirFS cryptographic filter
 *
 * Written by Pavel Zuna <xzunap00@stud.fit.vutbr.cz>
 *
 */

#include "cipherflt.h"

static struct kmem_cache *cipherflt_inode_data_cache;
struct list_head cipherflt_inode_list;
spinlock_t cipherflt_inode_list_lock;

int cipherflt_inode_data_cache_init(void)
{
	printk(INFO "cipherflt_inode_data_cache_init\n");

	cipherflt_inode_data_cache =
		kmem_cache_create("cipherflt_inode_data_cache",
				sizeof (struct cipherflt_inode_data),
				0, 0, NULL);
	if (cipherflt_inode_data_cache == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&cipherflt_inode_list);
	spin_lock_init(&cipherflt_inode_list_lock);

	return 0;
}

struct cipherflt_inode_data *cipherflt_inode_data_alloc(void)
{
	struct cipherflt_inode_data *data;
	int err;

	printk(INFO "cipherflt_inode_data_alloc\n");

	data = kmem_cache_alloc(cipherflt_inode_data_cache, GFP_KERNEL);
	if (data == NULL)
		return ERR_PTR(-ENOMEM);

	err = redirfs_init_data(&data->rfs_data, cipherflt,
			cipherflt_inode_data_free, NULL);
	if (err) {
		kmem_cache_free(cipherflt_inode_data_cache, data);
		return ERR_PTR(err);
	}

	data->host = NULL;
	atomic_set(&data->trailer_written, 0);
	cipherflt_trailer_init(&data->trailer);
	init_completion(&data->ciphering);
	complete_all(&data->ciphering);

	spin_lock(&cipherflt_inode_list_lock);
	list_add(&data->inodes, &cipherflt_inode_list);
	spin_unlock(&cipherflt_inode_list_lock);

	return data;
}

void cipherflt_inode_data_attach(struct inode *inode,
		struct cipherflt_inode_data *data)
{
	printk(INFO "cipherflt_inode_data_attach\n");

	BUG_ON(inode == NULL);
	BUG_ON((data == NULL) || (IS_ERR(data)));

	data->host = inode;
	redirfs_attach_data_inode(cipherflt, inode, &data->rfs_data);
	redirfs_put_data(&data->rfs_data);
	redirfs_put_data(&data->rfs_data);
}

struct cipherflt_inode_data *cipherflt_inode_data_get(struct inode *inode)
{
	struct redirfs_data *rfs_data;

	printk(INFO "cipherflt_inode_data_get\n");

	rfs_data = redirfs_get_data_inode(cipherflt, inode);
	if (rfs_data == NULL)
		return NULL;
	redirfs_put_data(rfs_data);
	return rfs_to_inode_data(rfs_data);
}

void cipherflt_inode_data_detach(struct inode *inode)
{
	struct redirfs_data *rfs_data;

	printk(INFO "cipherflt_inode_data_detach\n");

	BUG_ON(inode == NULL);

	rfs_data = redirfs_detach_data_inode(cipherflt, inode);
	if (rfs_data)
		redirfs_put_data(rfs_data);
}

void cipherflt_inode_data_free(struct redirfs_data *rfs_data)
{
	struct cipherflt_inode_data *data = rfs_to_inode_data(rfs_data);

	printk(INFO "cipherflt_inode_data_free\n");

	spin_lock(&cipherflt_inode_list_lock);
	list_del(&data->inodes);
	spin_unlock(&cipherflt_inode_list_lock);

	cipherflt_trailer_free(&data->trailer);

	kmem_cache_free(cipherflt_inode_data_cache, data);
}

void cipherflt_inode_data_cache_free(void)
{
	struct cipherflt_inode_data *data;
	struct cipherflt_inode_data *tmp;

	printk(INFO "cipherflt_inode_data_cache_free\n");

	if (cipherflt_inode_data_cache == NULL)
		return;

	list_for_each_entry_safe(data, tmp, &cipherflt_inode_list, inodes) {
		cipherflt_inode_data_detach(data->host);
	}

	kmem_cache_destroy(cipherflt_inode_data_cache);
	cipherflt_inode_data_cache = NULL;
}

/* end of file */

