/*
 * cipherflt - RedirFS cryptographic filter
 *
 * Written by Pavel Zuna <xzunap00@stud.fit.vutbr.cz>
 *
 */

#include "cipherflt.h"

struct cipherflt_context_data *cipherflt_context_data_alloc(
		struct cipherflt_trailer *trailer)
{
	struct cipherflt_context_data *data;
	int rv;

	printk(INFO "cipherflt_context_data_alloc\n");

	data = kzalloc(sizeof (struct cipherflt_context_data), GFP_KERNEL);
	if (data == NULL)
		return ERR_PTR(-ENOMEM);

	rv = redirfs_init_data(&data->rfs_data, cipherflt,
			cipherflt_context_data_free, NULL);
	if (rv)
		goto error;

	rv = cipherflt_cipher_init(trailer, &data->desc);
	if (rv)
		goto error;

	INIT_LIST_HEAD(&data->blocks);
	data->block_size = trailer->block_size;
	data->iv_size = trailer->iv_size;

	return data;
error:
	kfree(data);
	return ERR_PTR(rv);
}

int cipherflt_context_data_add_blocks(struct page *page, struct inode *inode,
		struct cipherflt_context_data *data)
{
	int rv;

	printk(INFO "cipherflt_context_data_add_blocks\n");

	rv = cipherflt_block_add_blocks(page, inode, data->block_size,
			data->iv_size, &data->desc, &data->blocks);
	return rv;
}

void cipherflt_context_data_attach(redirfs_context context,
		struct cipherflt_context_data *data)
{
	printk(INFO "cipherflt_context_data_attach\n");

	redirfs_attach_data_context(cipherflt, context, &data->rfs_data);
	redirfs_put_data(&data->rfs_data);
	redirfs_put_data(&data->rfs_data);
}

struct cipherflt_context_data *cipherflt_context_data_get(
		redirfs_context context)
{
	struct redirfs_data *rfs_data;

	printk(INFO "cipherflt_context_data_get\n");

	rfs_data = redirfs_get_data_context(cipherflt, context);
	if (rfs_data == NULL)
		return NULL;
	redirfs_put_data(rfs_data);
	return rfs_to_context_data(rfs_data);
}

void cipherflt_context_data_detach(redirfs_context context)
{
	struct redirfs_data *rfs_data;

	printk(INFO "cipherflt_context_data_detach\n");

	rfs_data = redirfs_detach_data_context(cipherflt, context);
	if (rfs_data)
		redirfs_put_data(rfs_data);
}

void cipherflt_context_data_free(struct redirfs_data *rfs_data)
{
	struct cipherflt_context_data *data = rfs_to_context_data(rfs_data);
	struct cipherflt_block *block;
	struct cipherflt_block *tmp;

	printk(INFO "cipherflt_context_data_free\n");

	list_for_each_entry_safe(block, tmp, &data->blocks, blocks) {
		cipherflt_block_free(block);
	}

	cipherflt_cipher_free(&data->desc);
	kfree(data);
}

/* end of file */

