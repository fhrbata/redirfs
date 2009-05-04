/*
 * cipherflt - RedirFS cryptographic filter
 *
 * Written by Pavel Zuna <xzunap00@stud.fit.vutbr.cz>
 *
 */

#include "cipherflt.h"

redirfs_filter cipherflt;

enum redirfs_rv cipherflt_pre_d_iput(redirfs_context context,
		struct redirfs_args *args)
{
	struct inode *inode = args->args.d_iput.inode;

	cipherflt_inode_data_detach(inode);
	return REDIRFS_CONTINUE;
}

enum redirfs_rv cipherflt_pre_open(redirfs_context context,
		struct redirfs_args *args)
{
	struct cipherflt_inode_data *data;
	struct file *file = args->args.f_open.file;
	struct inode *inode = file->f_dentry->d_inode;
	int rv;

	data = cipherflt_inode_data_get(inode);
	if (data != NULL) {
		if (atomic_add_unless(&data->trailer_written, -1, 0)) {
			mutex_lock(&inode->i_mutex);
			i_size_write(inode, i_size_read(inode) - TRAILER_SIZE);
			mutex_unlock(&inode->i_mutex);
		}
		return REDIRFS_CONTINUE;
	}

	data = cipherflt_inode_data_alloc();
	if (IS_ERR(data)) {
		rv = PTR_ERR(data);
		printk(KERN_ERR FILTER_NAME
			": failed to allocate inode data: %d\n", rv);
		return REDIRFS_CONTINUE;
	}

	if (i_size_read(inode) == 0) {
		rv = cipherflt_trailer_generate_key(&data->trailer);
		if (rv) {
			printk(KERN_ERR FILTER_NAME
				": failed to generate key: %d\n", rv);
			goto error;
		}
	} else {
		rv = cipherflt_trailer_read(file, &data->trailer);
		if (rv) {
			printk(KERN_ERR FILTER_NAME
				": failed to read trailer: %d\n", rv);
			goto error;
		}
		if (!inode_data_is_encrypted(data)) {
			goto error;
		}
		mutex_lock(&inode->i_mutex);
		i_size_write(inode, i_size_read(inode) - TRAILER_SIZE);
		mutex_unlock(&inode->i_mutex);
	}
	
	cipherflt_inode_data_attach(inode, data);
	return REDIRFS_CONTINUE;
error:
	cipherflt_inode_data_free(&data->rfs_data);
	return REDIRFS_CONTINUE;
}

enum redirfs_rv cipherflt_post_release(redirfs_context context,
		struct redirfs_args *args)
{
	struct cipherflt_inode_data *data;
	struct file *file = args->args.f_release.file;
	struct inode *inode = file->f_dentry->d_inode;
	int rv;

	data = cipherflt_inode_data_get(inode);
	if (data == NULL)
		return REDIRFS_CONTINUE;

	if (atomic_add_unless(&data->trailer_written, 1, 1)) {
		rv = cipherflt_trailer_write(file, &data->trailer);
		if (rv) {
			printk(KERN_ERR FILTER_NAME
				": failed to write trailer: %d\n", rv);
		}
	}

	return REDIRFS_CONTINUE;
}

enum redirfs_rv cipherflt_pre_read(redirfs_context context,
		struct redirfs_args *args)
{
	struct cipherflt_inode_data *data;
	struct inode *inode = args->args.f_open.file->f_dentry->d_inode;
	struct completion *completion;
	int rv;

	data = cipherflt_inode_data_get(inode);
	if (data != NULL) {
		completion = &data->ciphering;
		do {
			rv = wait_for_completion_interruptible(completion);
		} while (rv == -ERESTARTSYS);
	}

	return REDIRFS_CONTINUE;
}

enum redirfs_rv cipherflt_pre_write(redirfs_context context,
		struct redirfs_args *args)
{
	struct cipherflt_inode_data *data;
	struct inode *inode = args->args.f_open.file->f_dentry->d_inode;
	struct completion *completion;
	int rv;

	data = cipherflt_inode_data_get(inode);
	if (data != NULL) {
		completion = &data->ciphering;
		do {
			rv = wait_for_completion_interruptible(completion);
		} while (rv == -ERESTARTSYS);
	}

	return REDIRFS_CONTINUE;
}

enum redirfs_rv cipherflt_pre_readpages(redirfs_context context,
		struct redirfs_args *args)
{
	struct cipherflt_context_data *cdata;
	struct cipherflt_inode_data *data;
	struct cipherflt_trailer *trailer;
	struct list_head *pages = args->args.a_readpages.pages;
	struct inode *inode = args->args.a_readpages.mapping->host;
	struct page *page;
	unsigned nr_pages = args->args.a_readpages.nr_pages;
	unsigned i;
	int rv;

	data = cipherflt_inode_data_get(inode);
	if (data == NULL)
		return REDIRFS_CONTINUE;
	trailer = &data->trailer;

	cdata = cipherflt_context_data_alloc(trailer);
	if (IS_ERR(cdata)) {
		rv = PTR_ERR(cdata);
		printk(KERN_INFO KERN_ERR
			": failed to initialize context data: %d\n", rv);
		return REDIRFS_CONTINUE;
	}

	for (i = 0; i < nr_pages; ++i) {
		page = list_entry(pages->prev, struct page, lru);
		rv = cipherflt_context_data_add_blocks(page, trailer, cdata);
		if (rv) {
			printk(KERN_INFO KERN_ERR
				": failed to add blocks: %d\n", rv);
		}
	}

	if (list_empty(cdata->blocks))
		goto error;

	rv = cipherflt_cipher_init(trailer, &cdata->desc);
	if (rv) {
		printk(KERN_INFO KERN_ERR
			": failed to initialize cipher: %d\n", rv);
		goto error;
	}

	redirfs_data_attach_context(cipherflt, context, &cdata->rfs_data);
	redirfs_put_data(&cdata->rfs_data);
	redirfs_put_data(&cdata->rfs_data);

	return REDIRFS_CONTINUE;
error:
	cipherflt_context_data_free(cdata);
	return REDIRFS_CONTINUE;
}

enum redirfs_rv cipherflt_post_readpages(redirfs_context context,
		struct redirfs_args *args)
{
	struct cipherflt_context_data *cdata;
	struct cipherflt_block *block;
	int rv;

	cdata = redirfs_detach_data_context(cipherflt, context);
	if (cdata == NULL)
		return REDIRFS_CONTINUE;

	list_for_each_entry(block, &cdata->blocks, blocks) {
		page = block->page;
	}

	return REDIRFS_CONTINUE;
}

enum redirfs_rv cipherflt_pre_writepages(redirfs_context context,
		struct redirfs_args *args)
{
	return REDIRFS_CONTINUE;
}

enum redirfs_rv cipherflt_post_writepages(redirfs_context context,
		struct redirfs_args *args)
{
	return REDIRFS_CONTINUE;
}

int cipherflt_unregister(void)
{
	int rv;

	redirfs_deactivate_filter(cipherflt);

	cipherflt_inode_data_cache_free();

	rv = redirfs_unregister_filter(cipherflt);
	if (rv) {
		printk(KERN_ERR FILTER_NAME
			": failed to unregister filter: %d\n", rv);
		return rv;
	}

	return 0;
}

static struct redirfs_filter_operations cipherflt_ops = {
	.unregister = cipherflt_unregister
};

static struct redirfs_filter_info cipherflt_info = {
	.owner = THIS_MODULE,
	.name = FILTER_NAME,
	.priority = FILTER_PRIORITY,
	.active = 1,
	.ops = &cipherflt_ops
};

static struct redirfs_op_info cipherflt_op_info[] = {
	{REDIRFS_REG_DOP_D_IPUT, cipherflt_pre_d_iput, NULL},
	{REDIRFS_REG_FOP_OPEN, cipherflt_pre_open, NULL},
	{REDIRFS_REG_FOP_RELEASE, NULL, cipherflt_post_release},
	{REDIRFS_REG_FOP_READ, cipherflt_pre_read, NULL},
	{REDIRFS_REG_FOP_WRITE, cipherflt_pre_write, NULL},
	{REDIRFS_REG_AOP_READPAGES, cipherflt_pre_readpages, NULL},
	{REDIRFS_REG_AOP_READPAGES, NULL, cipherflt_post_readpages},
	{REDIRFS_REG_AOP_WRITEPAGES, cipherflt_pre_writepages, NULL},
	{REDIRFS_REG_AOP_WRITEPAGES, NULL, cipherflt_post_writepages},
	{REDIRFS_OP_END, NULL, NULL}
};

static int __init cipherflt_init(void)
{
	int rv;

	cipherflt = redirfs_register_filter(&cipherflt_info);
	if (IS_ERR(cipherflt)) {
		rv = PTR_ERR(cipherflt);
		printk(KERN_ERR FILTER_NAME
			": failed to register filter: %d\n", rv);
		return rv;
	}

	rv = cipherflt_inode_data_cache_init();
	if (rv) {
		printk(KERN_ERR FILTER_NAME
			": failed to initialize inode data cache: %d\n", rv);
		goto error;
	}

	rv = redirfs_set_operations(cipherflt, cipherflt_op_info);
	if (rv) {
		printk(KERN_ERR FILTER_NAME
			": failed to set VFS operations: %d\n", rv);
		goto error;
	}

	printk(KERN_INFO
		"RedirFS cryptographic filter, version " FILTER_VERSION "\n");

	return 0;

error:
	if (cipherflt_unregister() != 0)
		return 0;
	redirfs_delete_filter(cipherflt);

	return rv;
}

static void __exit cipherflt_exit(void)
{
	printk(KERN_INFO FILTER_NAME
		": exiting...\n");

	cipherflt_unregister();
	redirfs_delete_filter(cipherflt);
}

module_init(cipherflt_init);
module_exit(cipherflt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pavel Zuna <xzunap00@stud.fit.vutbr.cz>");
MODULE_DESCRIPTION("RedirFS cryptographic filter, version " FILTER_VERSION);

/* end of file */

