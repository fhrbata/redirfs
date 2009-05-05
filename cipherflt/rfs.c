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

int decrypt_already_read_pages(struct cipherflt_inode_data *data,
		struct address_space *mapping)
{
	struct cipherflt_trailer *trailer = &data->trailer;
	struct cipherflt_block *block;
	struct cipherflt_block *tmp;
	struct blkcipher_desc desc;
	struct list_head blocks;
	struct pagevec pvec;
	struct inode *inode = mapping->host;
	unsigned int i;
	unsigned int p;
	unsigned nr_pages;
	int rv;

	printk(INFO "decrypt_already_read_pages\n");

	rv = cipherflt_cipher_init(trailer, &desc);
	if (rv) {
		printk(FAIL "initialize cipher: %d\n", rv);
		return rv;
	}

	INIT_LIST_HEAD(&blocks);

	pagevec_init(&pvec, 0);
	for (i = 0; i < mapping->nrpages; i += (PAGEVEC_SIZE)) {
		nr_pages = pagevec_lookup(&pvec, mapping, i, (PAGEVEC_SIZE));
		for (p = 0; p < nr_pages; ++p) {
			rv = cipherflt_block_add_blocks(pvec.pages[p], inode,
					trailer->block_size, trailer->iv_size,
					&desc, &blocks);
			if (rv)
				printk(FAIL "add blocks: %d\n", rv);
		}
		pagevec_release(&pvec);
	}

	list_for_each_entry(block, &blocks, blocks) {
		rv = cipherflt_cipher_decrypt(block->page, block->iv,
				trailer->iv_size, block->len, block->offset,
				&desc);
		if (rv)
			printk(FAIL "decrypt block: %d\n", rv);
	}

	list_for_each_entry_safe(block, tmp, &blocks, blocks) {
		cipherflt_block_free(block);
	}

	return 0;
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
		printk(FAIL "allocate inode data: %d\n", rv);
		return REDIRFS_CONTINUE;
	}

	if (i_size_read(inode) == 0) {
		rv = cipherflt_trailer_generate_key(&data->trailer);
		if (rv) {
			printk(FAIL "generate key: %d\n", rv);
			goto error;
		}
	} else {
		rv = cipherflt_trailer_read(file, &data->trailer);
		if (rv) {
			printk(FAIL "read trailer: %d\n", rv);
			goto error;
		}
		printk(INFO "hypa megha pic-hovinah!\n");
		if (!inode_data_is_encrypted(data))
			goto error;

		mutex_lock(&inode->i_mutex);
		i_size_write(inode, i_size_read(inode) - TRAILER_SIZE);
		mutex_unlock(&inode->i_mutex);

		rv = decrypt_already_read_pages(data, inode->i_mapping);
		if (rv)
			printk(FAIL "decrypt pages: %d\n", rv);
	}
	
	cipherflt_inode_data_attach(inode, data);
	return REDIRFS_CONTINUE;
error:
	redirfs_put_data(&data->rfs_data);
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
		if (rv)
			printk(FAIL "write trailer: %d\n", rv);
	}

	return REDIRFS_CONTINUE;
}

enum redirfs_rv cipherflt_pre_read(redirfs_context context,
		struct redirfs_args *args)
{
	/*struct cipherflt_inode_data *data;
	struct inode *inode = args->args.f_open.file->f_dentry->d_inode;
	struct completion *completion;
	int rv;

	data = cipherflt_inode_data_get(inode);
	if (data != NULL) {
		completion = &data->ciphering;
		do {
			rv = wait_for_completion_interruptible(completion);
		} while (rv == -ERESTARTSYS);
	}*/

	return REDIRFS_CONTINUE;
}

enum redirfs_rv cipherflt_pre_write(redirfs_context context,
		struct redirfs_args *args)
{
	/*struct cipherflt_inode_data *data;
	struct inode *inode = args->args.f_open.file->f_dentry->d_inode;
	struct completion *completion;
	int rv;

	data = cipherflt_inode_data_get(inode);
	if (data != NULL) {
		completion = &data->ciphering;
		do {
			rv = wait_for_completion_interruptible(completion);
		} while (rv == -ERESTARTSYS);
	}*/

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
	int rv;

	data = cipherflt_inode_data_get(inode);
	if (data == NULL)
		return REDIRFS_CONTINUE;
	trailer = &data->trailer;

	cdata = cipherflt_context_data_alloc(trailer);
	if (IS_ERR(cdata)) {
		rv = PTR_ERR(cdata);
		printk(FAIL "allocate context data: %d\n", rv);
		return REDIRFS_CONTINUE;
	}

	list_for_each_entry(page, pages, lru) {
		rv = cipherflt_context_data_add_blocks(page, inode, cdata);
		if (rv)
			printk(FAIL "add blocks: %d\n", rv);
	}

	cipherflt_context_data_attach(context, cdata);
	if (list_empty(&cdata->blocks))
		cipherflt_context_data_detach(context);

	return REDIRFS_CONTINUE;
}

enum redirfs_rv cipherflt_post_readpages(redirfs_context context,
		struct redirfs_args *args)
{
	struct cipherflt_context_data *cdata;
	struct cipherflt_block *block;
	int rv;

	cdata = cipherflt_context_data_get(context);
	if (cdata == NULL)
		return REDIRFS_CONTINUE;

	list_for_each_entry(block, &cdata->blocks, blocks) {
		rv = cipherflt_cipher_decrypt(block->page, block->iv,
				cdata->iv_size, block->len, block->offset,
				&cdata->desc);
		if (rv)
			printk(FAIL "decrypt block: %d\n", rv);
	}

	cipherflt_context_data_detach(context);
	return REDIRFS_CONTINUE;
}

enum redirfs_rv cipherflt_pre_writepages(redirfs_context context,
		struct redirfs_args *args)
{
	struct cipherflt_context_data *cdata;
	struct cipherflt_inode_data *data;
	struct cipherflt_trailer *trailer;
	struct cipherflt_block *block;
	struct writeback_control *wbc = args->args.a_writepages.wbc;
	struct address_space *mapping = args->args.a_writepages.mapping;
	struct pagevec pvec;
	struct inode *inode = mapping->host;
	pgoff_t start;
	pgoff_t end;
	int nr_pages;
	int rv;
	int p;

	data = cipherflt_inode_data_get(inode);
	if (data == NULL)
		return REDIRFS_CONTINUE;
	trailer = &data->trailer;

	cdata = cipherflt_context_data_alloc(trailer);
	if (IS_ERR(cdata)) {
		rv = PTR_ERR(cdata);
		printk(FAIL "allocate context data: %d\n", rv);
		return REDIRFS_CONTINUE;
	}

	if (wbc->range_cyclic) {
		start = 0;
		end = -1;
	} else {
		start = wbc->range_start >> PAGE_CACHE_SHIFT;
		end = wbc->range_end >> PAGE_CACHE_SHIFT;
	}

	if (atomic_read(&data->trailer_written)) {
		mutex_lock(&inode->i_mutex);
		i_size_write(inode, i_size_read(inode) - TRAILER_SIZE);
		mutex_unlock(&inode->i_mutex);
	}

	pagevec_init(&pvec, 0);
	while (start < end) {
		nr_pages = pagevec_lookup_tag(&pvec, mapping, &start,
			PAGECACHE_TAG_DIRTY,
			min(end - start, (pgoff_t) (PAGEVEC_SIZE - 1)) + 1);
		if (nr_pages == 0)
			break;
		for (p = 0; p < nr_pages; ++p) {
			rv = cipherflt_block_add_blocks(pvec.pages[p], inode,
					trailer->block_size, trailer->iv_size,
					&cdata->desc, &cdata->blocks);
			if (rv)
				printk(FAIL "add blocks: %d\n", rv);
		}
		pagevec_release(&pvec);
	}

	if (atomic_read(&data->trailer_written)) {
		mutex_lock(&inode->i_mutex);
		i_size_write(inode, i_size_read(inode) + TRAILER_SIZE);
		mutex_unlock(&inode->i_mutex);
	}

	list_for_each_entry(block, &cdata->blocks, blocks) {
		rv = cipherflt_cipher_encrypt(block->page, block->iv,
				trailer->iv_size, block->len, block->offset,
				&cdata->desc);
		if (rv)
			printk(FAIL "encrypt block: %d\n", rv);
	}

	cipherflt_context_data_attach(context, cdata);
	if (list_empty(&cdata->blocks))
		cipherflt_context_data_detach(context);

	args->args.a_writepages.wbc->sync_mode = WB_SYNC_ALL;

	return REDIRFS_CONTINUE;
}

enum redirfs_rv cipherflt_post_writepages(redirfs_context context,
		struct redirfs_args *args)
{

	struct cipherflt_context_data *cdata;
	struct cipherflt_block *block;
	int rv;

	cdata = cipherflt_context_data_get(context);
	if (cdata == NULL)
		return REDIRFS_CONTINUE;

	list_for_each_entry(block, &cdata->blocks, blocks) {
		if (PageWriteback(block->page))
			wait_on_page_writeback(block->page);
		rv = cipherflt_cipher_decrypt(block->page, block->iv,
				cdata->iv_size, block->len, block->offset,
				&cdata->desc);
		if (rv)
			printk(FAIL "decrypt block: %d\n", rv);
	}

	cipherflt_context_data_detach(context);
	return REDIRFS_CONTINUE;
}

int cipherflt_unregister(void)
{
	int rv;

	redirfs_deactivate_filter(cipherflt);

	cipherflt_block_cache_free();
	cipherflt_inode_data_cache_free();

	rv = redirfs_unregister_filter(cipherflt);
	if (rv) {
		printk(FAIL "unregister filter: %d\n", rv);
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
	{REDIRFS_REG_AOP_READPAGES, cipherflt_pre_readpages,
			cipherflt_post_readpages},
	{REDIRFS_REG_AOP_WRITEPAGES, cipherflt_pre_writepages,
			cipherflt_post_writepages},
	{REDIRFS_OP_END, NULL, NULL}
};

static int __init cipherflt_init(void)
{
	int rv;

	printk(KERN_INFO
		"RedirFS cryptographic filter, version " FILTER_VERSION "\n");

	cipherflt = redirfs_register_filter(&cipherflt_info);
	if (IS_ERR(cipherflt)) {
		rv = PTR_ERR(cipherflt);
		printk(FAIL "register filter: %d\n", rv);
		return rv;
	}

	rv = cipherflt_inode_data_cache_init();
	if (rv) {
		printk(FAIL "initialize inode data cache: %d\n", rv);
		goto error;
	}

	rv = cipherflt_block_cache_init();
	if (rv) {
		printk(FAIL "initialize block cache: %d\n", rv);
		goto error;
	}

	rv = redirfs_set_operations(cipherflt, cipherflt_op_info);
	if (rv) {
		printk(FAIL "set VFS operations: %d\n", rv);
		goto error;
	}

	return 0;

error:
	if (cipherflt_unregister() != 0)
		return 0;
	redirfs_delete_filter(cipherflt);

	return rv;
}

static void __exit cipherflt_exit(void)
{
	printk(INFO "exiting...\n");

	cipherflt_unregister();
	redirfs_delete_filter(cipherflt);
}

module_init(cipherflt_init);
module_exit(cipherflt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pavel Zuna <xzunap00@stud.fit.vutbr.cz>");
MODULE_DESCRIPTION("RedirFS cryptographic filter, version " FILTER_VERSION);

/* end of file */

