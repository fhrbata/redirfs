/*
 * rwtestflt - redirfs read/write test filter
 */

#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/scatterlist.h>
#include <linux/writeback.h>
#include <linux/list.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>

#include <redirfs.h>

#define RWTESTFLT_VERSION "0.2"

#define TRAILER_MAGIC "cryptfltPZ"
#define TRAILER_KEY_FIELD_SIZE 64
#define TRAILER_SIZE ( \
	sizeof(TRAILER_MAGIC) - 1 + \
	sizeof(u8) + sizeof(u8) + sizeof(u16) + sizeof(u16) + \
	TRAILER_KEY_FIELD_SIZE \
	)

#define AES_KEY "\x06\xa9\x21\x40\x36\xb8\xa1\x5b" \
                "\x51\x2e\x03\xd5\x34\x12\x00\x06"
#define AES_IV  "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30" \
                "\xb4\x22\xda\x80\x2c\x9f\xac\x41"

struct rwtestflt_block {
	struct list_head blocks;
	struct page *page;
	char *iv;
	int start;
	int end;
};

struct rwtestflt_writepages_context_data {
	struct redirfs_data rfs_data;
	struct blkcipher_desc desc;
	struct list_head blocks;
};

struct rwtestflt_trailer {
	u8 version;
	u8 algorithm;
	u8 key_size;
	u8 iv_size;
	u16 block_size;
	char *key;
};

struct rwtestflt_inode_data {
	struct list_head inodes;
	spinlock_t struct_lock;
	spinlock_t inode_lock;
	atomic_t trailer_written;
	struct rwtestflt_trailer trailer;
};

#define rfs_to_context_data(ptr) \
	container_of(ptr, struct rwtestflt_context_data, rfs_data)

struct rwtestflt_context_data {
	struct redirfs_data rfs_data;
	struct blkcipher_desc desc;
	int len;
};

#define rfs_to_inode_data(ptr) \
	container_of(ptr, struct rwtestflt_inode_data, rfs_data)

struct rwtestflt_inode_data {
	struct redirfs_data rfs_data;
	struct rwtestflt_trailer *trailer;
};

static redirfs_filter rwtestflt;

static struct redirfs_filter_info rwtestflt_info = {
	.owner = THIS_MODULE,
	.name = "rwtestflt",
	.priority = 500000000,
	.active = 1
};

static void rwtestflt_context_data_free(struct redirfs_data *rfs_data)
{
	struct rwtestflt_context_data *data = rfs_to_context_data(rfs_data);
	printk(KERN_INFO "free context data\n");
	kfree(data);
}

static void rwtestflt_inode_data_free(struct redirfs_data *rfs_data)
{
	struct rwtestflt_inode_data *data = rfs_to_inode_data(rfs_data);
	printk(KERN_INFO "free inode data\n");
	if (data->trailer != NULL)
		kfree(data->trailer->key);
	kfree(data->trailer);
	kfree(data);
}

static struct rwtestflt_context_data *rwtestflt_context_data_alloc(void)
{
        struct rwtestflt_context_data *data;
        int err;

        data = kzalloc(sizeof(struct rwtestflt_context_data), GFP_KERNEL);
        if (!data)
                return ERR_PTR(-ENOMEM);

        err = redirfs_init_data(&data->rfs_data, rwtestflt,
			rwtestflt_context_data_free, NULL);
        if (err) {
                kfree(data);
                return ERR_PTR(err);
        }

        return data;
}

static struct rwtestflt_inode_data *rwtestflt_inode_data_alloc(void)
{
	struct rwtestflt_inode_data *data;
	int err;

	data = kzalloc(sizeof(struct rwtestflt_inode_data), GFP_KERNEL);
	if (data == NULL)
		return ERR_PTR(-ENOMEM);

	err = redirfs_init_data(&data->rfs_data, rwtestflt,
			rwtestflt_inode_data_free, NULL);
	if (err) {
		kfree(data);
		return ERR_PTR(err);
	}

	return data;
}

struct rwtestflt_trailer *rwtestflt_read_trailer(struct file *file)
{
	struct rwtestflt_trailer *trailer;
	mm_segment_t old_fs;
	loff_t offset;
	char buffer[TRAILER_SIZE];
	int rv;

	offset = file->f_dentry->d_inode->i_size;
	if (offset < TRAILER_SIZE)
		return NULL;
	offset -= TRAILER_SIZE;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	rv = file->f_op->read(file, buffer, TRAILER_SIZE, &offset);

	set_fs(old_fs);

	if (rv < TRAILER_SIZE)
		return NULL;
	if (memcmp(buffer, TRAILER_MAGIC, sizeof(TRAILER_MAGIC) - 1) != 0)
		return NULL;

	trailer = kzalloc(sizeof(struct rwtestflt_trailer), GFP_KERNEL);
	if (trailer == NULL)
		return ERR_PTR(-ENOMEM);

	offset = sizeof(TRAILER_MAGIC) - 1;
	memcpy(&trailer->version, buffer + offset, sizeof(u8));
	offset += sizeof(u8);
	memcpy(&trailer->algorithm, buffer + offset, sizeof(u8));
	offset += sizeof(u8);
	memcpy(&trailer->block_size, buffer + offset, sizeof(u16));
	offset += sizeof(u16);
	memcpy(&trailer->key_size, buffer + offset, sizeof(u16));

	/*if (trailer->key_size > TRAILER_KEY_FIELD_SIZE)
	{
		kfree(trailer);
		return NULL;
	}*/

	trailer->key = kzalloc(sizeof(struct rwtestflt_trailer), GFP_KERNEL);
	if (trailer->key == NULL)
	{
		kfree(trailer);
		return ERR_PTR(-ENOMEM);
	}

	offset += sizeof(u16);
	memcpy(trailer->key, buffer + offset, trailer->key_size);

	return trailer;
}

struct rwtestflt_trailer *rwtestflt_get_trailer(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct rwtestflt_inode_data *data;
	struct rwtestflt_trailer *trailer = NULL;
	struct redirfs_data *rfs_data;

	rfs_data = redirfs_get_data_inode(rwtestflt, inode);
	if (rfs_data != NULL)
	{
		redirfs_put_data(rfs_data);
		return rfs_to_inode_data(rfs_data)->trailer;
	}

	trailer = rwtestflt_read_trailer(file);
	if (trailer && !IS_ERR(trailer))
	{
		data = rwtestflt_inode_data_alloc();
		if (IS_ERR(data))
		{
			printk(KERN_ERR "rwtestflt: get_trailer OOM\n");
			kfree(trailer->key);
			kfree(trailer);
			return NULL;
		}
		data->trailer = trailer;
		redirfs_attach_data_inode(rwtestflt, inode, &data->rfs_data);
		redirfs_put_data(&data->rfs_data);
		redirfs_put_data(&data->rfs_data);
		printk(KERN_INFO "rwtestflt: attached data to inode\n");
	}

	return trailer;
}

enum redirfs_rv rwtestflt_open(redirfs_context context,
		struct redirfs_args *args)
{
	struct rwtestflt_trailer *trailer;
	struct file *file = args->args.f_open.file;

	if (IS_SYNC(file->f_dentry->d_inode))
		printk(KERN_INFO "rwtestflt: inode is sync!\n");

	trailer = rwtestflt_get_trailer(file);
	if (trailer != NULL)
	{
		printk(KERN_INFO "rwtestflt: %i\n", trailer->key_size);
	}

	printk(KERN_INFO "rwtestflt: file %s\n", file->f_dentry->d_name.name);

	printk(KERN_INFO "rwtestflt: open callback\n");
	return REDIRFS_CONTINUE;
}

enum redirfs_rv rwtestflt_read(redirfs_context context,
		struct redirfs_args *args)
{
	printk(KERN_INFO "rwtestflt: read callback\n");
	return REDIRFS_CONTINUE;
}

enum redirfs_rv rwtestflt_write(redirfs_context context,
		struct redirfs_args *args)
{
	struct file *file = args->args.f_write.file;
	struct address_space *mapping = file->f_mapping;
	struct dentry *dentry;
	struct pagevec pvec;
	int nr_pages;
	int i;

	printk(KERN_INFO "rwtestflt: write callback\n");
	list_for_each_entry(dentry, &mapping->host->i_dentry, d_alias) {
		printk(KERN_INFO "rwtestflt: file %s\n", dentry->d_name.name);
	}

	if (args->type.call == REDIRFS_PRECALL)
		printk(KERN_INFO "rwtestflt: write precall\n");
	else
		printk(KERN_INFO "rwtestflt: write postcall\n");

	pagevec_init(&pvec, 0);
	nr_pages = pagevec_lookup(&pvec, mapping, 0, 10);
	for (i = 0; i < nr_pages; ++i) {
		struct page *page = pvec.pages[i];
		struct buffer_head *head;
		struct buffer_head *bh;
		int buffer_count = 0;
		int dirty_buffer_count = 0;

		lock_page(page);
		if (PageDirty(page))
			printk(KERN_INFO "rwtestflt: page dirty!\n");
		if (PageUptodate(page))
			printk(KERN_INFO "rwtestflt: page uptodate!\n");
		if (PagePrivate(page)) {
			head = page_buffers(page);
			if (head) {
				for (bh = head; buffer_count == 0 || bh != head; bh = bh->b_this_page) {
					++buffer_count;
					if (buffer_dirty(bh))
						++dirty_buffer_count;
					if (buffer_req(bh))
						printk(KERN_INFO "rwtestflt: buffer req!\n");
				}
			}
			printk(KERN_INFO "rwtestflt: dirty buffer count %i/%i\n", dirty_buffer_count, buffer_count);
		}
		unlock_page(page);
	}
	pagevec_release(&pvec);

	return REDIRFS_CONTINUE;
}

enum redirfs_rv rwtestflt_write_begin(redirfs_context context,
		struct redirfs_args *args)
{
	struct file *file = args->args.a_write_begin.file;
	struct address_space *mapping = file->f_mapping;
	struct dentry *dentry;
	struct pagevec pvec;
	int unlock = 0;
	int nr_pages;
	int i;

	printk(KERN_INFO "rwtestflt: write_begin callback\n");
	list_for_each_entry(dentry, &mapping->host->i_dentry, d_alias) {
		printk(KERN_INFO "rwtestflt: file %s\n", dentry->d_name.name);
	}

	if (args->type.call == REDIRFS_PRECALL)
		printk(KERN_INFO "rwtestflt: write_begin precall\n");
	else
		printk(KERN_INFO "rwtestflt: write_begin postcall\n");

	pagevec_init(&pvec, 0);
	nr_pages = pagevec_lookup(&pvec, mapping, 0, 10);
	for (i = 0; i < nr_pages; ++i) {
		struct page *page = pvec.pages[i];
		struct buffer_head *head;
		struct buffer_head *bh;
		int buffer_count = 0;
		int dirty_buffer_count = 0;

		if (!PageLocked(page))
		{
			lock_page(page);
			unlock = 1;
		}
		if (PageDirty(page))
			printk(KERN_INFO "rwtestflt: page dirty!\n");
		if (PageUptodate(page))
			printk(KERN_INFO "rwtestflt: page uptodate!\n");
		if (PagePrivate(page)) {
			head = page_buffers(page);
			if (head) {
				for (bh = head; buffer_count == 0 || bh != head; bh = bh->b_this_page) {
					++buffer_count;
					if (buffer_dirty(bh))
						++dirty_buffer_count;
					if (buffer_req(bh))
						printk(KERN_INFO "rwtestflt: buffer req!\n");
				}
			}
			printk(KERN_INFO "rwtestflt: dirty buffer count %i/%i\n", dirty_buffer_count, buffer_count);
		}
		if (unlock)
		{
			unlock_page(page);
			unlock = 0;
		}
	}
	pagevec_release(&pvec);

	return REDIRFS_CONTINUE;
}

enum redirfs_rv rwtestflt_release(redirfs_context context,
		struct redirfs_args *args)
{
	struct inode *inode = args->args.f_release.inode;
	struct address_space *mapping = inode->i_mapping;
	struct dentry *dentry;
	struct pagevec pvec;
	int unlock = 0;
	int nr_pages;
	int i;

	printk(KERN_INFO "rwtestflt: release callback\n");
	list_for_each_entry(dentry, &inode->i_dentry, d_alias) {
		printk(KERN_INFO "rwtestflt: file %s\n", dentry->d_name.name);
	}

	if (args->type.call == REDIRFS_PRECALL)
		printk(KERN_INFO "rwtestflt: release precall\n");
	else
		printk(KERN_INFO "rwtestflt: release postcall\n");

	pagevec_init(&pvec, 0);
	nr_pages = pagevec_lookup(&pvec, mapping, 0, 10);
	for (i = 0; i < nr_pages; ++i) {
		struct page *page = pvec.pages[i];
		struct buffer_head *head;
		struct buffer_head *bh;
		int buffer_count = 0;
		int dirty_buffer_count = 0;

		if (!PageLocked(page))
		{
			lock_page(page);
			unlock = 1;
		}
		if (PageDirty(page))
			printk(KERN_INFO "rwtestflt: page dirty!\n");
		if (PageUptodate(page))
			printk(KERN_INFO "rwtestflt: page uptodate!\n");
		if (PagePrivate(page)) {
			head = page_buffers(page);
			if (head) {
				for (bh = head; buffer_count == 0 || bh != head; bh = bh->b_this_page) {
					++buffer_count;
					if (buffer_dirty(bh))
						++dirty_buffer_count;
					if (buffer_req(bh))
						printk(KERN_INFO "rwtestflt: buffer req!\n");
				}
			}
			printk(KERN_INFO "rwtestflt: dirty buffer count %i/%i\n", dirty_buffer_count, buffer_count);
		}
		if (unlock)
		{
			unlock_page(page);
			unlock = 0;
		}
	}
	pagevec_release(&pvec);

	return REDIRFS_CONTINUE;
}

enum redirfs_rv rwtestflt_write_end(redirfs_context context,
		struct redirfs_args *args)
{
	struct file *file = args->args.a_write_end.file;
	struct address_space *mapping = file->f_mapping;
	struct dentry *dentry;
	struct pagevec pvec;
	int unlock = 0;
	int nr_pages;
	int i;

	printk(KERN_INFO "rwtestflt: write_end callback\n");
	list_for_each_entry(dentry, &mapping->host->i_dentry, d_alias) {
		printk(KERN_INFO "rwtestflt: file %s\n", dentry->d_name.name);
	}

	if (args->type.call == REDIRFS_PRECALL)
		printk(KERN_INFO "rwtestflt: write_end precall\n");
	else
		printk(KERN_INFO "rwtestflt: write_end postcall\n");

	pagevec_init(&pvec, 0);
	nr_pages = pagevec_lookup(&pvec, mapping, 0, 10);
	for (i = 0; i < nr_pages; ++i) {
		struct page *page = pvec.pages[i];
		struct buffer_head *head;
		struct buffer_head *bh;
		int buffer_count = 0;
		int dirty_buffer_count = 0;

		if (!PageLocked(page))
		{
			lock_page(page);
			unlock = 1;
		}
		if (PageDirty(page))
			printk(KERN_INFO "rwtestflt: page dirty!\n");
		if (PageUptodate(page))
			printk(KERN_INFO "rwtestflt: page uptodate!\n");
		if (PagePrivate(page)) {
			head = page_buffers(page);
			if (head) {
				for (bh = head; buffer_count == 0 || bh != head; bh = bh->b_this_page) {
					++buffer_count;
					if (buffer_dirty(bh))
						++dirty_buffer_count;
					if (buffer_req(bh))
						printk(KERN_INFO "rwtestflt: buffer req!\n");
				}
			}
			printk(KERN_INFO "rwtestflt: dirty buffer count %i/%i\n", dirty_buffer_count, buffer_count);
		}
		if (unlock)
		{
			unlock_page(page);
			unlock = 0;
		}
	}
	pagevec_release(&pvec);

	return REDIRFS_CONTINUE;
}

enum redirfs_rv rwtestflt_readpage(redirfs_context context,
		struct redirfs_args *args)
{
	printk(KERN_INFO "rwtestflt: readpage callback\n");
	return REDIRFS_CONTINUE;
}

enum redirfs_rv rwtestflt_writepage(redirfs_context context,
		struct redirfs_args *args)
{
	struct rwtestflt_context_data *data;
	struct redirfs_data *rfs_data;
	struct crypto_blkcipher *tfm;
	struct scatterlist sg;
	// struct scatterlist so;
	struct page *page = args->args.a_writepage.page;
	struct inode *inode = page->mapping->host;
	// struct page *pago = NULL;
	// char *page_virt = NULL;
	// char *pago_virt = NULL;
	int len;
	int ret;

	struct buffer_head *head;
	struct buffer_head *bh;
	int buffer_count = 0;
	int dirty_buffer_count = 0;

	if (args->type.call == REDIRFS_PRECALL)
	{
		printk(KERN_INFO "rwtestflt: writepage precall\n");

		if (PageReclaim(page))
		{
			printk(KERN_INFO "rwtestflt: page reclaim!\n");
		}
		if (PageReferenced(page))
		{
			printk(KERN_INFO "rwtestflt: page referenced!\n");
		}
		if (PageMappedToDisk(page))
		{
			printk(KERN_INFO "rwtestlt: page is mapped to disk\n");
		}
		if (PageDirty(page))
		{
			printk(KERN_INFO "rwtestflt: page dirty!\n");
		}
		if (PageUptodate(page))
		{
			printk(KERN_INFO "rwtestflt: page uptodate!\n");
		}
		if (PagePrivate(page))
		{
			head = page_buffers(page);
			if (head)
			{
				for (	bh = head;
					buffer_count == 0 || bh != head;
					bh = bh->b_this_page)
				{
					++buffer_count;
					if (buffer_dirty(bh))
						++dirty_buffer_count;
					/*else
						set_buffer_dirty(bh);*/
					if (buffer_req(bh))
						printk(KERN_INFO "rwtestflt: buffer req\n");
					if (buffer_mapped(bh))
						printk(KERN_INFO "rwtestflt: buffer mapped\n");
					if (buffer_async_write(bh))
						printk(KERN_INFO "rwtestflt: buffer async write\n");
					if (buffer_delay(bh))
						printk(KERN_INFO "rwtestflt: buffer delay\n");
				}
			}
			if (head == head->b_this_page)
				printk(KERN_INFO "rwtestflt: only one buffer head? wtf!\n");
			printk(KERN_INFO "rwtestflt: dirty buffer count %i/%i\n",
					dirty_buffer_count, buffer_count);
		}

		data = rwtestflt_context_data_alloc();
		
		tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(tfm)) {
			printk(KERN_ERR "crypto_alloc_blkcipher\n");
			goto end;
		}
		data->desc.tfm = tfm;
		data->desc.flags = 0;

		ret = crypto_blkcipher_setkey(tfm, AES_KEY, 16);
		if (ret) {
			printk(KERN_ERR "crypto_blkcipher_setkey\n");
			goto error;
		}
		crypto_blkcipher_set_iv(tfm, AES_IV, 16);

		printk(KERN_INFO "rwtestflt: page index %li\n", page->index);
		printk(KERN_INFO "rwtestflt: page num %li\n", page->mapping->nrpages);
		printk(KERN_INFO "rwtestflt: file size %li\n", inode->i_size);

		if ((page->index + 1) >= page->mapping->nrpages)
			len = inode->i_size - page->index * (PAGE_SIZE);
		else
			len = (PAGE_SIZE);
		data->len = len;

		printk(KERN_INFO "rwtestflt: ciphering %i\n", len);

		// pago = alloc_page(GFP_KERNEL);

		// sg_set_page(&so, pago, len, 0);

		sg_set_page(&sg, page, len, 0);

		ret = crypto_blkcipher_encrypt(&data->desc, &sg, &sg, len);

		printk(KERN_INFO "rwtestflt: done\n");

		redirfs_attach_data_context(rwtestflt, context, &data->rfs_data);
		redirfs_put_data(&data->rfs_data);
		redirfs_put_data(&data->rfs_data);
		printk(KERN_INFO "rwtestflt: data cnt %i\n", data->rfs_data.cnt);
		goto end;
error:
		crypto_free_blkcipher(tfm);
	}
	else
	{
		printk(KERN_INFO "rwtestflt: writepage postcall\n");

		rfs_data = redirfs_detach_data_context(rwtestflt, context);
		if (rfs_data)
		{
			printk(KERN_INFO "rwtestflt: writepage returned %i\n", args->rv.rv_int);
			if (args->rv.rv_int == AOP_WRITEPAGE_ACTIVATE)
			{
				printk(KERN_INFO "rwtestflt: page active!\n");
			}
			printk(KERN_INFO "rwtestflt: page flags: %lu\n", page->flags);
			lock_page(page);
			if (PageReclaim(page))
			{
				printk(KERN_INFO "rwtestflt: page reclaim!\n");
			}
			if (PageReferenced(page))
			{
				printk(KERN_INFO "rwtestflt: page referenced!\n");
			}
			if (PageWriteback(page))
			{
				printk(KERN_INFO "rwtestlft: waiting for page writeback\n");
				wait_on_page_writeback(page);
				printk(KERN_INFO "rwtestflt: waiting done\n");
			}
			if (PageMappedToDisk(page))
			{
				printk(KERN_INFO "rwtestlt: page is mapped to disk\n");
			}
			data = rfs_to_context_data(rfs_data);
			printk(KERN_INFO "rwtestflt: unciphering %i\n", data->len);
			sg_set_page(&sg, page, data->len, 0);
			crypto_blkcipher_set_iv(data->desc.tfm, AES_IV, 16);
			ret = crypto_blkcipher_decrypt(&data->desc, &sg, &sg, data->len);
			crypto_free_blkcipher(data->desc.tfm);
			printk(KERN_INFO "rwtestflt: data cnt %i\n", rfs_data->cnt);
			redirfs_put_data(&data->rfs_data);
			if (PageDirty(page))
			{
				printk(KERN_INFO "rwtestflt: page dirty!\n");
			}
			if (PageUptodate(page))
			{
				printk(KERN_INFO "rwtestflt: page uptodate!\n");
			}
			SetPageUptodate(page);
			unlock_page(page);
		}
	}
end:
	printk(KERN_INFO "rwtestflt: writepage callback\n");
	return REDIRFS_CONTINUE;
}

enum redirfs_rv rwtestflt_readpages(redirfs_context context,
		struct redirfs_args *args)
{
	struct dentry *dentry;

	printk(KERN_INFO "rwtestflt: readpages callback\n");
	list_for_each_entry(dentry, &args->args.a_readpages.mapping->host->i_dentry, d_alias) {
		printk(KERN_INFO "rwtestflt: file %s\n", dentry->d_name.name);
	}
	return REDIRFS_CONTINUE;
}

enum redirfs_rv rwtestflt_writepages(redirfs_context context,
		struct redirfs_args *args)
{
	struct address_space *mapping = args->args.a_writepages.mapping;
	struct dentry *dentry;
	struct pagevec pvec;
	int unlock = 0;
	int nr_pages;
	int i;

	printk(KERN_INFO "rwtestflt: writepages callback\n");
	list_for_each_entry(dentry, &args->args.a_writepages.mapping->host->i_dentry, d_alias) {
		printk(KERN_INFO "rwtestflt: file %s\n", dentry->d_name.name);
	}
	printk(KERN_INFO "rwtestflt: sync mode %i\n", args->args.a_writepages.wbc->sync_mode);
	printk(KERN_INFO "rwtestflt: nr to write %li\n", args->args.a_writepages.wbc->nr_to_write);
	printk(KERN_INFO "rwtestflt: pages skipped %li\n", args->args.a_writepages.wbc->pages_skipped);
	printk(KERN_INFO "rwtestflt: writeback index %li\n", mapping->writeback_index);
	printk(KERN_INFO "rwtestflt: range start %li\n", args->args.a_writepages.wbc->range_start);
	printk(KERN_INFO "rwtestflt: range end %li\n", args->args.a_writepages.wbc->range_end);
	printk(KERN_INFO "rwtestflt: nonblocking %i\n", args->args.a_writepages.wbc->nonblocking);
	printk(KERN_INFO "rwtestflt: range cyclic %i\n", args->args.a_writepages.wbc->range_cyclic);
	printk(KERN_INFO "rwtestflt: for writepages %i\n", args->args.a_writepages.wbc->for_writepages);
	printk(KERN_INFO "rwtestflt: for reclaim %i\n", args->args.a_writepages.wbc->for_reclaim);

	if (args->type.call == REDIRFS_PRECALL)
		printk(KERN_INFO "rwtestflt: writepages precall\n");
	else
		printk(KERN_INFO "rwtestflt: writepages postcall\n");

	pagevec_init(&pvec, 0);
	nr_pages = pagevec_lookup(&pvec, mapping, 0, 10);
	for (i = 0; i < nr_pages; ++i) {
		struct page *page = pvec.pages[i];
		struct buffer_head *head;
		struct buffer_head *bh;
		int buffer_count = 0;
		int dirty_buffer_count = 0;

		if (!PageLocked(page))
		{
			lock_page(page);
			unlock = 1;
		}
		if (PageDirty(page))
			printk(KERN_INFO "rwtestflt: page dirty!\n");
		if (PageUptodate(page))
			printk(KERN_INFO "rwtestflt: page uptodate!\n");
		if (PagePrivate(page)) {
			head = page_buffers(page);
			if (head) {
				for (bh = head; buffer_count == 0 || bh != head; bh = bh->b_this_page) {
					++buffer_count;
					if (buffer_dirty(bh))
						++dirty_buffer_count;
					if (buffer_req(bh))
						printk(KERN_INFO "rwtestflt: buffer req!\n");
				}
			}
			printk(KERN_INFO "rwtestflt: dirty buffer count %i/%i\n", dirty_buffer_count, buffer_count);
		}
		if (unlock)
		{
			unlock_page(page);
			unlock = 0;
		}
	}
	pagevec_release(&pvec);

	/* args->args.a_writepages.wbc->sync_mode = WB_SYNC_ALL; */

/*	struct address_space *mapping = args->args.a_writepages.mapping;
	struct writeback_control *wbc = args->args.a_writepages.wbc;
	struct pagevec pvec;
	int nr_pages;
	pgoff_t writeback_index;
	pgoff_t index;
	pgoff_t end;
	pgoff_t done_index;
	int cycled;
	int done = 0;

	printk(KERN_INFO "rwtestflt: ==========================\n");

	if (args->type.call == REDIRFS_PRECALL)
	{
		printk(KERN_INFO "rwtestflt: writepages precall\n");

		if (wbc->nonblocking && bdi_write_congested(mapping->backing_dev_info)) {
			return REDIRFS_CONTINUE;
		}

		pagevec_init(&pvec, 0);
		if (wbc->range_cyclic) {
			writeback_index = mapping->writeback_index;
			index = writeback_index;
			if (index == 0)
				cycled = 1;
			else
				cycled = 0;
			end = -1;
		} else {
			index = wbc->range_start >> PAGE_CACHE_SHIFT;
			end = wbc->range_end >> PAGE_CACHE_SHIFT;
			cycled = 1;
		}

retry:
		done_index = index;
		while (!done && (index <= end)) {
			int i;

			nr_pages = pagevec_lookup_tag(&pvec, mapping, &index,
					PAGECACHE_TAG_DIRTY,
					min(end - index, (pgoff_t) (PAGEVEC_SIZE - 1)) + 1);
			if (nr_pages == 0)
				break;

			for (i = 0; i < nr_pages; ++i) {
				struct page *page = pvec.pages[i];

				if (page->index > end) {
					done = 1;
					break;
				}

				done_index = page->index + 1;

				lock_page(page);

				if (unlikely(page->mapping != mapping)) {
continue_unlock:
					unlock_page(page);
					continue;
				}

				if (!PageDirty(page)) {
					goto continue_unlock;
				}

				if (PageWriteback(page)) {
					if (wbc->sync_mode != WB_SYNC_NONE)
						wait_on_page_writeback(page);
					else
						goto continue_unlock;
				}

				BUG_ON(PageWriteback(page));
				if (!clear_page_dirty_for_io(page))
					goto continue_unlock;

				printk(KERN_INFO "rwtestflt: got a page!\n");
				printk(KERN_INFO "rwtestflt: page index %li\n", page->index);

				struct buffer_head *head;
				struct buffer_head *bh;
				int buffer_count = 0;
				int dirty_buffer_count = 0;

				if (PageReclaim(page))
				{
					printk(KERN_INFO "rwtestflt: page reclaim!\n");
				}
				if (PageReferenced(page))
				{
					printk(KERN_INFO "rwtestflt: page referenced!\n");
				}
				if (PageMappedToDisk(page))
				{
					printk(KERN_INFO "rwtestlt: page is mapped to disk\n");
				}
				if (PageDirty(page))
				{
					printk(KERN_INFO "rwtestflt: page dirty!\n");
				}
				if (PageUptodate(page))
				{
					printk(KERN_INFO "rwtestflt: page uptodate!\n");
				}
				if (PagePrivate(page))
				{
					head = page_buffers(page);
					if (head)
					{
						for (	bh = head;
							buffer_count == 0 || bh != head;
							bh = bh->b_this_page)
						{
							++buffer_count;
							if (buffer_dirty(bh))
								++dirty_buffer_count;
							else
								set_buffer_dirty(bh);
							if (buffer_req(bh))
								printk(KERN_INFO "rwtestflt: buffer req\n");
							if (buffer_mapped(bh))
								printk(KERN_INFO "rwtestflt: buffer mapped\n");
							if (buffer_async_write(bh))
								printk(KERN_INFO "rwtestflt: buffer async write\n");
							if (buffer_delay(bh))
								printk(KERN_INFO "rwtestflt: buffer delay\n");
						}
					}
					if (head == head->b_this_page)
						printk(KERN_INFO "rwtestflt: only one buffer head? wtf!\n");
					printk(KERN_INFO "rwtestflt: dirty buffer count %i/%i\n",
							dirty_buffer_count, buffer_count);
				}
			}
			pagevec_release(&pvec);
		}
		if (!cycled) {
			cycled = 1;
			index = 0;
			end = writeback_index - 1;
			goto retry;
		}
	}
	else
	{
		printk(KERN_INFO "rwtestflt: writepages postcall\n");
	}

	printk(KERN_INFO "rwtestflt: ==========================\n");
*/
	return REDIRFS_CONTINUE;
}

static struct redirfs_op_info rwtestflt_op_info[] = {
	{REDIRFS_REG_FOP_OPEN, rwtestflt_open, NULL},
	{REDIRFS_REG_FOP_RELEASE, rwtestflt_release, rwtestflt_release},
	{REDIRFS_REG_FOP_READ, rwtestflt_read, rwtestflt_read},
	{REDIRFS_REG_FOP_WRITE, rwtestflt_write, rwtestflt_write},
	{REDIRFS_REG_AOP_READPAGE, rwtestflt_readpage, rwtestflt_readpage},
	{REDIRFS_REG_AOP_WRITEPAGE, rwtestflt_writepage, rwtestflt_writepage},
	{REDIRFS_REG_AOP_READPAGES, rwtestflt_readpages, rwtestflt_readpages},
	{REDIRFS_REG_AOP_WRITEPAGES, rwtestflt_writepages, rwtestflt_writepages},
	{REDIRFS_REG_AOP_WRITE_BEGIN, rwtestflt_write_begin, rwtestflt_write_begin},
	{REDIRFS_REG_AOP_WRITE_END, rwtestflt_write_end, rwtestflt_write_end},
	{REDIRFS_OP_END, NULL, NULL}
};

static int __init rwflt_init(void)
{
	struct redirfs_path_info rwflt_path_info;
	struct nameidata nd;
	redirfs_path path;
	int err;
	int rv;

	rwtestflt = redirfs_register_filter(&rwtestflt_info);
	if (IS_ERR(rwtestflt)) {
		rv = PTR_ERR(rwtestflt);
		printk(KERN_ERR "rwtestflt: register filter "
				"failed: %d\n", rv);
		return rv;
	}

	rv = redirfs_set_operations(rwtestflt, rwtestflt_op_info);
	if (rv) {
		printk(KERN_ERR "rwtestflt: set operations "
				"failed: %d\n", rv);
		goto error;
	}

	rv = path_lookup("/tmp/rwtest", LOOKUP_FOLLOW, &nd);
	if (rv) {
		printk(KERN_ERR "rwtestflt: path lookup failed: %d\n", rv);
		goto error;
	}

	rwflt_path_info.dentry = nd.path.dentry;
	rwflt_path_info.mnt = nd.path.mnt;
	rwflt_path_info.flags = REDIRFS_PATH_INCLUDE;

	path = redirfs_add_path(rwtestflt, &rwflt_path_info);
	if (IS_ERR(path)) {
		rv = PTR_ERR(path);
		printk(KERN_ERR "rwtestflt: add path failed: %d\n", rv);
		goto error;
	}
	path_put(&nd.path);
	redirfs_put_path(path);

	printk(KERN_INFO "RedirFS read/write test filter, "
			"version " RWTESTFLT_VERSION "\n");
	return 0;

error:
	err = redirfs_unregister_filter(rwtestflt);
	if (err) {
		printk(KERN_ERR "rwtestflt: unregister filter "
				"failed: %d\n", rv);
		return 0;
	}
	redirfs_delete_filter(rwtestflt);
	return rv;
}

static void __exit rwflt_exit(void)
{
	int rv;

	rv = redirfs_unregister_filter(rwtestflt);
	if (rv) {
		printk(KERN_ERR "rwtestflt: unregister filter "
				"failed: %d\n", rv);
	}
	redirfs_delete_filter(rwtestflt);

	printk(KERN_INFO "rwtestflt: exiting...\n");
}

module_init(rwflt_init);
module_exit(rwflt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pavel Zuna <xzunap00@stud.fit.vutbr.cz>");
MODULE_DESCRIPTION("RedirFS read/write test filter, "
                   "version " RWTESTFLT_VERSION);

