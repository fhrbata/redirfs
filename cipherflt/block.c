/*
 * cipherflt - RedirFS cryptographic filter
 *
 * Written by Pavel Zuna <xzunap00@stud.fit.vutbr.cz>
 *
 */

#include "cipherflt.h"

static struct kmem_cache *cipherflt_block_cache;

int cipherflt_block_cache_init(void)
{
	printk(INFO "cipherflt_block_cache_init\n");

	cipherflt_block_cache =
		kmem_cache_create("cipherflt_block_cache",
				sizeof (struct cipherflt_block), 0, 0, NULL);
	if (cipherflt_block_cache == NULL)
		return -ENOMEM;

	return 0;
}

struct cipherflt_block *cipherflt_block_alloc(void)
{
	struct cipherflt_block *block;

	printk(INFO "cipherflt_block_alloc\n");

	block = kmem_cache_alloc(cipherflt_block_cache, GFP_KERNEL);
	if (block == NULL)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&block->blocks);
	block->page = NULL;
	block->iv = NULL;
	block->len = 0;
	block->offset = 0;

	return block;
}

int cipherflt_block_add_blocks(struct page *page, struct inode *inode,
		u16 block_size, u8 iv_size, struct blkcipher_desc *desc,
		struct list_head *blocks)
{
	struct cipherflt_block *block;
	unsigned int offset;
	char *iv;

	printk(INFO "cipherflt_block_add_blocks\n");

	for (offset = 0; offset < (PAGE_SIZE); offset += block_size) {
		block = cipherflt_block_alloc();
		if (IS_ERR(block))
			return PTR_ERR(block);

		iv = cipherflt_cipher_generate_iv(page, iv_size, desc);
		if (IS_ERR(iv)) {
			cipherflt_block_free(block);
			return PTR_ERR(iv);
		}

		block->iv = iv;
		block->page = page;
		block->offset = offset;
		block->len = i_size_read(inode) - (page->index * (PAGE_SIZE));
		if (block->len > block_size)
			block->len = block_size;

		list_add(&block->blocks, blocks);
	}

	return 0;
}

void cipherflt_block_free(struct cipherflt_block *block)
{
	printk(INFO "cipherflt_block_free\n");

	BUG_ON(block == NULL);

	list_del(&block->blocks);
	if (block->iv != NULL)
		kfree(block->iv);
	kmem_cache_free(cipherflt_block_cache, block);
}

void cipherflt_block_cache_free(void)
{
	printk(INFO "cipherflt_block_cache_free\n");

	if (cipherflt_block_cache == NULL)
		return;

	kmem_cache_destroy(cipherflt_block_cache);
	cipherflt_block_cache = NULL;
}

/* end of file */

