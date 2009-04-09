/*
 * rwtestflt - redirfs read/write test filter
 */

#include <asm/uaccess.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/scatterlist.h>
#include <linux/writeback.h>

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

struct rwtestflt_trailer {
	u8 version;
	u8 algorithm;
	u16 block_size;
	u16 key_size;
	char *key;
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

	trailer = rwtestflt_get_trailer(file);
	if (trailer != NULL)
	{
		printk(KERN_INFO "rwtestflt: %i\n", trailer->key_size);
	}

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
	printk(KERN_INFO "rwtestflt: write callback\n");
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
	struct page *page = args->args.a_writepage.page;
	struct inode *inode = page->mapping->host;
	int len;
	int ret;

	if (args->type.call == REDIRFS_PRECALL)
	{
		printk(KERN_INFO "rwtestflt: writepage precall\n");

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
		rfs_data = redirfs_detach_data_context(rwtestflt, context);
		if (rfs_data)
		{
			lock_page(page);
			data = rfs_to_context_data(rfs_data);
			printk(KERN_INFO "rwtestflt: unciphering %i\n", data->len);
			sg_set_page(&sg, page, data->len, 0);
			crypto_blkcipher_set_iv(data->desc.tfm, AES_IV, 16);
			ret = crypto_blkcipher_decrypt(&data->desc, &sg, &sg, data->len);
			crypto_free_blkcipher(data->desc.tfm);
			printk(KERN_INFO "rwtestflt: data cnt %i\n", rfs_data->cnt);
			redirfs_put_data(&data->rfs_data);
			SetPageUptodate(page);
			unlock_page();
		}
	}
end:
	printk(KERN_INFO "rwtestflt: writepage callback\n");
	return REDIRFS_CONTINUE;
}

enum redirfs_rv rwtestflt_readpages(redirfs_context context,
		struct redirfs_args *args)
{
	printk(KERN_INFO "rwtestflt: readpages callback\n");
	return REDIRFS_CONTINUE;
}

enum redirfs_rv rwtestflt_writepages(redirfs_context context,
		struct redirfs_args *args)
{
	printk(KERN_INFO "rwtestflt: writepages callback\n");
	printk(KERN_INFO "rwtestflt: sync mode %i\n", args->args.a_writepages.wbc->sync_mode);
	printk(KERN_INFO "rwtestflt: nr to write %li\n", args->args.a_writepages.wbc->nr_to_write);
	printk(KERN_INFO "rwtestflt: pages skipped %li\n", args->args.a_writepages.wbc->pages_skipped);
	printk(KERN_INFO "rwtestflt: range start %li\n", args->args.a_writepages.wbc->range_start);
	printk(KERN_INFO "rwtestflt: range end %li\n", args->args.a_writepages.wbc->range_end);
	printk(KERN_INFO "rwtestflt: nonblocking %i\n", args->args.a_writepages.wbc->nonblocking);
	return REDIRFS_CONTINUE;
}

static struct redirfs_op_info rwtestflt_op_info[] = {
	{REDIRFS_REG_FOP_OPEN, rwtestflt_open, NULL},
	{REDIRFS_REG_FOP_READ, rwtestflt_read, rwtestflt_read},
	{REDIRFS_REG_FOP_WRITE, rwtestflt_write, rwtestflt_write},
	{REDIRFS_REG_AOP_READPAGE, rwtestflt_readpage, rwtestflt_readpage},
	{REDIRFS_REG_AOP_WRITEPAGE, rwtestflt_writepage, rwtestflt_writepage},
	{REDIRFS_REG_AOP_READPAGES, rwtestflt_readpages, rwtestflt_readpages},
	{REDIRFS_REG_AOP_WRITEPAGES, rwtestflt_writepages, rwtestflt_writepages},
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
}

module_init(rwflt_init);
module_exit(rwflt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pavel Zuna <xzunap00@stud.fit.vutbr.cz>");
MODULE_DESCRIPTION("RedirFS read/write test filter, "
                   "version " RWTESTFLT_VERSION);

