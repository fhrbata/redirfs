// TODO: move remaining code using crypto to compress.c
#include <linux/crypto.h>
#include <asm/uaccess.h> // get_fs / set_fs
#include "../redirfs/redirfs.h"
#include "../redirfs/inode.h"
#include "../redirfs/root.h"
#include "compflt.h"

// ripped from redirfs
static inline void *get_orig_read(struct file *f)
{
        struct redirfs_inode_t *rinode;
        struct redirfs_root_t *root;
        ssize_t(*orig_read) (struct file *, char __user *, size_t,
                        loff_t *);

        rinode = redirfs_ifind(f->f_dentry->d_inode->i_sb,
                        f->f_dentry->d_inode->i_ino);
        BUG_ON(!rinode);
        root = redirfs_rget(rinode->root);
        BUG_ON(!root);

        orig_read = root->orig_ops.reg_fops->read;

        return orig_read;
}

// ripped from redirfs
static inline void *get_orig_write(struct file *f)
{
        struct redirfs_inode_t *rinode;
        struct redirfs_root_t *root;
        ssize_t(*orig_write) (struct file *, const char __user *, size_t,
                        loff_t *);

        rinode = redirfs_ifind(f->f_dentry->d_inode->i_sb,
                        f->f_dentry->d_inode->i_ino);
        BUG_ON(!rinode);
        root = redirfs_rget(rinode->root);
        BUG_ON(!root);

        orig_write = root->orig_ops.reg_fops->write;

        return orig_write;
}

// TODO: read might not get the whole size in 1 go
ssize_t orig_read(struct file * f, char __user * buffer,
                size_t len, loff_t * off)
{
        int rv;
        mm_segment_t orig_fs;
        ssize_t(*orig_read) (struct file *, char __user *, size_t, loff_t *);

        printk("compflt: [f:orig_read] [%i@%i]: ", len, (int) *off);

        orig_fs = get_fs();
        set_fs(KERNEL_DS);
        orig_read = get_orig_read(f);
	rv = orig_read(f, buffer, len, off);
	hexdump(buffer, rv);	// DEBUG
	set_fs(orig_fs);
	return rv;
}

// TODO: write might not put the whole size in 1 go
ssize_t orig_write(struct file * f, const char __user * buffer,
			   size_t len, loff_t * off)
{
	int rv;
	mm_segment_t orig_fs;
	ssize_t(*orig_write) (struct file *, const char __user *, size_t, loff_t *);

	printk("compflt: [f:orig_write] [%i@%i]: ", len, (int) *off);
	hexdump((char*)buffer, len);	// DEBUG

	orig_fs = get_fs();
	set_fs(KERNEL_DS);
	orig_write = get_orig_write(f);
	rv = orig_write(f, buffer, len, off);
	set_fs(orig_fs);
	return rv;
}

static char* get_block_c(struct file* f, struct dmap *dm)
{
        char *block_c = NULL;
        loff_t tmp = 0;

        printk("compflt: [f:get_block_c]\n");

        block_c = kmalloc(dm->size_c, GFP_KERNEL);
        if (!block_c)
                return NULL;

        tmp = dm->off_c;
	orig_read(f, block_c, dm->size_c, &tmp);

        return block_c;
}

static char* get_block_u(struct file *f, struct dmap *dm, struct crypto_tfm *tfm)
{
	char *block_c = NULL;
        char *block_u = NULL;

        printk("compflt: [f:get_block_u]\n");

        if(!(block_c = get_block_c(f, dm))) {
                printk(KERN_ERR "compflt: failed to read data block\n");
                return NULL;
        }

        // we use COMPFLT_BLOCK_SIZE instead of dm->size_u , because we might
        // be adding data to the block (write operation)
        block_u = kmalloc(COMPFLT_BLOCK_SIZE, GFP_KERNEL);
        if (!block_u) {
                printk(KERN_ERR "compflt: failed to allocate %i bytes\n", dm->size_u);
                kfree(block_c);
                return NULL;
        }
	memset(block_u, 0, COMPFLT_BLOCK_SIZE);

	if (crypto_comp_decompress(tfm, block_c, dm->size_c, block_u, &dm->size_u)) {
                printk(KERN_ERR "compflt: failed to decompress data block\n");
                kfree(block_u);
                kfree(block_c);
                return NULL;
        }

	kfree(block_c);
	return block_u;
}

int put_block_u(struct file *f, struct dmap *dm, struct crypto_tfm *tfm, char *block_u)
{
        char *block_c;
        unsigned int size_c;
        loff_t tmp;
	int rv;

        printk("compflt: [f:put_block_u]\n");

        size_c = 2*COMPFLT_BLOCK_SIZE;
        block_c = kmalloc(size_c, GFP_KERNEL);

        if((rv = crypto_comp_compress(tfm, block_u, dm->size_u, block_c, &size_c))) {
                printk(KERN_ERR "compflt: failed to compress data block (rv=%i)\n", rv);
                return 1;
        }

        printk ("compflt: [f:put_block_u] compressed %i bytes | ratio=%i:%i\n", dm->size_u, size_c, dm->size_u);

        // TODO: off_c correction in some cases (not sure if it should be here
        // TODO: in some cases we need to set a new dm->off_c (move the block)

        dm->size_c = size_c;

/* TODO: NOT YET TESTED
        tmp = dm->off_c;	// we dont want our dm modified
        orig_write(f, block_c, dm->size_c, &tmp);
*/

        kfree(block_c);
        return 0;
}

static inline int dmap_match(struct dmap *dm, loff_t off_req, size_t size_req)
{
        return ((dm->off_u <= off_req && (dm->off_u + dm->size_u) > off_req) || (dm->off_u >= off_req && dm->off_u < off_req + size_req));
}

static void rw_params(struct dmap *dm, loff_t req_start, size_t req_size,
                loff_t* src_off, loff_t* dst_off, size_t *size, size_t blk_max)
{
        loff_t req_end = req_start + req_size;
        loff_t dm_end = dm->off_u + blk_max;

        printk("compflt: [f:rw_params]\n");

        // src_off
        if (req_start <= dm->off_u)
                *src_off = 0;
        else
                *src_off = req_start - dm->off_u;

        // dst_off
        if (dm->off_u <= req_start)
                *dst_off = 0;
        else
                *dst_off = dm->off_u - req_start;

        // size
        if (dm_end <= req_end)
                *size = dm->size_u - *src_off;
        else if (dm->off_u < req_start)
                *size = req_end - *src_off;
        else 
                *size = req_end - dm->off_u;
}

static inline void read_params(struct dmap *dm, loff_t req_start, size_t req_size,
                loff_t* src_off, loff_t* dst_off, size_t *size)
{
        printk("compflt: [f:read_params]\n");
        rw_params(dm, req_start, req_size, src_off, dst_off, size, dm->size_u);
}

static inline void write_params(struct dmap *dm, loff_t req_start, size_t req_size,
                loff_t* src_off, loff_t* dst_off, size_t *size)
{
        printk("compflt: [f:write_params]\n");
        rw_params(dm, req_start, req_size, src_off, dst_off, size, COMPFLT_BLOCK_SIZE);
}


// buff_u is expected to have enough space for size_req-bytes
int read_u(struct file *f, struct header *fh, loff_t off_req, size_t * size_req, char *buff_u)
{
        struct crypto_tfm *tfm;
        struct dmap *dm;
        char *block_u;

        loff_t off_src;
        loff_t off_dst;
        size_t size;
        size_t size_total = 0;

        printk("compflt: [f:read_u] i=%li\n", fh->ino);

        memset(buff_u, 0, *size_req);

        tfm = comp_init(fh->method);

        list_for_each_entry(dm, &fh->map.list, list) {
                printk("compflt: [f:read_u] map=%i(%i) -> %i(%i)\n",
                                (int) dm->off_c, dm->size_c, (int) dm->off_u, dm->size_u);

                if (!dmap_match(dm, off_req, *size_req))
                        continue;

                printk("compflt: [f:read_u] match\n");

                if(!(block_u = get_block_u(f, dm, tfm)))
                        return 1;

                read_params (dm, off_req, *size_req, &off_src, &off_dst, &size);
                printk("compflt: [f:read_u] memcpy %i@%i -> %i\n", size, (int)off_src, (int)off_dst);

                memcpy(buff_u + off_dst, block_u + off_src, size);
                size_total += size;
        }
        crypto_free_tfm(tfm);
        *size_req = size_total;

        return 0;
}

int write_u(struct file *f, struct header *fh, loff_t off_req, size_t size_req, char *buff_in)
{
        struct crypto_tfm *tfm;
        struct dmap *dm;
        struct dmap *last = NULL;
        char *block_u;

        loff_t off_src;
        loff_t off_dst;
        size_t size;
        size_t size_total = size_req;

        printk("compflt: [f:write_u] i=%li\n", fh->ino);

        tfm = comp_init(fh->method);
        
        /* TODO: NOT YET TESTED
        list_for_each_entry(dm, &fh->map.list, list) {
                printk("compflt: [f:write_u] map=%i(%i) -> %i(%i)\n",
                                (int)dm->off_c, dm->size_c, (int)dm->off_u, dm->size_u);
                if (!dmap_match(dm, off_req, size_req))
                        continue;

                printk("compflt: [f:write_u] match\n");

                if(!(block_u = get_block_u(f, dm, tfm)))
                        return 1;

                write_params(dm, off_req, size_req, &off_src, &off_dst, &size);
                printk("compflt: [f:write_u] memcpy %i@%i -> %i\n", size, (int)off_src, (int)off_dst);

                memcpy(block_u + off_dst, buff_in + off_src, size);

                size_total -= size;

                if (off_dst + size > dm->size_u) {
                        // uncompressed size have changed, update it
                        printk("#UPDATING size_u\n");
                        dm->size_u = off_dst + size;
                }

                put_block_u(f, dm, tfm, block_u);
                last = dm;
        }
        */

        while (size_total > 0) {
                printk("compflt: [f:write_u] newblk remaining=%i\n", size_total);

                dm = dmap_init();
                if (!dm)
                        return 1;

                if (last) {
                        dm->off_u = last->off_u+last->size_u;
                        dm->off_c = last->off_c+last->size_c;
                }
                else {
                        dm->off_c = COMPFLT_FH_RESERVED;
                }

                write_params(dm, off_req, size_req, &off_src, &off_dst, &dm->size_u);
                if(!(block_u = kmalloc(dm->size_u, GFP_KERNEL))) {
                        printk(KERN_ERR "compflt: failed to allocate %i bytes\n", dm->size_u);
                        return 1;
                }

                printk("compflt: [f:write_u] memcpy %i@%i -> %i\n", dm->size_u, (int)off_src, (int)off_dst);

                // off_dst has to be 0 in this case
                BUG_ON(off_dst);
                memcpy(block_u, buff_in + off_src, dm->size_u);

                // put_block_u updates dm->size_c
                put_block_u(f, dm, tfm, block_u);
                header_add_dm(fh, dm);

                size_total -= dm->size_u;

                kfree(block_u);
                last = dm;
        }

        // TODO: doesnt have to happen always in write_u
        fh->dirty = 1;

        crypto_free_tfm(tfm);
        return 0;
}
