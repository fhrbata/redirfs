#include <linux/crypto.h>
#include <asm/uaccess.h> // get_fs / set_fs
#include "../redirfs/redir.h"
#include "compflt.h"

static inline void *get_orig_read(struct file *f)
{
        struct rfile *rfile = rfile_find(f);
        BUG_ON(!rfile);
        return rfile->rf_op_old->read;
}

static inline void *get_orig_write(struct file *f)
{
        struct rfile *rfile = rfile_find(f);
        BUG_ON(!rfile);
        return rfile->rf_op_old->write;
}

// TODO: read might not get the whole size in 1 go
ssize_t orig_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
        int rv;
        mm_segment_t orig_fs;
        ssize_t(*orig_read) (struct file*, char __user*, size_t, loff_t*);

        debug_printk("compflt: [f:orig_read] [%i@%i]: ", len, (int)*off);

        orig_fs = get_fs();
        set_fs(KERNEL_DS);
        orig_read = get_orig_read(f);
	rv = orig_read(f, buf, len, off);
	hexdump(buf, rv); // DEBUG
	set_fs(orig_fs);
	return rv;
}

// TODO: write might not put the whole size in 1 go
ssize_t orig_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
	int rv;
	mm_segment_t orig_fs;
	ssize_t(*orig_write) (struct file*, const char __user*, size_t, loff_t*);

	debug_printk("compflt: [f:orig_write] [%i@%i]: ", len, (int) *off);
	hexdump((char*)buf, len); // DEBUG

	orig_fs = get_fs();
	set_fs(KERNEL_DS);
	orig_write = get_orig_write(f);
	rv = orig_write(f, buf, len, off);
	set_fs(orig_fs);
	return rv;
}

#define rw_match(blk, off_req, size_req, blk_max) \
        ((blk->off_u <= off_req && (blk->off_u + blk_max) > off_req) || (blk->off_u >= off_req && blk->off_u < off_req + size_req));

static inline int read_match(struct block *blk, loff_t off_req, size_t size_req)
{
        return rw_match(blk, off_req, size_req, blk->size_u);
}
static inline int write_match(struct block *blk, loff_t off_req, size_t size_req)
{
        return rw_match(blk, off_req, size_req, COMPFLT_BLOCK_SIZE_U);
}

static void rw_params(struct block *blk, loff_t req_start, size_t req_size,
                loff_t* src_off, loff_t* dst_off, size_t *size, size_t blk_max)
{
        loff_t req_end = req_start + req_size;
        loff_t blk_end = blk->off_u + blk_max;

        debug_printk("compflt: [f:rw_params] req_start=%i req_size=%i blk_start=%i blk_end=%i\n",
                (int)req_start, (int)req_size, (int)blk->off_u, (int)blk_end);

        // src_off
        if (req_start <= blk->off_u)
                *src_off = 0;
        else
                *src_off = req_start - blk->off_u;

        // dst_off
        if (blk->off_u <= req_start)
                *dst_off = 0;
        else
                *dst_off = blk->off_u - req_start;

        // size
        if (blk_end < req_end)
                *size = blk_max - *src_off;
        else
                *size = (req_end - blk->off_u) - *src_off;
}


static inline void read_params(struct block *blk, loff_t req_start, size_t req_size,
                loff_t* src_off, loff_t* dst_off, size_t *size)
{
        debug_printk("compflt: [f:read_params]\n");
        rw_params(blk, req_start, req_size, src_off, dst_off, size, blk->size_u);
}

static inline void write_params(struct block *blk, loff_t req_start, size_t req_size,
                loff_t* src_off, loff_t* dst_off, size_t *size)
{
        debug_printk("compflt: [f:write_params]\n");
        rw_params(blk, req_start, req_size, dst_off, src_off, size, COMPFLT_BLOCK_SIZE_U);
}

// buff_u is expected to have enough space for size_req bytes
int read_u(struct file *f, struct fheader *fh, loff_t off_req, size_t *size_req, char *buff_u)
{
        struct crypto_tfm *tfm;
        struct block *blk;

        loff_t off_src;
        loff_t off_dst;
        size_t size;
        size_t size_total = 0;

        debug_printk("compflt: [f:read_u] i=%li\n", fh->ino);

        memset(buff_u, 0, *size_req);

        tfm = comp_init(fh->method);

        list_for_each_entry(blk, &fh->map.file, file) {
                debug_block("compflt: [f:read_u]", blk);

                if (!read_match(blk, off_req, *size_req))
                        continue;

                debug_printk("compflt: [f:read_u] match\n");

                if(block_read(f, blk, tfm))
                        return -1;

                read_params(blk, off_req, *size_req, &off_src, &off_dst, &size);
                debug_printk("compflt: [f:read_u] memcpy %i@%i -> %i\n", size, (int)off_src, (int)off_dst);

                memcpy(buff_u+off_dst, blk->data_u+off_src, size);
                size_total += size;
        }
        comp_deinit(tfm);
        *size_req = size_total;

        return 0;
}

int write_u(struct file *f, struct fheader *fh, loff_t off_req, size_t *size_req, char *buff_in)
{
        struct crypto_tfm *tfm;
        struct block *blk = NULL;
        struct block *last = NULL;

        loff_t off_src;
        loff_t off_dst;
        size_t size;
        int size_total = (int)*size_req;

        debug_printk("compflt: [f:write_u] i=%li\n", fh->ino);

        tfm = comp_init(fh->method);
        
        list_for_each_entry(blk, &fh->map.file, file) {
                debug_block("compflt: [f:write_u]", blk);

                last = blk;

                if (!write_match(blk, off_req, *size_req))
                        continue;

                debug_printk("compflt: [f:write_u] match\n");

                if(block_read(f, blk, tfm))
                        return -1;
                write_params(blk, off_req, *size_req, &off_src, &off_dst, &size);

                debug_printk("compflt: [f:write_u] memcpy %i@%i -> %i\n", size, (int)off_src, (int)off_dst);
                memcpy(blk->data_u+off_dst, buff_in+off_src, size);

                size_total -= size;

                // update uncompressed size
                if (off_dst + size > blk->size_u) {
                        blk->size_u = off_dst + size;
                        blk->dirty = 1;
                }

                block_write(f, blk, tfm);
                fh->compressed = 1;
        }

        while (size_total > 0) {
                debug_printk("compflt: [f:write_u] newblk remaining=%i\n", size_total);

                blk = block_init();
                if (!blk)
                        return -1;

                if (last) {
                        last->off_next = last->off_c+COMPFLT_BH_SIZE+last->size_c;
                        blk->off_u = last->off_u+last->size_u;
                        blk->off_c = last->off_next;
                }
                else {
                        blk->off_c = COMPFLT_FH_SIZE;
                }
                blk->dirty = 1;

                write_params(blk, off_req, *size_req, &off_src, &off_dst, (size_t*)&blk->size_u);
                debug_printk("compflt: [f:write_u] memcpy %i@%i -> %i\n", blk->size_u, (int)off_src, (int)off_dst);
                if(!(blk->data_u = kmalloc(blk->size_u, GFP_KERNEL))) {
                        printk(KERN_ERR "compflt: failed to allocate %i bytes\n", blk->size_u);
                        return -ENOMEM;
                }

                BUG_ON(off_dst); // off_dst has to be 0 in this case
                memcpy(blk->data_u, buff_in+off_src, blk->size_u);

                //TODO: check for block_write fails
                // updates blk->size_c
                block_write(f, blk, tfm);
                fh->compressed = 1;

                kfree(blk->data_u);

                fheader_add_blk(fh, blk);

                size_total -= blk->size_u;
                last = blk;
        }

        // update the size of the whole file
        fh->size = last->off_u + last->size_u;

        // size_total *should* be 0 at this point
        *size_req -= size_total;

        comp_deinit(tfm);
        return 0;
}
