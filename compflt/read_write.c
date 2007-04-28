#include <linux/crypto.h>
#include <asm/uaccess.h> // get_fs / set_fs
#include "../redirfs/redir.h"
#include "compflt.h"

// TODO: read might not get the whole size in 1 go
ssize_t cflt_orig_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
        int rv;
        mm_segment_t orig_fs;
        struct rfile *rfile = rfile_find(f);
        BUG_ON(!rfile);

        cflt_debug_printk("compflt: [f:orig_read] %i@%i\n", len, (int)*off);

        orig_fs = get_fs();
        set_fs(KERNEL_DS);
        rv = rfile->rf_op_old->read(f, buf, len, off);
        rfile_put(rfile);
	//cflt_hexdump(buf, rv); // DEBUG
	set_fs(orig_fs);
	return rv;
}

// TODO: write might not put the whole size in 1 go
ssize_t cflt_orig_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
	int rv;
	mm_segment_t orig_fs;
        struct rfile *rfile = rfile_find(f);
        BUG_ON(!rfile);

	cflt_debug_printk("compflt: [f:orig_write] %i@%i\n", len, (int) *off);
	//cflt_hexdump((char*)buf, len); // DEBUG

	orig_fs = get_fs();
	set_fs(KERNEL_DS);
        rv = rfile->rf_op_old->write(f, buf, len, off);
        rfile_put(rfile);
	set_fs(orig_fs);
	return rv;
}

#define cflt_rw_match(blk, off_req, size_req, blk_max) \
        ((blk->off_u <= off_req && (blk->off_u + blk_max) > off_req) || (blk->off_u >= off_req && blk->off_u < off_req + size_req));

static inline int cflt_read_match(struct cflt_block *blk, loff_t off_req, size_t size_req)
{
        return cflt_rw_match(blk, off_req, size_req, blk->size_u);
}
static inline int cflt_write_match(struct cflt_block *blk, loff_t off_req, size_t size_req)
{
        return cflt_rw_match(blk, off_req, size_req, blk->par->blksize);
}

static void cflt_rw_params(struct cflt_block *blk, loff_t req_start, size_t req_size,
                loff_t* src_off, loff_t* dst_off, size_t *size, size_t blk_max)
{
        loff_t req_end = req_start + req_size;
        loff_t blk_end = blk->off_u + blk_max;

        cflt_debug_printk("compflt: [f:rw_params] req_start=%i req_size=%i blk_start=%i blk_end=%i\n",
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


static inline void cflt_read_params(struct cflt_block *blk, loff_t req_start, size_t req_size,
                loff_t* src_off, loff_t* dst_off, size_t *size)
{
        cflt_debug_printk("compflt: [f:read_params]\n");
        cflt_rw_params(blk, req_start, req_size, src_off, dst_off, size, blk->size_u);
}

static inline void cflt_write_params(struct cflt_block *blk, loff_t req_start, size_t req_size,
                loff_t* src_off, loff_t* dst_off, size_t *size)
{
        cflt_debug_printk("compflt: [f:write_params]\n");
        cflt_rw_params(blk, req_start, req_size, dst_off, src_off, size, blk->par->blksize);
}

// buff_u is expected to have enough space for size_req bytes
int cflt_read(struct file *f, struct cflt_file *fh, loff_t off_req, size_t *size_req, char *buff_u)
{
        struct crypto_comp *tfm;
        struct cflt_block *blk;

        loff_t off_src;
        loff_t off_dst;
        size_t size;
        size_t size_total = 0;
        int err;

        cflt_debug_printk("compflt: [f:read_u] i=%li\n", fh->inode->i_ino);

        memset(buff_u, 0, *size_req);

        tfm = cflt_comp_init(fh->method);

        list_for_each_entry(blk, &fh->blks, file) {
                cflt_debug_block(blk);

                if (!cflt_read_match(blk, off_req, *size_req))
                        continue;

                cflt_debug_printk("compflt: [f:read_u] match\n");

                if ((err = cflt_block_read(f, blk, tfm)))
                        return err;

                cflt_read_params(blk, off_req, *size_req, &off_src, &off_dst, &size);
                cflt_debug_printk("compflt: [f:read_u] memcpy %i@%i -> %i\n", size, (int)off_src, (int)off_dst);

                memcpy(buff_u+off_dst, blk->data_u+off_src, size);
                kfree(blk->data_u);
                size_total += size;
        }
        cflt_comp_deinit(tfm);
        *size_req = size_total;

        return 0;
}

int cflt_write(struct file *f, struct cflt_file *fh, loff_t off_req, size_t *size_req, char *buff_in)
{
        int err = 0;

        struct crypto_comp *tfm;
        struct cflt_block *blk = NULL;
        struct cflt_block *last = NULL;

        loff_t off_src;
        loff_t off_dst;
        size_t size;
        int size_total = (int)*size_req;

        cflt_debug_printk("compflt: [f:write_u] i=%li\n", fh->inode->i_ino);

        tfm = cflt_comp_init(fh->method);

        list_for_each_entry(blk, &fh->blks, file) {
                cflt_debug_block(blk);

                last = blk;

                if (!cflt_write_match(blk, off_req, *size_req))
                        continue;

                cflt_debug_printk("compflt: [f:write_u] match\n");

                if ((err = cflt_block_read(f, blk, tfm)))
                        return err;

                cflt_write_params(blk, off_req, *size_req, &off_src, &off_dst, &size);

                cflt_debug_printk("compflt: [f:write_u] memcpy %i@%i -> %i\n", size, (int)off_src, (int)off_dst);

                memcpy(blk->data_u+off_dst, buff_in+off_src, size);

                size_total -= size;

                // update uncompressed size
                if (off_dst + size > blk->size_u) {
                        blk->size_u = off_dst + size;
                        blk->dirty = 1;
                }

                if((err = cflt_block_write(f, blk, tfm)))
                        return err;

                fh->compressed = 1;
        }

        while (size_total > 0) {
                cflt_debug_printk("compflt: [f:write_u] newblk remaining=%i\n", size_total);

                blk = cflt_block_init();
                if (!blk)
                        return -1;

                if (last) {
                        last->off_next = last->off_c+CFLT_BH_SIZE+last->size_c;
                        blk->off_u = last->off_u+last->size_u;
                        blk->off_c = last->off_next;
                }
                else {
                        blk->off_c = CFLT_FH_SIZE;
                }

                blk->dirty = 1;

                cflt_file_add_blk(fh, blk);

                cflt_write_params(blk, off_req, *size_req, &off_src, &off_dst, (size_t*)&blk->size_u);
                cflt_debug_printk("compflt: [f:write_u] memcpy %i@%i -> %i\n", blk->size_u, (int)off_src, (int)off_dst);

                blk->data_u = kmalloc(blk->size_u, GFP_KERNEL);
                if(!blk->data_u)
                        return -ENOMEM;

                memcpy(blk->data_u, buff_in+off_src, blk->size_u);

                // updates blk->size_c
                if ((err = cflt_block_write(f, blk, tfm))) {
                        kfree(blk->data_u);
                        return err;
                }

                kfree(blk->data_u);
                fh->compressed = 1;
                size_total -= blk->size_u;
                last = blk;
        }

        // size_total *should* be 0 at this point
        *size_req -= size_total;

        cflt_comp_deinit(tfm);
        return err;
}
