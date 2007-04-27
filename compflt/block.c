#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "compflt.h"

#define CACHE_NAME "compflt_block"

static struct kmem_cache *cflt_block_cache = NULL;
spinlock_t cflt_block_cache_l = SPIN_LOCK_UNLOCKED;

int cflt_block_cache_init(void)
{
        cflt_debug_printk("compflt: [f:cflt_block_cache_init]\n");

        cflt_block_cache = kmem_cache_create(CACHE_NAME, sizeof(struct cflt_block), 0, 0, NULL, NULL);

        if (!cflt_block_cache)
                return -ENOMEM;

        return 0;
}

void cflt_block_cache_deinit(void)
{
        cflt_debug_printk("compflt: [f:cflt_block_cache_deinit]\n");

        spin_lock(&cflt_block_cache_l);
        kmem_cache_destroy(cflt_block_cache);
        spin_unlock(&cflt_block_cache_l);
        cflt_block_cache = NULL;
}

struct cflt_block* cflt_block_init(void)
{
        struct cflt_block *blk;

        cflt_debug_printk("compflt: [f:cflt_block_init]\n");

        spin_lock(&cflt_block_cache_l);
        blk = kmem_cache_alloc(cflt_block_cache, GFP_KERNEL);
        spin_unlock(&cflt_block_cache_l);

        if (!blk) {
                printk(KERN_ERR "compflt: failed to allocate a block\n");
                return NULL;
        }

        blk->data_u = blk->data_c = NULL;
        blk->par = NULL;
        blk->type = CFLT_BLK_NORM;
        blk->dirty = 0;
        blk->off_u = blk->off_c = blk->off_next = 0;
        blk->size_u = blk->size_c = 0;

        INIT_LIST_HEAD(&blk->file);

        return blk;
}

void cflt_block_deinit(struct cflt_block *blk)
{
        cflt_debug_printk("compflt: [f:cflt_block_deinit]\n");

        list_del(&blk->file);
        spin_lock(&cflt_block_cache_l);
        kmem_cache_free(cflt_block_cache, blk);
        spin_unlock(&cflt_block_cache_l);
}

// sets 'off' to the start of the next header (or 0 if last)
int cflt_block_read_header(struct file *f, struct cflt_block *blk, loff_t *off)
{
        int rv = 0;
        int boff = 0;
        char buf[CFLT_BH_SIZE]; // max size

        cflt_debug_printk("compflt: [f:cflt_block_read_header]\n");

        memset(buf, 0, sizeof(buf));
        blk->off_c = *off;

        rv = cflt_orig_read(f, buf, sizeof(buf), off);
        if (!rv) {
                printk(KERN_ERR "compflt: failed to read header\n");
                return -1;
        }

        memcpy((char*)&blk->type, buf+boff, sizeof(u8));
        boff += sizeof(u8);

        // reset is type-specific
        switch (blk->type) {
        case CFLT_BLK_FREE:
                // TODO: free block
                break;
        case CFLT_BLK_NORM:
                memcpy(&blk->off_u, buf+boff, sizeof(u32));
                boff += sizeof(u32);
                memcpy(&blk->off_next, buf+boff, sizeof(u32));
                boff += sizeof(u32);
                memcpy(&blk->size_c, buf+boff, sizeof(u32));
                boff += sizeof(u32);
                memcpy(&blk->size_u, buf+boff, sizeof(u32));
                break;
        default:
                // TODO
                break;
        }

        cflt_debug_block(blk);

        *off = blk->off_next;
        return 0;
}

int cflt_block_write_header(struct file *f, struct cflt_block *blk)
{
        loff_t off;
        char buf[CFLT_BH_SIZE]; // max size
        int boff = 0;
        int rv = 0;

        cflt_debug_printk("compflt: [f:cflt_block_write_header]\n");

        if (!blk->dirty)
                return 0;

        switch (blk->type) {
        case CFLT_BLK_FREE:
                // TODO: free block
                break;
        case CFLT_BLK_NORM:
                memcpy(buf+boff, &blk->type, sizeof(u8));
                boff += sizeof(u8);
                memcpy(buf+boff, &blk->off_u, sizeof(u32));
                boff += sizeof(u32);
                memcpy(buf+boff, &blk->off_next, sizeof(u32));
                boff += sizeof(u32);
                memcpy(buf+boff, &blk->size_c, sizeof(u32));
                boff += sizeof(u32);
                memcpy(buf+boff, &blk->size_u, sizeof(u32));
                break;
        default:
                // TODO
                break;
        }

        off = blk->off_c;
        rv = cflt_orig_write(f, buf, sizeof(buf), &off);
        if (!rv) {
                printk(KERN_ERR "compflt: failed to write header\n");
                return -1;
        }
        blk->dirty = 0;

        return 0;
}

void cflt_block_write_headers(struct file *f, struct cflt_file *fh)
{
        struct cflt_block *blk;

        cflt_debug_printk("compflt: [f:cflt_block_write_headers]\n");

        list_for_each_entry(blk, &fh->blks, file) {
                // TODO: check for err
                cflt_block_write_header(f, blk);
        }
}

static int cflt_block_read_c(struct file *f, struct cflt_block *blk)
{
        loff_t off_data = blk->off_c + CFLT_BH_SIZE;

        cflt_debug_printk("compflt: [f:cflt_block_read_c]\n");

        blk->data_c = kmalloc(blk->size_c, GFP_KERNEL);
        if (!blk->data_c)
                return -ENOMEM;

        cflt_orig_read(f, blk->data_c, blk->size_c, &off_data);

        return 0;
}

int cflt_block_read(struct file *f, struct cflt_block *blk, struct crypto_comp *tfm)
{
        int err = 0;

        cflt_debug_printk("compflt: [f:cflt_block_read]\n");

        if ((err = cflt_block_read_c(f, blk))) {
                printk(KERN_ERR "compflt: failed to read block error: %i\n", err);
                return err;
        }

        if ((err = cflt_decomp_block(tfm, blk))) {
                printk(KERN_ERR "compflt: failed to decompress block error: %i\n", err);
                return err;
        }

        kfree(blk->data_c);
        return err;
}

int cflt_block_write(struct file *f, struct cflt_block *blk, struct crypto_comp *tfm)
{
        int err = 0;
        loff_t off_data;
        size_t old = blk->size_c;

        cflt_debug_printk("compflt: [f:cflt_block_write]\n");

        err = cflt_comp_block(tfm, blk);
        if(err)
                return err;

        if (blk->size_c != old) {
                // TODO: manage block size changes
                blk->dirty = 1;
        }

        off_data = blk->off_c + CFLT_BH_SIZE;
        cflt_orig_write(f, blk->data_c, blk->size_c, &off_data);

        kfree(blk->data_c);
        return err;
}

