#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "compflt.h"

#define CACHE_NAME "compflt_block"

static kmem_cache_t *block_cache = NULL;
spinlock_t block_cache_l = SPIN_LOCK_UNLOCKED;

static struct list_head block_list;
rwlock_t block_list_l = RW_LOCK_UNLOCKED;

int block_cache_init(void)
{
        debug_printk("compflt: [f:block_cache_init]\n");

        block_cache = kmem_cache_create(CACHE_NAME, sizeof(struct block), 0, 0, NULL, NULL);

        if (!block_cache) {
                printk(KERN_ERR "compflt: failed to allocate block cache\n");
                return -ENOMEM;
        }

        INIT_LIST_HEAD(&block_list);

        return 0;
}

void block_cache_deinit(void)
{
        struct block *blk;
        struct block *tmp;

        debug_printk("compflt: [f:block_cache_deinit]\n");

        read_lock(&block_list_l);
        list_for_each_entry_safe(blk, tmp, &block_list, all) {
                block_deinit(blk);
        }
        read_unlock(&block_list_l);

        spin_lock(&block_cache_l);
        if(kmem_cache_destroy(block_cache))
                printk(KERN_ERR "compflt: failed to destroy block cache\n");
        block_cache = NULL;
        spin_unlock(&block_cache_l);
}

struct block* block_init(void)
{
        struct block *blk;

        debug_printk("compflt: [f:block_init]\n");

        spin_lock(&block_cache_l);
        blk = kmem_cache_alloc(block_cache, SLAB_KERNEL);
        spin_unlock(&block_cache_l);

        if (!blk) {
                printk(KERN_ERR "compflt: failed to allocate a block\n");
                return NULL;
        }

        blk->data_u = NULL;
        blk->type = 1;
        blk->dirty = 0;
        blk->off_u = 0;
        blk->off_c = 0;
        blk->off_next = 0;
        blk->size_u = 0;
        blk->size_c = 0;

        write_lock(&block_list_l);
        list_add(&blk->all, &block_list);
        write_unlock(&block_list_l);
        INIT_LIST_HEAD(&blk->file);

        return blk;
}

void block_deinit(struct block *blk)
{
        debug_printk("compflt: [f:block_deinit]\n");

        list_del(&blk->all);
        list_del(&blk->file);
        spin_lock(&block_cache_l);
        kmem_cache_free(block_cache, blk);
        spin_unlock(&block_cache_l);
}

// sets off to the start of the next header (or 0 if last)
int block_read_header(struct file *f, struct block *blk, loff_t *off)
{
        int rv = 0;

        blk->off_c = *off;

        // TODO: do all this in one read
        rv = orig_read(f, (u8*)&blk->type, sizeof(u8), off);
        if (!rv) {
                return -1; // eof
        }

        // TODO: handle 'free' blocks
        if (!blk->type)
                return -1;

        orig_read(f, (char*)&blk->off_u, sizeof(u32), off);
        orig_read(f, (char*)&blk->off_next, sizeof(u32), off);
        orig_read(f, (char*)&blk->size_c, sizeof(u32), off);
        orig_read(f, (char*)&blk->size_u, sizeof(u32), off);

        *off = blk->off_next;

        return 0;
}

int block_write_header(struct file *f, struct block *blk)
{
        loff_t off;

        if (!blk->dirty)
                return 0;
        
        off = blk->off_c;
        // TODO: do all this in one write
        orig_write(f, (char*)&blk->type, sizeof(u8), &off);
        orig_write(f, (char*)&blk->off_u, sizeof(u32), &off);
        orig_write(f, (char*)&blk->off_next, sizeof(u32), &off);
        orig_write(f, (char*)&blk->size_c, sizeof(u32), &off);
        orig_write(f, (char*)&blk->size_u, sizeof(u32), &off);
        blk->dirty = 0;

        return 0;
}

static char* block_read_c(struct file *f, struct block *blk)
{
        char *block_c = NULL;
        loff_t off_data = blk->off_c + COMPFLT_BH_SIZE;

        debug_printk("compflt: [f:block_read_c]\n");

        block_c = kmalloc(blk->size_c, GFP_KERNEL);
        if (!block_c)
                return NULL;

        orig_read(f, block_c, blk->size_c, &off_data);

        return block_c;
}

int block_read(struct file *f, struct block *blk, struct crypto_tfm *tfm)
{
        char *block_c = NULL;

        debug_printk("compflt: [f:block_read]\n");

        if(!(block_c = block_read_c(f, blk))) {
                printk(KERN_ERR "compflt: failed to read data block\n");
                return -1;
        }

        blk->data_u = decomp_block(tfm, blk, block_c);
        if(!blk->data_u)
                return -1;

        kfree(block_c);
        return 0;
}

int block_write(struct file *f, struct block *blk, struct crypto_tfm *tfm)
{
        char *block_c;
        loff_t off_data;
        size_t old = blk->size_c;

        debug_printk("compflt: [f:block_write]\n");

        block_c = comp_block(tfm, blk, blk->data_u);
        if(!block_c)
                return -1;

        if (blk->size_c != old) {
                // TODO: manage block size changes
                // this will be handled in cblock
                blk->dirty = 1;
        }

        off_data = blk->off_c + COMPFLT_BH_SIZE;

        orig_write(f, block_c, blk->size_c, &off_data);

        kfree(block_c);

        return 0;
}

