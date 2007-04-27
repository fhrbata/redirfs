#include <linux/slab.h>
#include <linux/spinlock.h>
#include "compflt.h"

#define CACHE_NAME "cflt_file"

static struct kmem_cache *cflt_file_cache = NULL;
spinlock_t cflt_file_cache_l = SPIN_LOCK_UNLOCKED;

struct list_head cflt_file_list;
rwlock_t cflt_file_list_l = RW_LOCK_UNLOCKED;

static unsigned int cflt_blksize = CFLT_DEFAULT_BLKSIZE;

inline void cflt_file_reset(struct cflt_file *fh, unsigned long ino)
{
        cflt_debug_printk("compflt: [f:cflt_file_reset] i=%li\n", ino);

        fh->ino = ino;
        fh->dirty = 0;
        fh->compressed = 0;
        fh->size = 0;
        fh->method = cflt_cmethod;
        fh->blksize = cflt_blksize;
}

inline void cflt_file_clr_blks(struct cflt_file *fh)
{
        struct cflt_block *blk;
        struct cflt_block *tmp;

        cflt_debug_printk("compflt: [f:cflt_file_clr_blks]\n");

        list_for_each_entry_safe(blk, tmp, &fh->blks, file) {
                cflt_block_deinit(blk);
        }
}

static struct cflt_file* cflt_file_init(unsigned long ino)
{
        struct cflt_file *fh;

        cflt_debug_printk("compflt: [f:cflt_file_init] i=%li\n", ino);

        spin_lock(&cflt_file_cache_l);
        fh = kmem_cache_alloc(cflt_file_cache, GFP_KERNEL);
        spin_unlock(&cflt_file_cache_l);

        if (!fh) {
                printk(KERN_ERR "compflt: failed to alloc file header\n");
                return NULL;
        }

        INIT_LIST_HEAD(&fh->blks);

        cflt_file_reset(fh, ino);

        return fh;
}

void cflt_file_deinit(struct cflt_file *fh)
{
        cflt_debug_printk("compflt: [f:cflt_file_deinit] i=%li\n", fh->ino);

        list_del(&fh->all);

        cflt_file_clr_blks(fh);

        spin_lock(&cflt_file_cache_l);
        kmem_cache_free(cflt_file_cache, fh);
        spin_unlock(&cflt_file_cache_l);
}

int cflt_file_cache_init(void)
{
        cflt_debug_printk("compflt: [f:cflt_file_cache_init]\n");

        cflt_file_cache = kmem_cache_create(CACHE_NAME, sizeof(struct cflt_file), 0, 0, NULL, NULL);

        if (!cflt_file_cache)
                return -ENOMEM;

        INIT_LIST_HEAD(&cflt_file_list);

        return 0;
}


void cflt_file_cache_deinit(void)
{
        struct cflt_file *fh;
        struct cflt_file *tmp;

        cflt_debug_printk("compflt: [f:cflt_file_cache_deinit]\n");

        read_lock(&cflt_file_list_l);
        list_for_each_entry_safe(fh, tmp, &cflt_file_list, all) {
                cflt_file_deinit(fh);
        }
        read_unlock(&cflt_file_list_l);

        // TODO: "The caller must guarantee that noone will allocate memory
        // from the cache during the kmem_cache_destroy."
        spin_lock(&cflt_file_cache_l);
        kmem_cache_destroy(cflt_file_cache);
        spin_unlock(&cflt_file_cache_l);
}

// TODO: add it to the right place , so we get a sequential list of mappings
// it does work so far , because all blocks are placed sequentialy so far
void cflt_file_add_blk(struct cflt_file *fh, struct cflt_block *blk)
{
        cflt_debug_printk("compflt: [f:cflt_file_add_blk] i=%li\n", fh->ino);

        blk->par = fh;

        switch(blk->type) {
        case CFLT_BLK_FREE:
                // TODO: free block
                break;
        case CFLT_BLK_NORM:
                list_add_tail(&(blk->file), &fh->blks);
                break;
        default:
                // TODO
                break;
        }

}

void cflt_file_del_blk(struct cflt_file *fh, struct cflt_block *blk)
{
        cflt_debug_printk("compflt: [f:cflt_file_del_blk] i=%li\n", fh->ino);

        list_del(&blk->file);
}

struct cflt_file *cflt_file_find(unsigned long ino)
{
        struct cflt_file *buf;

        cflt_debug_printk("compflt: [f:cflt_file_find] i=%li\n", ino);

        read_lock(&cflt_file_list_l);
        list_for_each_entry(buf, &cflt_file_list, all) {
                if (buf->ino == ino)
                        goto out;
        }

        buf = NULL;
out:
        read_unlock(&cflt_file_list_l);
        return buf;
}

static int cflt_file_read_block_headers(struct file *f, struct cflt_file *fh)
{
        int err = 0;
        loff_t off = CFLT_FH_SIZE;
        struct cflt_block *blk;

        cflt_debug_printk("compflt: [f:cflt_file_read_block_headers]\n");

        while(!err && off) {
                blk = cflt_block_init();
                if (!blk) {
                        // TODO: change cflt_block_init prototype to return the error
                        err = -ENOMEM;
                        printk(KERN_ERR "compflt: failed to init a block\n");
                        return err;
                }

                if (!(err = cflt_block_read_header(f, blk, &off)))
                        cflt_file_add_blk(fh, blk);
        }

        return err;
}

struct cflt_file *cflt_file_get_header(struct file *f)
{
        struct cflt_file *fh = NULL;
        unsigned long ino = f->f_dentry->d_inode->i_ino;

        cflt_debug_printk("compflt: [f:cflt_file_get] i=%li\n", ino);

        fh = cflt_file_find(ino);

        if (!fh) {
                fh = cflt_file_init(ino);
                if(cflt_file_read(f, fh)) {
                        printk(KERN_ERR "compflt: failed to read file header\n");
                        cflt_file_deinit(fh);
                        return NULL;
                }
                write_lock(&cflt_file_list_l);
                list_add(&(fh->all), &(cflt_file_list));
                write_unlock(&cflt_file_list_l);

                if (fh->compressed)
                        cflt_file_read_block_headers(f, fh);

        }
        return fh;
}

int cflt_file_blksize_set(unsigned int new)
{
        if (new >= CFLT_BLKSIZE_MIN && new <= CFLT_BLKSIZE_MAX && !(new%CFLT_BLKSIZE_MOD)) {
                cflt_blksize = new;
                printk(KERN_INFO "compflt: block size set to %i bytes\n", new);
        }

        return 0;
}

int cflt_file_proc_blksize(char* buf, int bsize)
{
        int len = 0;
        len = sprintf(buf, "%i\n", cflt_blksize);
        return len;
}

int cflt_file_read(struct file *f, struct cflt_file *fh)
{
        char buf[CFLT_FH_SIZE];
        loff_t off = 0;
        int boff = 0;
        int rv = 0;

        cflt_debug_printk("compflt: [f:cflt_file_read] i=%li\n", fh->ino);

        rv = cflt_orig_read(f, buf+boff, sizeof(buf), &off);
        if(rv < sizeof(CFLT_MAGIC)-1 || memcmp(buf, CFLT_MAGIC, sizeof(CFLT_MAGIC)-1)) {
                fh->dirty = 1;
                return 0;
        }
        fh->compressed = 1;
        boff += sizeof(CFLT_MAGIC)-1;
        memcpy(&fh->method, buf+boff, sizeof(u8));
        boff += sizeof(u8);
        memcpy(&fh->blksize, buf+boff, sizeof(u32));

        cflt_debug_file_header(fh);

        return 0;
}

void cflt_file_write(struct file *f, struct cflt_file *fh)
{
        loff_t off = 0;
        char buf[CFLT_FH_SIZE];
        int boff = 0;

        cflt_debug_printk("compflt: [f:cflt_file_write] i=%li\n", fh->ino);

        if (!fh->dirty)
                return;

        memcpy(buf+boff, CFLT_MAGIC, sizeof(CFLT_MAGIC)-1);
        boff += sizeof(CFLT_MAGIC)-1;
        memcpy(buf+boff, &fh->method, sizeof(u8));
        boff += sizeof(u8);
        memcpy(buf+boff, &fh->blksize, sizeof(u32));
        cflt_orig_write(f, buf, sizeof(buf), &off);

        fh->dirty = 0;
}
