#include <linux/slab.h>
#include <linux/spinlock.h>
#include "compflt.h"

#define CACHE_NAME "compflt_fheader"

static kmem_cache_t *fheader_cache = NULL;
spinlock_t fheader_cache_l = SPIN_LOCK_UNLOCKED;

struct list_head fheader_list;
rwlock_t fheader_list_l = RW_LOCK_UNLOCKED;

static struct fheader* fheader_init(unsigned long ino)
{
        struct fheader *fh;

        debug_printk("compflt: [f:fheader_init] i=%li\n", ino);

        spin_lock(&fheader_cache_l);
        fh = kmem_cache_alloc(fheader_cache, SLAB_KERNEL);
        spin_unlock(&fheader_cache_l);

        if (!fh) {
                printk(KERN_ERR "compflt: failed to alloc file fheader\n");
                return NULL;
        }

        INIT_LIST_HEAD(&fh->map.file);
        fh->ino = ino;
        fh->dirty = 0;
        fh->compressed = 0;
        fh->method = comp_method();
        fh->size = 0;

        return fh;
}

inline void fheader_clear_blks(struct fheader *fh)
{
        struct block *blk;
        struct block *tmp;

        list_for_each_entry_safe(blk, tmp, &(fh->map.file), file) {
                block_deinit(blk);
        }
}

void fheader_deinit(struct fheader *fh)
{
        debug_printk("compflt: [f:fheader_deinit] i=%li\n", fh->ino);

        list_del(&fh->all);
        fheader_clear_blks(fh);

        spin_lock(&fheader_cache_l);
        kmem_cache_free(fheader_cache, fh);
        spin_unlock(&fheader_cache_l);
}

int fheader_cache_init(void)
{
        debug_printk("compflt: [f:fheader_cache_init]\n");

        fheader_cache = kmem_cache_create(CACHE_NAME, sizeof(struct fheader), 0, 0, NULL, NULL);

        if (!fheader_cache) {
                printk(KERN_ERR "compflt: failed to allocate file fheader cache\n");
                return -ENOMEM;
        }

        INIT_LIST_HEAD(&fheader_list);

        return 0;
}


void fheader_cache_deinit(void)
{
        struct fheader *fh;
        struct fheader *tmp;

        debug_printk("compflt: [f:fheader_cache_deinit]\n");

        read_lock(&fheader_list_l);
        list_for_each_entry_safe(fh, tmp, &fheader_list, all) {
                fheader_deinit(fh);
        }
        read_unlock(&fheader_list_l);

        // TODO: "The caller must guarantee that noone will allocate memory
        // from the cache during the kmem_cache_destroy."
        spin_lock(&fheader_cache_l);
        kmem_cache_destroy(fheader_cache);
        spin_unlock(&fheader_cache_l);
}

// TODO: add it to the right place , so we get a sequential list of mappings
// it does work so far , because all blocks are placed sequentialy so far
void fheader_add_blk(struct fheader *fh, struct block *blk)
{
        debug_printk("compflt: [f:fheader_add_blk] i=%li\n", fh->ino);

        list_add_tail(&(blk->file), &(fh->map.file));
}

void fheader_del_blk(struct fheader *fh, struct block *blk)
{
        debug_printk("compflt: [f:block_add] i=%li\n", fh->ino);

        list_del(&blk->file);
}

void fheader_del(unsigned long ino)
{
        struct fheader *fh;

        debug_printk("compflt: [f:fheader_del] i=%li\n", ino);

        fh = fheader_find(ino);
        if (!fh)
                return;

        fheader_deinit(fh);
}

struct fheader *fheader_find(unsigned long ino)
{
        struct fheader *buf;

        debug_printk("compflt: [f:fheader_find] i=%li\n", ino);

        read_lock(&fheader_list_l);
        list_for_each_entry(buf, &fheader_list, all) {
                if (buf->ino == ino)
                        goto out;
        }

        buf = NULL;
out:
        read_unlock(&fheader_list_l);
        return buf;
}

struct fheader *fheader_get(struct file *f)
{
        struct fheader *fh = NULL;
        unsigned long ino = f->f_dentry->d_inode->i_ino;

        debug_printk("compflt: [f:fheader_get] i=%li\n", ino);

        fh = fheader_find(ino);

        if (!fh) {
                fh = fheader_init(ino);
                if(fheader_read(f, fh)) {
                        printk(KERN_ERR "compflt: failed to read fheader from file\n");
                        fheader_deinit(fh);
                        return NULL;
                }
                write_lock(&fheader_list_l);
                list_add(&(fh->all), &(fheader_list));
                write_unlock(&fheader_list_l);
        }
        return fh;
}

int fheader_read(struct file *f, struct fheader *fh)
{
        struct block *blk;
        u8 magic[4] = { 0, 0, 0, 0 };
        loff_t off = 0;
        int rv = 0;

        debug_printk("compflt: [f:fheader_read] i=%li\n", fh->ino);

        // TODO: do all this in one read
        orig_read(f, magic, sizeof(magic), &off);
        if(memcmp(magic, COMPFLT_MAGIC, sizeof(magic))) {
                fh->dirty = 1;
                return 0;
        }
        fh->compressed = 1;
        orig_read(f, (u8*)&fh->method, sizeof(u8), &off);

        while(!rv && off) {
                blk = block_init();
                if (!blk)
                        return -ENOMEM;
                rv = block_read_header(f, blk, &off);
                fheader_add_blk(fh, blk);
        }

        return 0;
}

void fheader_write(struct file *f, struct fheader *fh)
{
        struct block *blk;
        loff_t off = 0;

        debug_printk("compflt: [f:fheader_write] i=%li\n", fh->ino);

        if (fh->dirty) {
                // TODO: do all this in one write
                orig_write(f, COMPFLT_MAGIC, sizeof(COMPFLT_MAGIC) - 1, &off);
                orig_write(f, (u8*)&fh->method, sizeof(u8), &off);
                fh->dirty = 0;
        }

        list_for_each_entry(blk, &(fh->map.file), file) {
                block_write_header(f, blk);
        }
}
