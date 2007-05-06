#include <linux/slab.h>
#include <linux/spinlock.h>
#include "../redirfs/redirfs.h"
#include "compflt.h"

#define CACHE_NAME "cflt_file"

static struct kmem_cache *cflt_file_cache = NULL;
//spinlock_t cflt_file_cache_l = SPIN_LOCK_UNLOCKED;

struct list_head cflt_file_list;
spinlock_t cflt_file_list_l = SPIN_LOCK_UNLOCKED;

static unsigned int cflt_blksize = CFLT_DEFAULT_BLKSIZE;

// reset (struct cflt_file) values
inline void cflt_file_reset(struct cflt_file *fh, struct inode *inode)
{
        cflt_debug_printk("compflt: [f:cflt_file_reset] i=%li\n", inode->i_ino);

        fh->inode = inode;
        fh->size_u = 0;
        fh->method = cflt_cmethod;
        fh->blksize = cflt_blksize;
        atomic_set(&fh->cnt, 0);
        atomic_set(&fh->dirty, 0);
        atomic_set(&fh->compressed, 0);
}

// deinit all block belonging to this file
inline void cflt_file_clr_blks(struct cflt_file *fh)
{
        struct cflt_block *blk;
        struct cflt_block *tmp;

        cflt_debug_printk("compflt: [f:cflt_file_clr_blks]\n");

        list_for_each_entry_safe(blk, tmp, &fh->blks, file) {
                //spin_lock(&fh->lock);
                list_del(&blk->file);
                //spin_unlock(&fh->lock);
                cflt_block_deinit(blk);
        }
}

// alloc and initialize a (struct cflt_file)
static struct cflt_file* cflt_file_init(struct inode *inode)
{
        struct cflt_file *fh;

        cflt_debug_printk("compflt: [f:cflt_file_init] i=%li\n", inode->i_ino);

        //spin_lock(&cflt_file_cache_l);
        fh = kmem_cache_alloc(cflt_file_cache, GFP_KERNEL);
        //spin_unlock(&cflt_file_cache_l);

        if (!fh) {
                printk(KERN_ERR "compflt: failed to alloc file header\n");
                return NULL;
        }

        INIT_LIST_HEAD(&fh->blks);

        cflt_file_reset(fh, inode);

        //spin_lock(&cflt_file_list_l);
        list_add(&(fh->all), &(cflt_file_list));
        //spin_unlock(&cflt_file_list_l);

        return fh;
}

// dealloc a (struct cflt_file) and remove from master file list
static void cflt_file_deinit(struct cflt_file *fh)
{
        cflt_debug_printk("compflt: [f:cflt_file_deinit] i=%li\n", fh->inode->i_ino);

        // TODO: wait for fh->cnt to be 0 before we deinit
        BUG_ON(atomic_read(&fh->cnt));

        spin_lock(&cflt_file_list_l);
        list_del(&fh->all);
        spin_unlock(&cflt_file_list_l);

        cflt_file_clr_blks(fh);

        //spin_lock(&cflt_file_cache_l);
        kmem_cache_free(cflt_file_cache, fh);
        //spin_unlock(&cflt_file_cache_l);
}

// callback registered with redirfs
static inline void cflt_file_deinit_cb(void *data)
{
        cflt_file_deinit((struct cflt_file*)data);
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

        list_for_each_entry_safe(fh, tmp, &cflt_file_list, all) {
                cflt_file_deinit(fh);
        }

        BUG_ON(!list_empty(&cflt_file_list));

        //spin_lock(&cflt_file_cache_l);
        kmem_cache_destroy(cflt_file_cache);
        //spin_unlock(&cflt_file_cache_l);
}

// TODO: add it to the right place , so we get a sequential list of mappings
// it does work so far , because all blocks are placed sequentialy so far
void cflt_file_add_blk(struct cflt_file *fh, struct cflt_block *blk)
{
        cflt_debug_printk("compflt: [f:cflt_file_add_blk] i=%li\n", fh->inode->i_ino);

        blk->par = fh;

        switch(blk->type) {
        case CFLT_BLK_FREE:
                //spin_lock(&fh->lock);
                list_add_tail(&(blk->file), &fh->free);
                //spin_unlock(&fh->lock);
                break;
        case CFLT_BLK_NORM:
                //spin_lock(&fh->lock);
                list_add_tail(&(blk->file), &fh->blks);
                //spin_unlock(&fh->lock);
                fh->size_u += blk->size_u;
                break;
        default:
                // TODO
                break;
        }
}

//  void cflt_file_del_blk(struct cflt_file *fh, struct cflt_block *blk)
//  {
//  }

// read all block headers from file
int cflt_file_read_block_headers(struct file *f, struct cflt_file *fh)
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

                err = cflt_block_read_header(f, blk, &off);
                if (err)
                        cflt_block_deinit(blk);
                else 
                        cflt_file_add_blk(fh, blk);
        }

        return err;
}

// write headers of all blocks to file
void cflt_file_write_block_headers(struct file *f, struct cflt_file *fh)
{
        struct cflt_block *blk;

        cflt_debug_printk("compflt: [f:cflt_block_write_block_headers]\n");

        //spin_lock(&fh->lock);
        list_for_each_entry(blk, &fh->blks, file) {
                cflt_block_write_header(f, blk);
        }
        //spin_unlock(&fh->lock);
}

// TODO: change to return int , and move cflt_file to params
// try to find the cflt_field corresponding to inode in the cache
struct cflt_file *cflt_file_find(struct inode *inode)
{
        struct cflt_file *fh = NULL;

        cflt_debug_printk("compflt: [f:cflt_file_find] i=%li\n", inode->i_ino);

        rfs_get_data_inode(compflt, inode, (void**)&fh);

        return fh;
}

// if the cflt_file is not in the cache and f is set then try to read it from
// the file
struct cflt_file *cflt_file_get(struct inode *inode, struct file *f)
{
        struct cflt_file *fh = NULL;

        cflt_debug_printk("compflt: [f:cflt_file_get] i=%li\n", inode->i_ino);

        fh = cflt_file_find(inode);
        if (!fh && f) {
                fh = cflt_file_init(inode);

                if (!fh)
                        return NULL;

                if (cflt_file_read(f, fh)) {
                        // not an error (file doesnt exist or not copressed)
                        printk(KERN_ERR "compflt: failed to read file header\n");
                        cflt_file_deinit(fh);
                        return NULL;
                }

                rfs_attach_data_inode(compflt, inode, (void*)fh, cflt_file_deinit_cb);
                if (atomic_read(&fh->compressed))
                        cflt_file_read_block_headers(f, fh);

        }

        if (fh)
                atomic_inc(&fh->cnt);

        return fh;
}

void cflt_file_put(struct cflt_file *fh)
{
        BUG_ON(!atomic_read(&fh->cnt));

        atomic_dec(&fh->cnt);

        /* atm we only deinit on redirfs cb
        if(atomic_dec_and_test(&fh->cnt))
                cflt_file_deinit(fh);
                */
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

        cflt_debug_printk("compflt: [f:cflt_file_read] i=%li\n", fh->inode->i_ino);

        rv = cflt_orig_read(f, buf+boff, sizeof(buf), &off);
        if(rv < sizeof(CFLT_MAGIC)-1 || memcmp(buf, CFLT_MAGIC, sizeof(CFLT_MAGIC)-1)) {
                atomic_set(&fh->dirty, 1);
                return 0;
        }
        atomic_set(&fh->compressed, 1);
        boff += sizeof(CFLT_MAGIC)-1;
        memcpy(&fh->method, buf+boff, sizeof(u8));
        boff += sizeof(u8);
        memcpy(&fh->blksize, buf+boff, sizeof(u32));

        return 0;
}

void cflt_file_write(struct file *f, struct cflt_file *fh)
{
        loff_t off = 0;
        char buf[CFLT_FH_SIZE];
        int boff = 0;

        cflt_debug_printk("compflt: [f:cflt_file_write] i=%li\n", fh->inode->i_ino);

        if (!atomic_read(&fh->dirty))
                return;

        memcpy(buf+boff, CFLT_MAGIC, sizeof(CFLT_MAGIC)-1);
        boff += sizeof(CFLT_MAGIC)-1;
        memcpy(buf+boff, &fh->method, sizeof(u8));
        boff += sizeof(u8);
        memcpy(buf+boff, &fh->blksize, sizeof(u32));
        cflt_orig_write(f, buf, sizeof(buf), &off);

        atomic_set(&fh->dirty, 0);
}

int cflt_file_proc_stat(char *buf, int bsize)
{
        int len = 0;
        struct cflt_file *fh;
        struct cflt_block *blk;
        long u, c, overhead;

        if (len + 68 > bsize)
                return len;
        len += sprintf(buf, "%-10s%-12s%-10s%-12s%-12s%-11s\n", "ino", "alg", "blksize", "comp", "ohead", "decomp");

        spin_lock(&cflt_file_list_l);
        list_for_each_entry_reverse(fh, &cflt_file_list, all) {
                if (len + 68 > bsize)
                        return len;

                u = c = 0;
                overhead = CFLT_FH_SIZE;
                //spin_lock(&fh->lock);
                list_for_each_entry(blk, &fh->blks, file) {
                        overhead += CFLT_BH_SIZE;
                        u += blk->size_u;
                        c += blk->size_c;
                }
                //spin_unlock(&fh->lock);
                len += sprintf(buf+len, "%-10li%-12s%-10i%-12li%-12li%-11li\n", fh->inode->i_ino, cflt_method_known[fh->method], fh->blksize, c, overhead, u);
        }
        spin_unlock(&cflt_file_list_l);

        return len;
}
