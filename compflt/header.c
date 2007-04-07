#include <linux/slab.h>
#include "compflt.h"

static kmem_cache_t *header_cache = NULL;
static struct header header_list;
//rwlock_t header_list_l = RW_LOCK_UNLOCKED;

void header_add_dm(struct header *fh, struct dmap *dm)
{
        printk("compflt: [f:header_add_dm] i=%li\n", fh->ino);

        list_add(&(dm->list), &(fh->map.list));
        fh->blocks++;
}

void header_del_dm(struct header *fh, struct dmap *dm)
{
        printk("compflt: [f:dmap_add] i=%li\n", fh->ino);

        fh->blocks--;
        list_del(&dm->list);
}


static struct header* header_init(unsigned long ino)
{
        struct header *fh;

        printk("compflt: [f:header_init] i=%li\n", ino);

        fh = kmem_cache_alloc(header_cache, SLAB_KERNEL);

        if (!fh) {
                printk(KERN_ERR "compflt: failed to alloc file header\n");
                return NULL;
        }

        INIT_LIST_HEAD(&fh->map.list);
        fh->ino = ino;
        fh->dirty = 0;
        fh->blocks = 0;
        fh->compressed = 0;
        fh->method = COMPFLT_DEFAULT_CMETHOD;

        return fh;
}

static void header_deinit(struct header *fh)
{
        struct dmap *dm;
        struct dmap *tmp;

        printk("compflt: [f:header_deinit] i=%li\n", fh->ino);

        list_del(&fh->list);

        // clean dm list
        list_for_each_entry_safe(dm, tmp, &(fh->map.list), list) {
                dmap_deinit(dm);
        }
        kmem_cache_free(header_cache, fh);
}

int header_cache_init(void)
{
        printk("compflt: [f:header_cache_init]\n");

        header_cache = kmem_cache_create("header_cache", sizeof(struct header), 0, 0, NULL, NULL);

        if (!header_cache) {
                printk(KERN_ERR "compflt: failed to allocate file header cache\n");
                return 1;
        }

        INIT_LIST_HEAD(&header_list.list);

        return 0;
}


void header_cache_deinit(void)
{
        struct header *fh;
        struct header *tmp;

        printk("compflt: [f:header_cache_deinit]\n");

        list_for_each_entry_safe(fh, tmp, &header_list.list, list) {
                header_deinit(fh);
        }

        // TODO: "The caller must guarantee that noone will allocate memory
        // from the cache during the kmem_cache_destroy."
        kmem_cache_destroy(header_cache);
}

void header_del(unsigned long ino)
{
        struct header *fh;

        printk("compflt: [f:header_del] i=%li\n", ino);

        fh = header_find(ino);
        if (!fh)
                return;

        header_deinit(fh);
}

struct header *header_find(unsigned long ino)
{
        struct header *buf;

        printk("compflt: [f:header_find] i=%li\n", ino);

        list_for_each_entry(buf, &header_list.list, list) {
                if (buf->ino == ino) {
                        return buf;
                }
        }

        return NULL;
}

struct header *header_get(struct file *f)
{
        struct header *fh = NULL;
        unsigned long ino = f->f_dentry->d_inode->i_ino;

        printk("compflt: [f:header_get] i=%li\n", ino);

        fh = header_find(ino);

        if (!fh) {
                fh = header_init(ino);
                if(header_read(f, fh)) {
                        printk(KERN_ERR "compflt: failed to read header from file\n");
                        header_deinit(fh);
                        return NULL;
                }
                list_add(&(fh->list), &(header_list.list));
        }
        return fh;
}

int header_read(struct file *f, struct header *fh)
{
        int i;
        struct dmap *dm;
        u8 magic[4] = { 0, 0, 0, 0 };
        loff_t off;

        printk("compflt: [f:header_read] i=%li\n", fh->ino);

        off = 0;
        // read the magic number and compare it
        orig_read(f, magic, sizeof(magic), &off);
        if(memcmp(magic, COMPFLT_MAGIC, sizeof(magic)))
                return 0;

        fh->compressed = 1;

        // now we read the rest of the headers
        orig_read(f, &fh->method, sizeof(fh->method), &off);
        orig_read(f, (char *) &fh->blocks, sizeof(fh->blocks), &off);

        for (i = 0; i < fh->blocks; i++) {
                dm = dmap_init();
                if (!dm)
                        return 1;

                orig_read(f, (char *) &dm->off_c, sizeof(loff_t), &off);
                orig_read(f, (char *) &dm->off_u, sizeof(loff_t), &off);
                orig_read(f, (char *) &dm->size_c, sizeof(size_t), &off);
                orig_read(f, (char *) &dm->size_u, sizeof(size_t), &off);

                list_add(&(dm->list), &(fh->map.list));
        }

        return 0;
}

// TODO: make sure we dont go beyond the COMPFLT_FH_RESERVED barier
void header_write(struct file *f, struct header *fh)
{
        struct dmap *dm;
        loff_t off;

        printk("compflt: [f:header_write] i=%li\n", fh->ino);

        if (!fh->dirty)
                return;

        off = 0;
        orig_write(f, COMPFLT_MAGIC, sizeof(COMPFLT_MAGIC) - 1, &off);
        orig_write(f, &fh->method, sizeof(fh->method), &off);
        orig_write(f, (char *) &fh->blocks, sizeof(fh->blocks), &off);

        list_for_each_entry(dm, &(fh->map.list), list) {
                orig_write(f, (char *) &dm->off_c, sizeof(loff_t), &off);
                orig_write(f, (char *) &dm->off_u, sizeof(loff_t), &off);
                orig_write(f, (char *) &dm->size_c, sizeof(size_t), &off);
                orig_write(f, (char *) &dm->size_u, sizeof(size_t), &off);
        }
        fh->dirty = 0;
        fh->compressed = 1;
}
