#include <linux/slab.h>
#include "compflt.h"

static kmem_cache_t *dmap_cache = NULL;
static struct dmap dmap_list;
//rwlock_t dmap_list_l = RW_LOCK_UNLOCKED;

int dmap_cache_init(void)
{
        printk("compflt: [f:dmap_cache_init]\n");

        dmap_cache = kmem_cache_create("dmap_cache", sizeof(struct dmap), 0, 0, NULL, NULL);
        if (!dmap_cache) {
                printk(KERN_ERR "compflt: failed to allocate dmap cache\n");
                return 1;
        }

        INIT_LIST_HEAD(&dmap_list.all);

        return 0;
}

void dmap_cache_deinit(void)
{
        struct dmap *dm;
        struct dmap *tmp;

        printk("compflt: [f:dmap_cache_deinit]\n");

        list_for_each_entry_safe(dm, tmp, &dmap_list.all, all) {
                dmap_deinit(dm);
        }

        // TODO: "The caller must guarantee that noone will allocate memory
        // from the cache during the kmem_cache_destroy."
        kmem_cache_destroy(dmap_cache);
}

struct dmap* dmap_init(void)
{
        struct dmap *dm;

        printk("compflt: [f:dmap_init]\n");

        dm = kmem_cache_alloc(dmap_cache, SLAB_KERNEL);

        if (!dm) {
                printk(KERN_ERR "compflt: failed to alloc a dmap\n");
                return NULL;
        }

        dm->off_u = dm->off_c = dm->size_u = dm->size_c = 0;

        list_add(&dm->all, &dmap_list.all);
        INIT_LIST_HEAD(&dm->list);

        return dm;
}

void dmap_deinit(struct dmap *dm)
{
        printk("compflt: [f:dmap_deinit]\n");

        list_del(&dm->all);
        list_del(&dm->list);
        kmem_cache_free(dmap_cache, dm);
}
