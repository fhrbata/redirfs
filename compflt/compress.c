#include <linux/crypto.h>
#include "compflt.h"

char *methods[] = { "rle", "deflate" };

struct crypto_tfm *comp_init(unsigned int mid)
{
        struct crypto_tfm *tfm;

        printk("compflt: [f:comp_init]\n");

        // initialize compression algorithm
        if (!crypto_alg_available(methods[mid], 0)) {
                printk(KERN_ERR "compflt: compression algorithm %s "
                                "unavailable\n", methods[mid]);
                return NULL;
        }

        tfm = crypto_alloc_tfm(methods[mid], 0);
        if (tfm == NULL) {
                printk(KERN_ERR "compflt: failed to alloc %s "
                                "compression algorithm\n", methods[mid]);
                return NULL;
        }

        return tfm;
}
