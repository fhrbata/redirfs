#include <linux/kernel.h>
#include "compflt.h"

#ifdef COMPFLT_DEBUG

void debug_block(char *pre, struct block *blk)
{
        printk("%s map=%i@%i -> %i@%i\n", pre,
        (int)blk->size_c, (int)blk->off_c, (int)blk->size_u, (int)blk->off_u);
}

void hexdump(void *buf, unsigned int len)
{
        int i = 0;

        printk("\n");
        while (len--) {
                if (!(i % 16)) {
                        if (i) printk("\n");
                        printk("%07x ", i);
                }
                printk("%02x ", *(u8 *)buf++);
                i++;
        }
        printk("\n");
}

#endif
