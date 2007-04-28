#include <linux/kernel.h>
#include "compflt.h"

#ifdef CFLT_DEBUG

void cflt_debug_block(struct cflt_block *blk)
{
        printk("compflt: [block] %i@%i -> %i@%i\n",
        (int)blk->size_c, (int)blk->off_c, (int)blk->size_u, (int)blk->off_u);
}

void cflt_debug_file_header(struct cflt_file *fh)
{
        printk("compflt: [file] ino=%li compressed=%i dirty=%i method=%i blksize=%i size=%li\n",
                        fh->inode->i_ino, fh->compressed, fh->dirty, fh->method,
                        fh->blksize, fh->size);
}

void cflt_hexdump(void *buf, unsigned int len)
{
        int i = 0;

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
