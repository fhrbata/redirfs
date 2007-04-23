#include <linux/crypto.h>
#include "compflt.h"

char *comp_methods[] = { "deflate", "lzf", "bzip2", "rle", NULL };
int cmethod = 0; // deflate is default

struct crypto_tfm *comp_init(unsigned int mid)
{
        struct crypto_tfm *tfm = NULL;

        debug_printk("compflt: [f:comp_init]\n");

        // initialize compression algorithm
        if (!crypto_alg_available(comp_methods[mid], 0)) {
                printk(KERN_ERR "compflt: compression method %s "
                                "unavailable\n", comp_methods[mid]);
                return NULL;
        }

        tfm = crypto_alloc_tfm(comp_methods[mid], 0);
        if (tfm == NULL) {
                printk(KERN_ERR "compflt: failed to alloc %s "
                                "compression method\n", comp_methods[mid]);
                return NULL;
        }

        return tfm;
}

inline void comp_deinit(struct crypto_tfm *tfm)
{
        crypto_free_tfm(tfm);
}

char* decomp_block(struct crypto_tfm *tfm, struct block *blk, char *block_c)
{
        char *block_u = NULL;

        debug_printk("compflt: [f:decomp_block]\n");

        // we use COMPFLT_BLOCK_SIZE_U instead of blk->size_u , because we might
        // be adding data to the block (write operation)
        block_u = kmalloc(COMPFLT_BLOCK_SIZE_U, GFP_KERNEL);
        if (!block_u) {
                printk(KERN_ERR "compflt: failed to allocate %i bytes\n", blk->size_u);
                return NULL;
        }

	memset(block_u, 0, COMPFLT_BLOCK_SIZE_U);
	if (crypto_comp_decompress(tfm, block_c, blk->size_c, block_u, &blk->size_u)) {
                printk(KERN_ERR "compflt: failed to decompress data block\n");
                kfree(block_u);
                return NULL;
        }

        debug_printk("compflt: [f:decomp_block] decompressed %i bytes | ratio=%i:%i\n", blk->size_c, blk->size_c, blk->size_u);

        return block_u;
}

char* comp_block(struct crypto_tfm *tfm, struct block *blk, char *block_u)
{
        char *block_c = NULL;
        unsigned int size_c;

        debug_printk("compflt: [f:comp_block]\n");

        size_c = 2*COMPFLT_BLOCK_SIZE_U;
        block_c = kmalloc(size_c, GFP_KERNEL);
        if (!block_c) {
                printk(KERN_ERR "compflt: failed to allocate %i bytes\n", size_c);
                return NULL;
        }

	memset(block_c, 0, size_c);
        if(crypto_comp_compress(tfm, block_u, blk->size_u, block_c, &size_c)) {
                printk(KERN_ERR "compflt: failed to compress data block\n");
                kfree(block_c);
                return NULL;
        }

        debug_printk("compflt: [f:comp_block] compressed %i bytes | ratio=%i:%i\n", blk->size_u, size_c, blk->size_u);

        blk->size_c = size_c;

        return block_c;
}

inline int comp_method(void)
{
        return cmethod;
}

int comp_proc_get(char* buf, int bsize)
{
        int len = 0;

        if (strlen(comp_methods[cmethod]) > bsize)
                return 0;

        len = sprintf(buf, "%s\n", comp_methods[cmethod]);
        return len;
}

void comp_proc_set(char* buf)
{
        char **p = comp_methods;
        int i = 0;

        while (*p) {
                if(!strcmp(*p, buf)) {
                        if (crypto_alg_available(*p, 0)) {
                                cmethod = i;
                                printk(KERN_INFO "compflt: compression method set to '%s'\n", *p);
                        }
                        else {
                                printk(KERN_INFO "compflt: compression method '%s' unavailable\n", *p);
                        }
                        break;
                }
                p++; i++;
        }
}

int comp_stat(char *buf, int bsize)
{
        int len = 0;
        struct fheader *fh;
        struct block *blk;
        long u, c, overhead;

        if (len + 60 > bsize)
                return len;
        len += sprintf(buf, "%-12s%-12s%-12s%-12s%-11s\n", "[ino]", "[alg]", "[comp]", "[decomp]", "[ohead]");

        list_for_each_entry_reverse(fh, &fheader_list, all) {
                if (len + 60 > bsize)
                        return len;

                u = c = 0;
                overhead = COMPFLT_FH_SIZE;
                list_for_each_entry(blk, &(fh->map.file), file) {
                        overhead += COMPFLT_BH_SIZE;
                        u += blk->size_u;
                        c += blk->size_c;
                }
                len += sprintf(buf+len, "%-12li%-12s%-12li%-12li%-11li\n", fh->ino, comp_methods[fh->method], c, u, overhead);
        }

        return len;
}
