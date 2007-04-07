#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

static int rle_init(struct crypto_tfm *tfm)
{
        return 0;
}

static void rle_exit(struct crypto_tfm *tfm)
{
        return;
}

static int rle_compress(struct crypto_tfm *tfm, const u8 *src,
			    unsigned int slen, u8 *dst, unsigned int (*dlen))
{
        u8 last;
        int cnt = 0;
        int inp = 0;
	int ret = 0;

        *dlen = 0;

        while (inp < slen)
        {
                if (src[inp] == src[inp+1]) {
                        last = src[inp];
                        dst[(*dlen)++] = last;
                        dst[(*dlen)++] = last;
                        inp += 2;
                        if (inp >= slen)
                                return ret;
                        while (src[inp] == last) {
                                cnt++; inp++;
                                if (inp >= slen) 
                                        break;
                        }
                        dst[(*dlen)++] = (u8)cnt;
                        cnt = 0;
                }
                else {
                        dst[(*dlen)++] = src[inp];
                        inp++;
                }
        }

	return ret;
}
 
static int rle_decompress(struct crypto_tfm *tfm, const u8 *src,
			      unsigned int slen, u8 *dst, unsigned int (*dlen))
{
        u8 last;
        int inp = 0;
	int ret = 0;
        int i;

        *dlen = 0;

        while (inp < slen) {
                if (src[inp] == src[inp+1]) {
                        last = src[inp];
                        dst[(*dlen)++] = last;
                        dst[(*dlen)++] = last;
                        inp += 2;
                        if (inp >= slen) // shouldnt happen here
                                return ret;
                        for (i = 0; i < (int)src[inp]; i++)
                                dst[(*dlen)++] = last;
                }
                else {
                        dst[(*dlen)++] = src[inp];
                }
                inp++;
        }

	return ret;
}

static struct crypto_alg alg = {
	.cra_name		= "rle",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_ctxsize		= 0,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(alg.cra_list),
	.cra_init		= rle_init,
	.cra_exit		= rle_exit,
	.cra_u			= { .compress = {
	.coa_compress 		= rle_compress,
	.coa_decompress  	= rle_decompress } }
};

static int __init init(void)
{
	return crypto_register_alg(&alg);
}

static void __exit exit(void)
{
	crypto_unregister_alg(&alg);
}

module_init(init);
module_exit(exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Jan Podrouzek <xpodro01@stud.fit.vutbr.cz>");
MODULE_DESCRIPTION("Simple RLE compression CryptoAPI transform");
