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

static int null_cpy (struct crypto_tfm *tfm, const u8 *src,
			    unsigned int slen, u8 *dst, unsigned int (*dlen))
{
        int ret = 0;
        int i;

        *dlen = 0;
        for (i = 0; i < slen; i++) {
                dst[(*dlen)++] = src[i];
        }

	return ret;
}
 
static struct crypto_alg alg = {
	.cra_name		= "null",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_ctxsize		= 0,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(alg.cra_list),
	.cra_init		= rle_init,
	.cra_exit		= rle_exit,
	.cra_u			= { .compress = {
	.coa_compress 		= null_cpy,
	.coa_decompress  	= null_cpy } }
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
MODULE_DESCRIPTION("null compression algorithm for CryptoAPI");
