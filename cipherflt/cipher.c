/*
 * cipherflt - RedirFS cryptographic filter
 *
 * Written by Pavel Zuna <xzunap00@stud.fit.vutbr.cz>
 *
 */

#include "cipherflt.h"

const char* cipherflt_algorithms[] = {
	"cbc(aes)"
};

int cipherflt_cipher_init_master(struct blkcipher_desc *desc)
{
	struct crypto_blkcipher *tfm;
	int rv;

	printk(INFO "cipherflt_cipher_init_master\n");

	tfm = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	printk(INFO "kok!\n");

	rv = crypto_blkcipher_setkey(tfm, AES_KEY, 16);
	if (rv) {
		crypto_free_blkcipher(tfm);
		return rv;
	}

	printk(INFO "still kok!\n");

	crypto_blkcipher_set_iv(tfm, AES_IV, 16);

	printk(INFO "well duh kok!\n");

	memset(desc, 0, sizeof (struct blkcipher_desc));
	desc->tfm = tfm;
	desc->flags = 0;
	return 0;
}

int cipherflt_cipher_encrypt_master(void *buffer, unsigned int len)
{
	struct blkcipher_desc desc;
	struct scatterlist sg;
	int rv;

	printk(INFO "cipherflt_cipher_encrypt_master\n");

	rv = cipherflt_cipher_init_master(&desc);
	if (rv)
		return rv;

	sg_set_buf(&sg, buffer, len);

	rv = crypto_blkcipher_encrypt(&desc, &sg, &sg, len);

	cipherflt_cipher_free(&desc);
	return rv;
}

int cipherflt_cipher_decrypt_master(void *buffer, unsigned int len)
{
	struct blkcipher_desc desc;
	struct scatterlist sg;
	int rv;

	printk(INFO "cipherflt_cipher_decrypt_master\n");

	rv = cipherflt_cipher_init_master(&desc);
	if (rv)
		return rv;

	printk(INFO "ok!\n");

	sg_set_buf(&sg, buffer, len);

	printk(INFO "still ok!\n");

	rv = crypto_blkcipher_decrypt(&desc, &sg, &sg, len);

	printk(INFO "pivocina!\n");

	cipherflt_cipher_free(&desc);
	printk(INFO "mega picovina!\n");
	return rv;
}

int cipherflt_cipher_init(struct cipherflt_trailer *trailer,
		struct blkcipher_desc *desc)
{
	const char *algorithm = cipherflt_algorithms[trailer->algorithm];
	struct crypto_blkcipher *tfm;
	int rv;

	printk(INFO "cipherflt_cipher_init\n");

	tfm = crypto_alloc_blkcipher(algorithm, 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	rv = crypto_blkcipher_setkey(tfm, trailer->key, trailer->key_size);
	if (rv) {
		crypto_free_blkcipher(tfm);
		return rv;
	}

	memset(desc, 0, sizeof (struct blkcipher_desc));
	desc->tfm = tfm;
	desc->flags = 0;
	return 0;
}

char* cipherflt_cipher_generate_iv(struct page *page,
		u8 iv_size, struct blkcipher_desc *desc)
{
	char *iv;

	printk(INFO "cipherflt_cipher_generate_iv\n");

	iv = kzalloc(iv_size, GFP_KERNEL);
	if (iv == NULL)
		return ERR_PTR(-ENOMEM);

	/* TODO: generate ESSIV */
	memcpy(iv, AES_IV, iv_size);

	return iv;
}

int cipherflt_cipher_encrypt(struct page *page, const char *iv,
		u8 iv_size, unsigned int len, unsigned int offset,
		struct blkcipher_desc *desc)
{
	struct scatterlist sg;
	int rv;

	printk(INFO "cipherflt_cipher_encrypt\n");

	crypto_blkcipher_set_iv(desc->tfm, iv, iv_size);

	sg_set_page(&sg, page, len, offset);

	rv = crypto_blkcipher_encrypt(desc, &sg, &sg, len);
	if ((rv) && (desc->flags != CRYPTO_TFM_RES_BAD_BLOCK_LEN))
		return rv;

	return 0;
}

int cipherflt_cipher_decrypt(struct page *page, const char *iv,
		u8 iv_size, unsigned int len, unsigned int offset,
		struct blkcipher_desc *desc)
{
	struct scatterlist sg;
	int rv;

	printk(INFO "cipherflt_cipher_decrypt\n");

	crypto_blkcipher_set_iv(desc->tfm, iv, iv_size);

	sg_set_page(&sg, page, len, offset);

	rv = crypto_blkcipher_decrypt(desc, &sg, &sg, len);
	if ((rv) && (desc->flags != CRYPTO_TFM_RES_BAD_BLOCK_LEN))
		return rv;

	return 0;
}

void cipherflt_cipher_free(struct blkcipher_desc *desc)
{
	printk(INFO "cipherflt_cipher_free\n");

	crypto_free_blkcipher(desc->tfm);
	desc->tfm = NULL;
}

/* end of file */

