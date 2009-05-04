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
	int rv;

	desc->tfm = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	desc->flags = 0;

	rv = crypto_blkcipher_setkey(desc->tfm, AES_KEY, 16);
	if (rv)
		goto error;

	rv = crypto_blkcipher_set_iv(desc->tfm, AES_IV, 16);
	if (rv)
		goto error;

	return 0;
error:
	crypto_free_blkcipher(desc->tfm);
	return rv;
}

int cipherflt_cipher_encrypt_master(void *buffer, unsigned int len)
{
	struct blkcipher_desc desc;
	struct scatterlist sg;
	int rv;

	rv = cipherflt_cipher_init_master(&desc);
	if (rv)
		return rv;

	sg_set_buf(&sg, buffer, len);

	rv = crypto_blkcipher_encrypt(&desc, &sg, &sg, len);

	crypto_free_blkcipher(desc.tfm);
	return rv;
}

int cipherflt_cipher_decrypt_master(void *buffer, unsigned int len)
{
	struct blkcipher_desc desc;
	struct scatterlist sg;
	int rv;

	rv = cipherflt_cipher_init_master(&desc);
	if (rv)
		return rv;

	sg_set_buf(&sg, buffer, len);

	rv = crypto_blkcipher_decrypt(&desc, &sg, &sg, len);

	crypto_free_blkcipher(desc.tfm);
	return rv;
}

int cipherflt_cipher_init(struct cipherflt_trailer *trailer,
		struct blkcipher_desc *desc)
{
	const char *algorithm = cipherflt_algorithms[data->trailer.algorithm];
	struct crypto_blkcipher *tfm;

	tfm = crypto_alloc_blkcipher(algorithm, 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	rv = crypto_blkcipher_setkey(tfm, trailer->key, trailer->key_size);
	if (rv) {
		crypto_free_blkcipher(tfm);
		return rv;
	}

	desc.tfm = tfm;
	desc.flags = 0;
	return 0;
}

char* cipherflt_cipher_generate_iv(struct page *page,
		struct cipherflt_trailer *trailer, struct blkcipher_desc *desc)
{
	char *iv;

	iv = kzalloc(trailer->iv_size, GFP_KERNEL);
	if (iv == NULL)
		return ERR_PTR(-ENOMEM);

	/* TODO: generate ESSIV */
	memset(iv, AES_IV, trailer->iv_size);

	return iv;
}

int cipherflt_cipher_encrypt(struct page *page,
		const char *iv, unsigned int len, unsigned int offset,
		struct cipherflt_trailer *trailer, struct blkcipher_desc *desc)
{
	struct scatterlist sg;
	int rv;

	rv = crypto_blkcipher_set_iv(desc->tfm, iv, trailer->iv_size);
	if (rv)
		return rv;

	sg_set_page(&sg, page, len, offset);

	rv = crypto_blkcipher_encrypt(desc, &sg, &sg, len);
	if (rv)
		return rv;

	return 0;
}

int cipherflt_cipher_decrypt(struct page *page,
		const char *iv, unsigned int len, unsigned int offset,
		struct cipherflt_trailer *trailer, struct blkcipher_desc *desc)
{
	struct scatterlist sg;
	int rv;

	rv = crypto_blkcipher_set_iv(desc->tfm, iv, trailer->iv_size);
	if (rv)
		return rv;

	sg_set_page(&sg, page, len, offset);

	rv = crypto_blkcipher_decrypt(desc, &sg, &sg, len);
	if (rv)
		return rv;

	return 0;
}

void cipherflt_cipher_free(struct blkcipher_desc *desc)
{
	crypto_free_blkcipher(desc.tfm);
	data->desc.tfm = NULL;
}

/* end of file */

