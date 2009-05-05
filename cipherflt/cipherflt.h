/*
 * cipherflt - RedirFS cryptographic filter
 *
 * Written by Pavel Zuna <xzunap00@stud.fit.vutbr.cz>
 *
 */

#include <linux/completion.h>
#include <linux/crypto.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/scatterlist.h>
#include <linux/writeback.h>

#include <redirfs.h>

/* begin temporary ! */
#define AES_KEY "\x06\xa9\x21\x40\x36\xb8\xa1\x5b" \
                "\x51\x2e\x03\xd5\x34\x12\x00\x06"
#define AES_IV  "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30" \
                "\xb4\x22\xda\x80\x2c\x9f\xac\x41"
/* end temporary ! */

#define FILTER_VERSION "0.1"
#define FILTER_VERSION_INT 1

#define FILTER_NAME "cipherflt"
#define FILTER_PRIORITY 500000000

#define INFO KERN_INFO FILTER_NAME ": "
#define FAIL KERN_ERR FILTER_NAME ": failed to "

extern redirfs_filter cipherflt;


struct cipherflt_trailer {
	u8 version;
	u8 algorithm;
	u8 key_size;
	u8 iv_size;
	u16 block_size;
	char *key;
};

#define TRAILER_MAGIC "cipherflt!"
#define TRAILER_KEY_SIZE_MAX 64
#define TRAILER_SIZE ( \
	sizeof(TRAILER_MAGIC) - 1 + \
	sizeof(u8) + sizeof(u8) + sizeof(u16) + sizeof(u16) + \
	TRAILER_KEY_SIZE_MAX \
	)

void cipherflt_trailer_init(struct cipherflt_trailer *trailer);
int cipherflt_trailer_read(struct file *file,
		struct cipherflt_trailer *trailer);
int cipherflt_trailer_write(struct file *file,
		struct cipherflt_trailer *trailer);
int cipherflt_trailer_generate_key(struct cipherflt_trailer *trailer);
void cipherflt_trailer_free(struct cipherflt_trailer *trailer);


struct cipherflt_inode_data {
	struct redirfs_data rfs_data;
	struct inode *host;
	struct list_head inodes;
	struct completion ciphering;
	atomic_t trailer_written;
	struct cipherflt_trailer trailer;
};

#define rfs_to_inode_data(ptr) \
	container_of(ptr, struct cipherflt_inode_data, rfs_data)

#define inode_data_is_encrypted(ptr) \
	(ptr->trailer.key != NULL)

int cipherflt_inode_data_cache_init(void);
struct cipherflt_inode_data *cipherflt_inode_data_alloc(void);
void cipherflt_inode_data_attach(struct inode *inode,
		struct cipherflt_inode_data *data);
struct cipherflt_inode_data *cipherflt_inode_data_get(struct inode *inode);
void cipherflt_inode_data_detach(struct inode *inode);
void cipherflt_inode_data_free(struct redirfs_data *data);
void cipherflt_inode_data_cache_free(void);


struct cipherflt_block {
	struct list_head blocks;
	struct page *page;
	char *iv;
	unsigned int len;
	unsigned int offset;
};

int cipherflt_block_cache_init(void);
struct cipherflt_block *cipherflt_block_alloc(void);
int cipherflt_block_add_blocks(struct page *page, struct inode *inode,
		u16 block_size, u8 iv_size, struct blkcipher_desc *desc,
		struct list_head *blocks);
void cipherflt_block_free(struct cipherflt_block *block);
void cipherflt_block_cache_free(void);


struct cipherflt_context_data {
	struct redirfs_data rfs_data;
	struct list_head blocks;
	struct blkcipher_desc desc;
	u16 block_size;
	u8 iv_size;
};

#define rfs_to_context_data(ptr) \
	container_of(ptr, struct cipherflt_context_data, rfs_data)

struct cipherflt_context_data *cipherflt_context_data_alloc(
		struct cipherflt_trailer *trailer);
int cipherflt_context_data_add_blocks(struct page *page, struct inode *inode,
		struct cipherflt_context_data *data);
void cipherflt_context_data_attach(redirfs_context context,
		struct cipherflt_context_data *data);
struct cipherflt_context_data *cipherflt_context_data_get(
		redirfs_context context);
void cipherflt_context_data_detach(redirfs_context context);
void cipherflt_context_data_free(struct redirfs_data *data);


int cipherflt_cipher_encrypt_master(void *buffer, unsigned int len);
int cipherflt_cipher_decrypt_master(void *buffer, unsigned int len);

int cipherflt_cipher_init(struct cipherflt_trailer *trailer,
		struct blkcipher_desc *desc);
char* cipherflt_cipher_generate_iv(struct page *page,
		u8 iv_size, struct blkcipher_desc *desc);
int cipherflt_cipher_encrypt(struct page *page, const char *iv,
		u8 iv_size, unsigned int start, unsigned int end,
		struct blkcipher_desc *desc);
int cipherflt_cipher_decrypt(struct page *page, const char *iv,
		u8 iv_size, unsigned int start, unsigned int end,
		struct blkcipher_desc *desc);
void cipherflt_cipher_free(struct blkcipher_desc *desc);

/* end of file */

