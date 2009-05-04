/*
 * cipherflt - RedirFS cryptographic filter
 *
 * Written by Pavel Zuna <xzunap00@stud.fit.vutbr.cz>
 *
 */

#include "cipherflt.h"

void cipherflt_trailer_init(struct cipherflt_trailer *trailer)
{
	printk(KERN_INFO FILTER_NAME
		": cipherflt_trailer_init\n");

	BUG_ON(trailer == NULL);

	trailer->version = FILTER_VERSION_INT;
	trailer->algorithm = 0;
	trailer->key_size = 16;
	trailer->iv_size = 16;
	trailer->block_size = 4096;
	trailer->key = NULL;
}

int cipherflt_trailer_read(struct file *file,
		struct cipherflt_trailer *trailer)
{
	mm_segment_t old_fs;
	loff_t offset;
	int buffer_offset;
	int rv;

	char buffer[TRAILER_SIZE];

	printk(KERN_INFO FILTER_NAME
		": cipherflt_trailer_read\n");

	BUG_ON(file == NULL);
	BUG_ON(trailer == NULL);

	offset = file->f_dentry->d_inode->i_size;
	if (offset < TRAILER_SIZE)
		return 0;
	offset -= TRAILER_SIZE;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	rv = file->f_op->read(file, buffer, TRAILER_SIZE, &offset);
	set_fs(old_fs);

	if ((rv < TRAILER_SIZE) ||
		(memcmp(buffer, TRAILER_MAGIC, sizeof (TRAILER_MAGIC) - 1)))
		return 0;

	buffer_offset = sizeof (TRAILER_MAGIC) - 1;
	memcpy(&trailer->version, buffer + buffer_offset, sizeof (u8));
	buffer_offset += sizeof (u8);
	memcpy(&trailer->algorithm, buffer + buffer_offset, sizeof (u8));
	buffer_offset += sizeof (u8);
	memcpy(&trailer->key_size, buffer + buffer_offset, sizeof (u8));
	buffer_offset += sizeof (u8);
	memcpy(&trailer->iv_size, buffer + buffer_offset, sizeof (u8));
	buffer_offset += sizeof (u8);
	memcpy(&trailer->block_size, buffer + buffer_offset, sizeof (u16));

	trailer->key = kzalloc(trailer->key_size, GFP_KERNEL);
	if (trailer->key == NULL)
		return -ENOMEM;

	buffer_offset += sizeof (u16);
	memcpy(trailer->key, buffer + buffer_offset, trailer->key_size);

	rv = cipherflt_cipher_decrypt_master(trailer->key,
			trailer->key_size);
	if (rv) {
		kfree(trailer->key);
		trailer->key = NULL;
		return rv;
	}

	return 0;
}

int cipherflt_trailer_write(struct file *file,
		struct cipherflt_trailer *trailer)
{
	mm_segment_t old_fs;
	loff_t offset;
	int buffer_offset;
	int rv;

	char buffer[TRAILER_SIZE];

	printk(KERN_INFO FILTER_NAME
		": cipherflt_trailer_write\n");

	BUG_ON(file == NULL);
	BUG_ON(trailer == NULL);

	memcpy(buffer, TRAILER_MAGIC, sizeof (TRAILER_MAGIC) - 1);

	buffer_offset = sizeof (TRAILER_MAGIC) - 1;
	memcpy(buffer + buffer_offset, &trailer->version, sizeof (u8));
	buffer_offset += sizeof (u8);
	memcpy(buffer + buffer_offset, &trailer->algorithm, sizeof (u8));
	buffer_offset += sizeof (u8);
	memcpy(buffer + buffer_offset, &trailer->key_size, sizeof (u8));
	buffer_offset += sizeof (u8);
	memcpy(buffer + buffer_offset, &trailer->iv_size, sizeof (u8));
	buffer_offset += sizeof (u8);
	memcpy(buffer + buffer_offset, &trailer->block_size, sizeof (u8));
	buffer_offset += sizeof (u16);
	memcpy(buffer + buffer_offset, trailer->key, trailer->key_size);

	rv = cipherflt_cipher_encrypt_master(buffer + buffer_offset,
			trailer->key_size);
	if (rv)
		return rv;

	offset = i_size_read(file->f_dentry->d_inode);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	rv = file->f_op->write(file, buffer, TRAILER_SIZE, &offset);
	set_fs(old_fs);

	if (rv != TRAILER_SIZE)
		rv = -1;

	return 0;
}

int cipherflt_trailer_generate_key(struct cipherflt_trailer *trailer)
{
	printk(KERN_INFO FILTER_NAME
		": cipherflt_trailer_generate_key\n");

	BUG_ON(trailer == NULL);

/*
	trailer->key = kzalloc(trailer->key_size, GFP_KERNEL);
	if (trailer->key == NULL)
		return -ENOMEM;
*/
	/* TODO: generate key */
	trailer->key = (char *) AES_KEY;

	return 0;
}

void cipherflt_trailer_free(struct cipherflt_trailer *trailer)
{
	printk(KERN_INFO FILTER_NAME
		": cipherflt_trailer_free\n");

	BUG_ON(trailer == NULL);

	/* FIXME: remove AES_KEY condition */
	if ((trailer->key != NULL) && (trailer->key != (char *) AES_KEY))
		kfree(trailer->key);
	trailer->key = NULL;
}

/* end of file */

