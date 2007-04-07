#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/fs.h>

#define COMPFLT_MAGIC "\x06\x10\x19\x82"
//#define COMPFLT_BLOCK_SIZE 4096
#define COMPFLT_BLOCK_SIZE 2048
#define COMPFLT_FH_RESERVED COMPFLT_BLOCK_SIZE
#define COMPFLT_DEFAULT_CMETHOD 1 // deflate as default

struct dmap {
        struct list_head all;
	struct list_head list; // main sequential list (header->map)
	loff_t off_u;
	loff_t off_c;
	size_t size_u;
	size_t size_c;
	//spinlock_t lock;
};

struct header {
        // TODO: might rename to 'all' for consistency sake
	struct list_head list;
	unsigned long ino;
	unsigned int compressed;
	u8 method;
	u8 dirty;
	u32 blocks;
	struct dmap map; // list of data mappings
	//spinlock_t lock;
};

// header.c
int header_cache_init(void);
void header_cache_deinit(void);
void header_del(unsigned long);
struct header *header_find(unsigned long);
struct header *header_get(struct file*);
int header_read(struct file*, struct header*);
void header_write(struct file*, struct header*);
void header_add_dm(struct header*, struct dmap*);
void header_del_dm(struct header*, struct dmap*);

// dmap.c
int dmap_cache_init(void);
void dmap_cache_deinit(void);
struct dmap* dmap_init(void);
void dmap_deinit(struct dmap*);

// read_write.c
ssize_t orig_read(struct file*, char __user*, size_t, loff_t*);
ssize_t orig_write(struct file*, const char __user*, size_t, loff_t*);
int read_u(struct file*, struct header*, loff_t, size_t*, char*);
int write_u(struct file*, struct header*, loff_t, size_t, char*);

// compress.c
struct crypto_tfm *comp_init(unsigned int);

// util.c
void hexdump(void*, unsigned int);
