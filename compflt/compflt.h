#include <linux/crypto.h>
#include <linux/list.h>
#include <linux/fs.h>

#define COMPFLT_MAGIC "\x06\x10\x19\x82"
#define COMPFLT_FH_SIZE 5
#define COMPFLT_BH_SIZE 17
#define COMPFLT_BLOCK_SIZE_U 4096
#define COMPFLT_BLOCK_SIZE_C 512

struct block {
        struct list_head all;
	struct list_head file;
        int dirty;
        unsigned int type; // u8 (0 == free , 1 == normal)
	unsigned int off_u; // u32
	unsigned int off_c; // not written to file
	unsigned int off_next; // u32
	unsigned int size_u; // u32
	unsigned int size_c; // u32
        char *data_u;
};

struct fheader {
	struct list_head all;
	unsigned long ino;
	int compressed;
	int dirty;
	unsigned int method; // u8
	struct block map;
        size_t size; // whole uncompressed size
};

// fheader.c
extern struct list_head fheader_list;
void fheader_deinit(struct fheader*);
void fheader_clear_blks(struct fheader*);
int fheader_cache_init(void);
void fheader_cache_deinit(void);
void fheader_del(unsigned long);
struct fheader *fheader_find(unsigned long);
struct fheader *fheader_get(struct file*);
int fheader_read(struct file*, struct fheader*);
void fheader_write(struct file*, struct fheader*);
void fheader_add_blk(struct fheader*, struct block*);
void fheader_del_blk(struct fheader*, struct block*);

// block.c
int block_cache_init(void);
void block_cache_deinit(void);
struct block* block_init(void);
void block_deinit(struct block*);
int block_read_header(struct file*, struct block*, loff_t*);
int block_write_header(struct file*, struct block*);
int block_read(struct file*, struct block*, struct crypto_tfm*);
int block_write(struct file*, struct block*, struct crypto_tfm*);

// cblock.c
// TODO

// read_write.c
ssize_t orig_read(struct file*, char __user*, size_t, loff_t*);
ssize_t orig_write(struct file*, const char __user*, size_t, loff_t*);
int read_u(struct file*, struct fheader*, loff_t, size_t*, char*);
int write_u(struct file*, struct fheader*, loff_t, size_t*, char*);

// compress.c
struct crypto_tfm *comp_init(unsigned int);
void comp_deinit(struct crypto_tfm*);
char* decomp_block(struct crypto_tfm*, struct block*, char*);
char* comp_block(struct crypto_tfm*, struct block*, char*);
int comp_method(void);
int comp_proc_get(char*, int);
void comp_proc_set(char*);
int comp_stat(char*, int);

// proc.c
int proc_init(void);
void proc_deinit(void);

// debug.c
#ifdef COMPFLT_DEBUG
        #define debug_printk printk
        void debug_block(char*, struct block*);
        void hexdump(void*, unsigned int);
#else
        #define debug_printk(format, args...) ;
        #define debug_block(pre, blk) ;
        #define hexdump(buf, len) ;
#endif
