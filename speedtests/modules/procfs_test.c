#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <asm/uaccess.h>
#include "buffer.h"

#define PRINTPREFIX "procfs_test: "

static struct proc_dir_entry *entry;

static int test_read(char *page, char **start, off_t offset, int count, int *eof, void *data){
  int len;

  if (offset > locbuf_currlen){
    printk(PRINTPREFIX "tried to read beyond the end of buffer\n");
    return(0);
  }
  
  if (offset + count >= locbuf_currlen){
    len = locbuf_currlen - offset;
    *eof = 1;
  }
  else{
    len = count;
    *eof = 0;
  }
  *start = page;
  
  // printk(PRINTPREFIX "copying %d bytes from offset %ld\n", len, offset);
  memcpy(page, locbuf + offset, len);
  
  return(len);
}

static int test_write(struct file *filp, const char __user *buff, unsigned long len, void *data){
  if (len > LOCBUFLEN){
    printk(PRINTPREFIX "too long input\n");
    len = LOCBUFLEN;
  }
  // printk("write %ld\n", len);
  memcpy(locbuf, buff, len);
  locbuf_currlen = len;
  return(len);
}

static int __init _init_module(void){
  if (!alloc_locbuf()){
    printk(PRINTPREFIX "cannot allocate local buffer\n");
    return(-1);
  }	    
  entry = create_proc_entry("test", 0644, &proc_root);
  if (entry == NULL){
    free_locbuf();
    printk(PRINTPREFIX "Creating proc entry failed\n");
  }
  // bind a handling read function
  entry->read_proc = test_read;
  // bind write funtion
  entry->write_proc = test_write;
  // set lenght of used data in local buffer
  locbuf_currlen = 0;
  return(0);
}

static void __exit _cleanup_module(void){
  free_locbuf();
  // at last remove entry
  remove_proc_entry("test", &proc_root);
}

module_init(_init_module);
module_exit(_cleanup_module);

MODULE_LICENSE("GPL");
