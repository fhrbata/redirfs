#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/relay.h>
#define __NOCURRLEN
#include "buffer.h"
#undef __NOCURRLEN
#include "../headers/relay_test.h"

#define PRINTPREFIX "relay_test: "

#define BUFNR 1
#define BUFSIZE LOCBUFLEN / BUFNR

struct rchan *rchan;

static int test_subbuf_start_callback(struct rchan_buf *buf, void *subbuf, void *prev_subbuf, size_t prev_padding){
  if (relay_buf_full(buf)) {
    //printk(PRINTPREFIX "buffer full\n");
    return(0);
  }					    
  return(1);
}

static int test_remove_buf_file_callback(struct dentry *dentry){
  debugfs_remove(dentry);
  return(0);
}

static struct dentry *test_create_buf_file_callback(const char *filename, struct dentry *parent, int mode, struct rchan_buf *buf, int *is_global){
  return debugfs_create_file(filename, mode, parent, buf, &relay_file_operations);
}

static struct rchan_callbacks test_relay_callbacks = {
  .subbuf_start = test_subbuf_start_callback,
  .create_buf_file = test_create_buf_file_callback,
  .remove_buf_file = test_remove_buf_file_callback,
};

static int test_ioctl(struct inode *ino, struct file *filp, unsigned int command, unsigned long arg){
  // using ioclt to fill relay buffer
  if (arg > LOCBUFLEN){
    return(-EINVAL);
  }
  
//  printk(PRINTPREFIX "writing %ld bytes to relay buffer\n", arg);
  relay_write(rchan, locbuf, arg);
  relay_flush(rchan);
  
  return(0);
}

static struct file_operations chardev_test_ops = {
  .owner = THIS_MODULE,
  .ioctl = test_ioctl,
};

static int __init _init_module(void){
  if (!alloc_locbuf()){
    printk(PRINTPREFIX "cannot allocate local buffer\n");
    return(-1);
  }
	  
  rchan = relay_open("relay_test", NULL, BUFSIZE, BUFNR, &test_relay_callbacks);
  if (!rchan){
    printk(PRINTPREFIX "unable to open relay\n");
    free_locbuf();
    return(-1);
  }
  if (register_chrdev(RELAY_CHRDEV_TEST_MAJOR_N, RELAY_CHRDEV_TEST_NAME, &chardev_test_ops)){
    printk(PRINTPREFIX "unable to initialize char device\n");
    free_locbuf();
    relay_close(rchan);
    return(-1);
  }
  printk(PRINTPREFIX "relay test initialized\n");
  return(0);
}

static void __exit _cleanup_module(void){
  free_locbuf();
  unregister_chrdev(RELAY_CHRDEV_TEST_MAJOR_N, RELAY_CHRDEV_TEST_NAME);
  relay_close(rchan);
}

module_init(_init_module);
module_exit(_cleanup_module);

MODULE_LICENSE("GPL");
