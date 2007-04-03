#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include "buffer.h"
#include "../headers/chardev_test.h"

#define PRINTPREFIX "chardev_test: "

static int test_ioctl(struct inode *ino, struct file *filp, unsigned int command, unsigned long arg){
  return(0);
}

static ssize_t test_read(struct file *filp, char __user *buff, size_t count, loff_t *offp){
  if (count > LOCBUFLEN){
    return(-EINVAL);
  }
  copy_to_user(buff, locbuf, count);
  return(count);
}

static ssize_t test_write(struct file *filp, const char __user *buff, size_t count, loff_t *offp){
  if (count > LOCBUFLEN){
    return(-EINVAL);
  }
  copy_from_user(locbuf, buff, count);
  return(count);
}

static struct file_operations chardev_test_ops = {
  .owner = THIS_MODULE,
  .write = test_write,
  .read = test_read,
  .ioctl = test_ioctl,
};

static int __init _init_module(void){
  if (!alloc_locbuf()){
    printk(PRINTPREFIX "cannot allocate local buffer\n");
    return(-1);
  }
  if (register_chrdev(CHARDEV_TEST_MAJOR_N, CHARDEV_TEST_NAME, &chardev_test_ops)){
    printk(PRINTPREFIX "unable to initialize char device\n");
    free_locbuf();
    return(-1);
  }
  locbuf_currlen = 0;
  return(0);
}

static void __exit _cleanup_module(void){
  free_locbuf();
  unregister_chrdev(CHARDEV_TEST_MAJOR_N, CHARDEV_TEST_NAME);
}

module_init(_init_module);
module_exit(_cleanup_module);

MODULE_LICENSE("GPL");
