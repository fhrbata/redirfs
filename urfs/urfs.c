#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include "urfs_kernel.h"
#include "../../../trunk/src/redirfs/redirfs.h"

#define URFS_MAJOR 60
#define URFS_NAME "urfs"
#define PRINTPREFIX URFS_NAME ": "

static struct rfs_filter_info *filters_info = NULL;
static int filters_info_count = 0;

static struct rfs_path_info *paths_info = NULL;
static int paths_info_count = 0;

static void free_filters_info(void){
  int i;

  if (filters_info != NULL && filters_info_count != 0){
    for(i = 0; i < filters_info_count; i++){
      if (filters_info[i].name != NULL){
        kfree(filters_info[i].name);
      }
    }
    kfree(filters_info);
  }
  filters_info = NULL;
  filters_info_count = 0;
}

static void free_paths_info(void){
  int i;

  if (paths_info != NULL && paths_info_count != 0){
    for(i = 0; i < paths_info_count; i++){
      if (paths_info[i].path != NULL){
        kfree(paths_info[i].path);
      }
    }
    kfree(paths_info);
  }
  paths_info = NULL;
  paths_info_count = 0;
}

static int copy_chararr_from_user(char **chararr, void __user *ptr){
  int len;
  int retval;

  retval = copy_from_user(&len, ptr, sizeof(int));
  printk("retval: %d, len: %d\n", retval, len);
  if (len > 0){
    *chararr = (char *) kmalloc(len, GFP_KERNEL);
    if (!(*chararr)){
      return(-2);
    }
    retval = copy_from_user(*chararr, ptr + sizeof(int), len);
  }
  return(len + sizeof(int));
}

static int copy_chararr_to_user(void __user *ptr, char *chararr, int len){
  int retval;
  
  retval = copy_to_user(ptr, &len, sizeof(int));
  retval = copy_to_user(ptr + sizeof(int), chararr, len);
  return(sizeof(int) + len);
}

#define copy_str_to_user(ptr, str) copy_chararr_to_user(ptr, str, strlen(str) + 1)

static int urfs_ioctl(struct inode *ino, struct file *filp, unsigned int command, unsigned long arg){
  void *ptr = (void *) arg;
  int retval;

  switch(command){
    case URFS_CMD_GET_FILTERS_INFO_PREPARE:
      {
	int i;
	int len = 0;

        if (rfs_get_filters_info(&filters_info, &filters_info_count) != RFS_ERR_OK){
	  printk(PRINTPREFIX "rfs_get_filters_info failed\n");
	  return(-EIO);
	}
	else{
          for(i = 0; i < filters_info_count; i++){
	    len += strlen(filters_info[i].name) + 1;
	    len += sizeof(int) * 3;
	  }
	  return(len);
	}
      }
      break;
    case URFS_CMD_GET_FILTERS_INFO_DATA:
      {
        int i;
	int offset = 0;
        struct rfs_filter_info *filter_info;

	for(i = 0; i < filters_info_count; i++){
	  filter_info = &filters_info[i];
	  offset += copy_str_to_user(ptr + offset, filter_info->name);
	  retval = copy_to_user(ptr + offset, &filter_info->priority, sizeof(int));
	  offset += sizeof(int);
	  retval = copy_to_user(ptr + offset, &filter_info->active, sizeof(int));
	  offset += sizeof(int);
	}
	free_filters_info();
      }
      break;
    case URFS_CMD_GET_FILTER_PATHS_INFO_PREPARE:
      {
	int i;
	int len = 0;
	char *filter_name = NULL;
	rfs_filter filter;
	enum rfs_err err;

	if (copy_chararr_from_user(&filter_name, ptr) < 0){
	  printk(PRINTPREFIX "cannot allocate memory for filter name\n");
	  return(-ENOMEM);
	}

	err = rfs_get_filter_by_name(&filter, filter_name);
	kfree(filter_name);
	if (err != RFS_ERR_OK){
	  return(-ENODEV);
	}

        if (rfs_get_paths_info(filter, &paths_info, &paths_info_count) != RFS_ERR_OK){
	  printk(PRINTPREFIX "rfs_get_paths_info failed\n");
	  return(-EIO);
	}
	else{
          for(i = 0; i < paths_info_count; i++){
	    len += strlen(paths_info[i].path) + 1;
	    len += sizeof(int) * 2;
	  }
	  return(len);
	}
      }
      break;
    case URFS_CMD_GET_FILTER_PATHS_INFO_DATA:
      {
        int i;
	int offset = 0;
	struct rfs_path_info *path_info;

	for(i = 0; i < paths_info_count; i++){
	  path_info = &paths_info[i];
	  offset += copy_str_to_user(ptr + offset, path_info->path);
	  retval = copy_to_user(ptr + offset, &path_info->flags, sizeof(int));
	  offset += sizeof(int);
	}
	free_paths_info();
      }
      break;
    case URFS_CMD_SET_FILTER_PATH:
      {
        char *filter_name = NULL;
	char *path = NULL;
	int flags;
	rfs_filter filter;
	enum rfs_err err;
	struct rfs_path_info path_info;
	int offset = 0;

	retval = copy_chararr_from_user(&filter_name, ptr + offset);
	if (retval < 0){
	  printk(PRINTPREFIX "cannot allocate memory for filter name\n");
	  return(-ENOMEM);
	}
	offset += retval;
        
        err = rfs_get_filter_by_name(&filter, filter_name);
	kfree(filter_name);
	if (err != RFS_ERR_OK){
	  return(-ENODEV);
	}

	retval = copy_chararr_from_user(&path, ptr + offset);
	if (retval < 0){
	  printk(PRINTPREFIX "cannot allocate memory for path\n");
	  return(-ENOMEM);
	}
	offset += retval;
	retval = copy_from_user(&flags, ptr + offset, sizeof(int));

        path_info.path = path;
	path_info.flags = flags;
	err = rfs_set_path(filter, &path_info);
	kfree(path);
	printk("set!\n");
	if (err != RFS_ERR_OK){
	  return(-EINVAL);
	}
      }
      break;
    case URFS_CMD_ACTIVATE_FILTER:
      {
        char *filter_name = NULL;
	rfs_filter filter;
	enum rfs_err err;

	if (copy_chararr_from_user(&filter_name, ptr) < 0){
	  printk(PRINTPREFIX "cannot allocate memory for filter name\n");
	  return(-ENOMEM);
	}

	err = rfs_get_filter_by_name(&filter, filter_name);
	kfree(filter_name);
	if (err != RFS_ERR_OK){
	  return(-ENODEV);
	}

	err = rfs_activate_filter(filter);
	if (err != RFS_ERR_OK){
	  return(-ENODEV);
	}
      }
      break;
    case URFS_CMD_DEACTIVATE_FILTER:
      {
        char *filter_name = NULL;
	rfs_filter filter;
	enum rfs_err err;

	if (copy_chararr_from_user(&filter_name, ptr) < 0){
	  printk(PRINTPREFIX "cannot allocate memory for filter name\n");
	  return(-ENOMEM);
	}

	err = rfs_get_filter_by_name(&filter, filter_name);
	kfree(filter_name);
	if (err != RFS_ERR_OK){
	  return(-ENODEV);
	}

	err = rfs_deactivate_filter(filter);
	if (err != RFS_ERR_OK){
	  return(-ENODEV);
	}
      }
      break;
    default:
      return(-ENOIOCTLCMD);
  }
  return(0);
}

static struct file_operations urfs_ops = {
  .owner = THIS_MODULE,
  .ioctl = urfs_ioctl,
};

static int __init _init_module(void){
  if (register_chrdev(URFS_MAJOR, URFS_NAME, &urfs_ops)){
    printk(PRINTPREFIX "unable to initialize char device\n");
    return(-1);
  }
  printk(PRINTPREFIX "loaded\n");
  return(0);
}

static void __exit _cleanup_module(void){
  unregister_chrdev(URFS_MAJOR, URFS_NAME);
  printk(PRINTPREFIX "unloaded\n");
}

module_init(_init_module);
module_exit(_cleanup_module);

MODULE_LICENSE("GPL");

