#include "redir.h"

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

static int redirctl_ioctl(struct inode *ino, struct file *filp, unsigned int command, unsigned long arg){
  void *ptr = (void *) arg;
  int retval;

  switch(command){
    case REDIRCTL_CMD_GET_FILTERS_INFO_PREPARE:
      {
	int i;
	int len = 0;

        if (flt_get_all_infos(&filters_info, &filters_info_count) != 0){
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
    case REDIRCTL_CMD_GET_FILTERS_INFO_DATA:
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
    case REDIRCTL_CMD_GET_FILTER_PATHS_INFO_PREPARE:
      {
	int i;
	int len = 0;
	char *filter_name = NULL;
	rfs_filter filter;
	int err;

	if (copy_chararr_from_user(&filter_name, ptr) < 0){
	  return(-ENOMEM);
	}

	err = flt_get_by_name(&filter, filter_name);
	kfree(filter_name);
	if (err != 0){
	  return(-ENODEV);
	}

        if (path_get_infos(filter, &paths_info, &paths_info_count) != 0){
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
    case REDIRCTL_CMD_GET_FILTER_PATHS_INFO_DATA:
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
    case REDIRCTL_CMD_SET_FILTER_PATH:
      {
        char *filter_name = NULL;
	char *path = NULL;
	int flags;
	rfs_filter filter;
	int err;
	int offset = 0;
	union rfs_mod mod;

	retval = copy_chararr_from_user(&filter_name, ptr + offset);
	if (retval < 0){
	  return(-ENOMEM);
	}
	offset += retval;
        
        err = flt_get_by_name(&filter, filter_name);
	kfree(filter_name);
	if (err != 0){
	  return(-ENODEV);
	}

	retval = copy_chararr_from_user(&path, ptr + offset);
	if (retval < 0){
	  return(-ENOMEM);
	}
	offset += retval;
	retval = copy_from_user(&flags, ptr + offset, sizeof(int));

        mod.id = RFS_SET_PATH;
	mod.set_path.path_info.path = path;
	mod.set_path.path_info.flags = flags;
	err = flt_execute_mod_cb((struct filter *) filter, &mod);
	kfree(path);
	if (err != 0){
	  return(err);
	}
      }
      break;
    case REDIRCTL_CMD_ACTIVATE_FILTER:
      {
        char *filter_name = NULL;
	rfs_filter filter;
	int err;
	union rfs_mod mod;

	if (copy_chararr_from_user(&filter_name, ptr) < 0){
	  return(-ENOMEM);
	}

	err = flt_get_by_name(&filter, filter_name);
	kfree(filter_name);
	if (err != 0){
	  return(-ENODEV);
	}

	mod.id = RFS_ACTIVATE;
	err = flt_execute_mod_cb((struct filter *) filter, &mod);
	if (err != 0){
	  return(err);
	}
      }
      break;
    case REDIRCTL_CMD_DEACTIVATE_FILTER:
      {
        char *filter_name = NULL;
	rfs_filter filter;
	int err;
	union rfs_mod mod;

	if (copy_chararr_from_user(&filter_name, ptr) < 0){
	  return(-ENOMEM);
	}

	err = flt_get_by_name(&filter, filter_name);
	kfree(filter_name);
	if (err != 0){
	  return(-ENODEV);
	}
	
	mod.id = RFS_DEACTIVATE;
	err = flt_execute_mod_cb((struct filter *) filter, &mod);
	if (err != 0){
	  return(err);
	}
      }
      break;
    default:
      return(-ENOIOCTLCMD);
  }
  return(0);
}

static struct file_operations redirctl_ops = {
  .owner = THIS_MODULE,
  .ioctl = redirctl_ioctl,
};

static struct class *redirctl_class;
static unsigned int redirctl_major;

int redirctl_init(void){
  int err=0;

  if ((redirctl_major = register_chrdev(0, REDIRCTL_NAME, &redirctl_ops)))
    goto end;

  redirctl_class = class_create(THIS_MODULE, REDIRCTL_NAME);
  if (IS_ERR(redirctl_class)){
    err = PTR_ERR(redirctl_class);
    goto unreg_cdev;
  }
  class_device_create(redirctl_class, NULL, MKDEV(redirctl_major,0), NULL, REDIRCTL_NAME);

  return(0);

unreg_cdev:
  unregister_chrdev(redirctl_major, REDIRCTL_NAME);

end:
  return(err);
}

void redirctl_destroy(void){
  class_device_destroy(redirctl_class, MKDEV(redirctl_major,0));
  class_destroy(redirctl_class);
  unregister_chrdev(redirctl_major, REDIRCTL_NAME);
}

