#include "urfs.h"

#define GETCONN(filp) ((struct conn *) filp->private_data)

int process_out_cmd_op_callback(struct ufilter *ufilter, struct request *request){
  struct omsg_list *omsg_list;
  struct conn *c = ufilter->c;

  omsg_list = OMSG_LIST_ALLOC;
  if (!omsg_list){
    return(-ENOMEM);
  }

  omsg_list->omsg.cmd = URFS_CMD_OP_CALLBACK;
  omsg_list->omsg.op_callback.ufilter_id = ufilter->id;
  omsg_list->omsg.op_callback.request_id = request->id;
  omsg_list->omsg.op_callback.context = request->context;
  
  // args copy to userspace here

  ufilter_request_add(ufilter, request);
  
  conn_msg_append(c, omsg_list);

  return(0);
}

static ssize_t urfs_read(struct file *filp, char __user *buff, size_t count, loff_t *offp){
  struct omsg_list *omsg_list;
  ssize_t len = sizeof(union omsg);

  dbgmsg(PRINTPREFIX "read\n");

  if (count < len){
    return(-EINVAL);
  }

  omsg_list = conn_msg_get_next(GETCONN(filp));
  if (omsg_list == NULL){
    return(-EAGAIN);
  }

  if (copy_to_user(buff, &omsg_list->omsg, len)){
    return(-EINVAL);
  }
  
  OMSG_LIST_FREE(omsg_list);
  
  return(len);
}

static int process_in_cmd_op_callback(struct conn *c, union imsg *imsg){
  struct request *request;
  struct ufilter *ufilter;
  int ufilter_id;

  ufilter_id = imsg->op_callback.ufilter_id;
  dbgmsg(PRINTPREFIX "ufilter_id: %d\n", ufilter_id);
  ufilter = conn_get_ufilter(c, ufilter_id);
  if (!ufilter){
    return(-EINVAL);
  }
  request = ufilter_request_get(ufilter, imsg->op_callback.request_id, 1);
  if (!request){
    return(-EINVAL);
  }
  
  request->retval = imsg->op_callback.retval;
  complete(&request->completion);

  return(0);
}

static int make_user_ptr(void __user *dst, void *src){
  return(copy_to_user(dst, &src, sizeof (void *)));
}

static int copy_inode_to_user(struct urfs_inode *uinode, struct inode *inode){
  int err;

  err = copy_to_user(&uinode->i_mode, &inode->i_mode, sizeof(umode_t));
  if (err){
    return(err);
  }
  return(0);
}

static int copy_qstr_to_user(struct urfs_str *ustr, struct qstr *qstr, unsigned char __user *str){
  int err;

  err = copy_to_user(&ustr->len, &qstr->len, sizeof(unsigned int));
  if (err){
    return(err);
  }
  err = copy_to_user(str, qstr->name, qstr->len + 1);
  if (err){
    return(err);
  }
  err = copy_to_user(&ustr->name, &str, sizeof(unsigned char *));
  if (err){
    return(err);
  }
  return(0);
}

static int copy_dentry_to_user(struct urfs_dentry *udentry, struct dentry *dentry, unsigned char __user *str){
  int err;

  err = copy_qstr_to_user(&udentry->d_name, &dentry->d_name, str);
  if (err){
    return(err);
  }
  return(0);
}

static int copy_nameidata_to_user(struct urfs_nameidata *und, struct nameidata *nd, unsigned char __user *str){
  int err;

  err = copy_dentry_to_user(&und->__dentry, nd->dentry, str);
  if (err){
    return(err);
  }
  err = make_user_ptr(&und->dentry, &und->__dentry);
  if (err){
    return(err);
  }
  return(0);
}

static int copy_file_to_user(struct urfs_file *ufile, struct file *file, unsigned char __user *str){
  int err;

  err = copy_dentry_to_user(&ufile->__f_dentry, file->f_dentry, str);
  if (err){
    return(err);
  }
  err = make_user_ptr(&ufile->f_dentry, &ufile->__f_dentry);
  if (err){
    return(err);
  }
  return(0);
}

static int process_in_cmd_op_callback_get_args(struct conn *c, union imsg *imsg){
  struct request *request;
  struct ufilter *ufilter;
  int ufilter_id;
  struct omsg_list *omsg_list;
  struct urfs_args __user *uargs;
  struct rfs_args *args;
  enum rfs_err err;
  unsigned char __user *str;

  err = RFS_ERR_INVAL;
  ufilter_id = imsg->op_callback_get_args.ufilter_id;
  ufilter = conn_get_ufilter(c, ufilter_id);
  if (!ufilter){
    goto send_error;
  }
  request = ufilter_request_get(ufilter, imsg->op_callback_get_args.request_id, 0);
  if (!request){
    goto send_error;
  }

  args = request->args;
  uargs = imsg->op_callback_get_args.args;
  if (!uargs){
    goto send_error;
  }
  str = imsg->op_callback_get_args.str;
  if (!str){
    goto send_error;
  }

  if (copy_to_user(&uargs->type, &args->type, sizeof(struct rfs_op_type))){
    goto send_error;
  }

  switch (args->type.id){
    case RFS_REG_IOP_PERMISSION:
    case RFS_DIR_IOP_PERMISSION:
      if (copy_inode_to_user(&uargs->args.i_permission.__inode, args->args.i_permission.inode)){
        goto send_error;
      }
      if (make_user_ptr(&uargs->args.i_permission.inode, &uargs->args.i_permission.__inode)){
        goto send_error;
      }
      if (copy_to_user(&uargs->args.i_permission.mask, &args->args.i_permission.mask, sizeof(int))){
        goto send_error;
      }
      if (copy_nameidata_to_user(&uargs->args.i_permission.__nd, args->args.i_permission.nd, str)){
        goto send_error;
      }
      if (make_user_ptr(&uargs->args.i_permission.nd, &uargs->args.i_permission.__nd)){
        goto send_error;
      }
      break;
    case RFS_REG_FOP_OPEN:
    case RFS_DIR_FOP_OPEN:
      if (copy_inode_to_user(&uargs->args.f_open.__inode, args->args.f_open.inode)){
        goto send_error;
      }
      if (make_user_ptr(&uargs->args.f_open.inode, &uargs->args.f_open.__inode)){
        goto send_error;
      }
      if (copy_file_to_user(&uargs->args.f_open.__file, args->args.f_open.file, str)){
        goto send_error;
      }
      if (make_user_ptr(&uargs->args.f_open.file, &uargs->args.f_open.__file)){
        goto send_error;
      }
      break;
    default:
      break;
  }
  
  request->retval = imsg->op_callback.retval;
  complete(&request->completion);

send_error:
  omsg_list = OMSG_LIST_ALLOC;
  if (!omsg_list){
    return(-ENOMEM);
  }
  omsg_list->omsg.cmd = imsg->cmd;
  omsg_list->omsg.op_callback_get_args.err = err;
  conn_msg_insert(c, omsg_list);
  return(0);
}

static int process_in_cmd_filter_register(struct conn *c, union imsg *imsg){
  char *filter_name = NULL;
  enum rfs_err err;
  int id = 0;
  struct ufilter *ufilter;
  struct omsg_list *omsg_list;
  struct rfs_filter_info info;
  int len;
 
  err = RFS_ERR_INVAL;
  if (!imsg->filter_register.filter_info){
    goto send_error;
  }
  if (copy_from_user(&info, imsg->filter_register.filter_info, sizeof(struct rfs_filter_info))){
    goto send_error;
  }
  if (!info.name){ // check for null name pointer
    goto send_error;
  }
  len = imsg->filter_register.filter_name_memlen;
  if (len <= 0){
    goto send_error;
  }
  filter_name = (char *) kmalloc(len, GFP_KERNEL);
  if (!filter_name){
    err = RFS_ERR_NOMEM;
    goto send_error;
  }
  if (copy_from_user(filter_name, info.name, len)){
    goto free_filter_name;
  }

  if (conn_alloc_ufilter(c, &id)){
     err = RFS_ERR_NOMEM;
     goto free_filter_name;
  }
  ufilter = conn_get_ufilter(c, id);
  if (!ufilter){
    err = RFS_ERR_NOENT;
    goto free_filter_name;
  }
  dbgmsg(PRINTPREFIX "name: %s, prio: %d, act: %d\n", filter_name, info.priority, info.active);
  err = ufilter_register(ufilter, filter_name, info.priority, info.active);

free_filter_name:
  kfree(filter_name);

send_error:
  omsg_list = OMSG_LIST_ALLOC;
  if (!omsg_list){
    return(-ENOMEM);
  }
  omsg_list->omsg.cmd = imsg->cmd;
  omsg_list->omsg.filter_register.err = err;
  omsg_list->omsg.filter_register.ufilter_id = id;
  conn_msg_insert(c, omsg_list);
  return(0);
}

static int process_in_cmd_filter_unregister(struct conn *c, union imsg *imsg){
  enum rfs_err err;
  struct ufilter *ufilter;
  struct omsg_list *omsg_list;
  int ufilter_id;
 
  ufilter_id = imsg->filter_unregister.ufilter_id;
  ufilter = conn_get_ufilter(c, ufilter_id);
  if (!ufilter){
    err = RFS_ERR_NOENT;
    goto send_error;
  }
  err = ufilter_unregister(ufilter);
  conn_free_ufilter(c, ufilter_id);

send_error:
  omsg_list = OMSG_LIST_ALLOC;
  if (!omsg_list){
    return(-ENOMEM);
  }
  omsg_list->omsg.cmd = imsg->cmd;
  omsg_list->omsg.filter_unregister.err = err;
  conn_msg_insert(c, omsg_list);
  return(0);
}

static int process_in_cmd_filter_activate(struct conn *c, union imsg *imsg){
  enum rfs_err err;
  struct ufilter *ufilter;
  struct omsg_list *omsg_list;
 
  ufilter = conn_get_ufilter(c, imsg->filter_activate.ufilter_id);
  if (!ufilter){
    err = RFS_ERR_NOENT;
    goto send_error;
  }
  if (ufilter->flt == NULL){
    dbgmsg("null pointer\n");
  }
  err = ufilter_activate(ufilter);

send_error:
  omsg_list = OMSG_LIST_ALLOC;
  if (!omsg_list){
    return(-ENOMEM);
  }
  omsg_list->omsg.cmd = imsg->cmd;
  omsg_list->omsg.filter_activate.err = err;
  conn_msg_insert(c, omsg_list);
  return(0);
}

static int process_in_cmd_filter_deactivate(struct conn *c, union imsg *imsg){
  enum rfs_err err;
  struct ufilter *ufilter;
  struct omsg_list *omsg_list;
 
  ufilter = conn_get_ufilter(c, imsg->filter_deactivate.ufilter_id);
  if (!ufilter){
    err = RFS_ERR_NOENT;
    goto send_error;
  }
  err = ufilter_deactivate(ufilter);

send_error:
  omsg_list = OMSG_LIST_ALLOC;
  if (!omsg_list){
    return(-ENOMEM);
  }
  omsg_list->omsg.cmd = imsg->cmd;
  omsg_list->omsg.filter_deactivate.err = err;
  conn_msg_insert(c, omsg_list);
  return(0);
}

static int process_in_cmd_filter_set_path(struct conn *c, union imsg *imsg){
  char *path = NULL;
  enum rfs_err err;
  struct ufilter *ufilter;
  struct omsg_list *omsg_list;
  struct rfs_path_info info;
  int len;
 
  err = RFS_ERR_INVAL;
  if (!imsg->filter_set_path.path_info){
    goto send_error;
  }
  if (copy_from_user(&info, imsg->filter_set_path.path_info, sizeof(struct rfs_path_info))){
    goto send_error;
  }
  if (!info.path){ // check for null name pointer
    goto send_error;
  }
  len = imsg->filter_set_path.path_memlen;
  if (len <= 0){
    goto send_error;
  }
  path = (char *) kmalloc(len, GFP_KERNEL);
  if (!path){
    err = RFS_ERR_NOMEM;
    goto send_error;
  }
  if (copy_from_user(path, info.path, len)){
    goto free_path;
  }

  ufilter = conn_get_ufilter(c, imsg->filter_set_path.ufilter_id);
  if (!ufilter){
    err = RFS_ERR_NOENT;
    goto free_path;
  }
  dbgmsg(PRINTPREFIX "path: %s, prio: 0x%X\n", path, info.flags);
  err = ufilter_set_path(ufilter, path, info.flags);

free_path:
  kfree(path);

send_error:
  omsg_list = OMSG_LIST_ALLOC;
  if (!omsg_list){
    return(-ENOMEM);
  }
  omsg_list->omsg.cmd = imsg->cmd;
  omsg_list->omsg.filter_set_path.err = err;
  conn_msg_insert(c, omsg_list);
  return(0);
}

static int process_in_cmd_filter_set_operations(struct conn *c, union imsg *imsg){
  struct rfs_op_info *op_info = NULL;
  struct rfs_op_info *op;
  enum rfs_err err;
  struct ufilter *ufilter;
  struct omsg_list *omsg_list;
  char ops_call_flags[RFS_OP_END];
  int op_info_count;
  int i;

  err = RFS_ERR_INVAL;
  if (!imsg->filter_set_operations.ops_call_flags){
    goto send_error;
  }
  if (copy_from_user(&ops_call_flags, imsg->filter_set_operations.ops_call_flags, sizeof(char) * RFS_OP_END)){
    goto send_error;
  }
  // count number of used operations
  op_info_count = 0;
  for(i = 0; i < RFS_OP_END; i++){
    if (ops_call_flags[i]){
      op_info_count++;
    }
  }
  op_info = (struct rfs_op_info *) kmalloc(sizeof(struct rfs_op_info) * (op_info_count + 1), GFP_KERNEL);
  if (!op_info){
    err = RFS_ERR_NOMEM;
    goto send_error;
  }
  // set array of rfs_op_info to call generic callback for all used operations
  op_info_count = 0;
  for(i = 0; i < RFS_OP_END; i++){
    if (ops_call_flags[i]){
      op = &op_info[op_info_count];
      op->op_id = i;
      op->pre_cb = ops_call_flags[i] | PRE_CALL_FLAG ? ufilter_generic_cb : NULL;
      if (op->pre_cb){
        dbgmsg(PRINTPREFIX "setting pre_cb for op_id %d\n", i);
      }
      op->post_cb = ops_call_flags[i] | POST_CALL_FLAG ? ufilter_generic_cb : NULL;
      if (op->post_cb){
        dbgmsg(PRINTPREFIX "setting post_cb for op_id %d\n", i);
      }
      op_info_count++;
    }
  }
  op = &op_info[op_info_count];
  op->op_id = RFS_OP_END;
  op->pre_cb = NULL;
  op->post_cb = NULL;

  ufilter = conn_get_ufilter(c, imsg->filter_set_operations.ufilter_id);
  if (!ufilter){
    err = RFS_ERR_NOENT;
    goto free_op_info;
  }
  err = ufilter_set_operations(ufilter, op_info);

free_op_info:
  kfree(op_info);

send_error:
  omsg_list = OMSG_LIST_ALLOC;
  if (!omsg_list){
    return(-ENOMEM);
  }
  omsg_list->omsg.cmd = imsg->cmd;
  omsg_list->omsg.filter_set_operations.err = err;
  conn_msg_insert(c, omsg_list);
  return(0);
}

static int process_in_cmd_conn_switch_callbacks(struct conn *c, union imsg *imsg){
  struct omsg_list *omsg_list;
 
  conn_switch_callbacks(c, imsg->conn_switch_callbacks.enable);

  omsg_list = OMSG_LIST_ALLOC;
  if (!omsg_list){
    return(-ENOMEM);
  }
  omsg_list->omsg.cmd = imsg->cmd;
  conn_msg_insert(c, omsg_list);
  return(0);
}

static ssize_t urfs_write(struct file *filp, const char __user *buff, size_t count, loff_t *offp){  
  union imsg imsg;
  struct conn *c = GETCONN(filp);
  int err = 0;
  int len = sizeof(union imsg);

  dbgmsg(PRINTPREFIX "write\n");

  if (count < len){
    return(-EINVAL);
  }
    
  if (copy_from_user(&imsg, buff, len)){
    return(-EINVAL);  
  }
  
  switch (imsg.cmd){
    case URFS_CMD_FILTER_REGISTER:
      err = process_in_cmd_filter_register(c, &imsg);
      break;
    case URFS_CMD_FILTER_UNREGISTER:
      err = process_in_cmd_filter_unregister(c, &imsg);
      break;
    case URFS_CMD_FILTER_ACTIVATE:
      err = process_in_cmd_filter_activate(c, &imsg);
      break;
    case URFS_CMD_FILTER_DEACTIVATE:
      err = process_in_cmd_filter_deactivate(c, &imsg);
      break;
    case URFS_CMD_FILTER_SET_PATH:
      err = process_in_cmd_filter_set_path(c, &imsg);
      break;
    case URFS_CMD_FILTER_SET_OPERATIONS:
      err = process_in_cmd_filter_set_operations(c, &imsg);
      break;
    case URFS_CMD_CONN_SWITCH_CALLBACKS:
      err = process_in_cmd_conn_switch_callbacks(c, &imsg);
      break;
    case URFS_CMD_OP_CALLBACK:
      err = process_in_cmd_op_callback(c, &imsg);
      break;
    case URFS_CMD_OP_CALLBACK_GET_ARGS:
      err = process_in_cmd_op_callback_get_args(c, &imsg);
      break;
    default:
      return(-EINVAL);
  }
  if (err){
    return(err);
  }

  return(len);
}

static unsigned int urfs_poll(struct file *filp, struct poll_table_struct *wait){
  unsigned int retval = POLLOUT | POLLWRNORM;
  struct conn *c = GETCONN(filp);
 
  dbgmsg(PRINTPREFIX "poll started\n");
  poll_wait(filp, &c->waitq, wait);
  if (conn_msg_pending(c)){
    retval |= POLLIN | POLLRDNORM;
  }
  dbgmsg(PRINTPREFIX "poll returned\n");
  return(retval);
}

static int urfs_open(struct inode *ino, struct file *filp){
  struct conn *newconn;
  
  newconn = conn_create();
  if (!newconn){
    return(PTR_ERR(newconn));
  }
  filp->private_data = (void *) newconn; 
  return(0);
}

static int urfs_release(struct inode *ino, struct file *filp){
  conn_destroy(GETCONN(filp));
  return(0);
}

static struct file_operations urfs_ops = {
  .owner = THIS_MODULE,
  .read = urfs_read,
  .write = urfs_write,
  .poll = urfs_poll,
  .open = urfs_open,
  .release = urfs_release,
};

static dev_t urfs_dev;
static struct class *urfs_class;

static int __init _init_module(void){
  int err;

  err = register_chrdev(0, URFS_NAME, &urfs_ops); // passing 0 to assign dynamic major
  if (err < 0){
    printk(KERN_ERR PRINTPREFIX "cannot register chardevice\n");
    goto end;
  }
  
  printk(KERN_INFO PRINTPREFIX "assigned major number %d\n", err);

  urfs_dev = MKDEV(err, 0);

  urfs_class = class_create(THIS_MODULE, URFS_NAME);
  if (IS_ERR(urfs_class)){
    printk(KERN_ERR PRINTPREFIX "cannot create class\n");
    err = PTR_ERR(urfs_class);
    goto unregister;
  }
  class_device_create(urfs_class, NULL, urfs_dev, NULL, URFS_NAME);

  printk(KERN_INFO PRINTPREFIX "loaded\n");

  return(0);

unregister:
  unregister_chrdev(MAJOR(urfs_dev), REDIRCTL_NAME);
end:
  return(err);
}

static void __exit _cleanup_module(void){
  class_device_destroy(urfs_class, urfs_dev);
  class_destroy(urfs_class);
  unregister_chrdev(MAJOR(urfs_dev), REDIRCTL_NAME);
  printk(KERN_INFO PRINTPREFIX "unloaded\n");
}

module_init(_init_module);
module_exit(_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jirka Pirko <jirka@pirko.cz>");
MODULE_DESCRIPTION("Userspace Filters interface for the RedirFS Framework");

