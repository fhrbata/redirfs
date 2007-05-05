#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../../urfs.h"

enum rfs_retv udummyflt_permission(rfs_context context, struct rfs_args *args){
  printf("udummyflt: permission: dentry: %s, call: %s, file: %s\n",
	 args->args.i_permission.nd ? (char *)args->args.i_permission.nd->dentry->d_name.name : "",
	 (args->type.call == RFS_PRECALL) ? "precall" : "postcall",
	 S_ISDIR(args->args.i_permission.inode->i_mode) ? "dir" : "reg");
  return(RFS_CONTINUE);
}

enum rfs_retv udummyflt_open(rfs_context context, struct rfs_args *args){
  printf("udummyflt: open: dentry: %s, call: %s, file: %s\n",
	 args->args.f_open.file->f_dentry->d_name.name, 
	 (args->type.call == RFS_PRECALL) ? "precall" : "postcall",
	 S_ISDIR(args->args.f_open.inode->i_mode) ? "dir" : "reg");
  return(RFS_CONTINUE);
}

static struct rfs_op_info op_info[] = {
  {RFS_REG_IOP_PERMISSION, udummyflt_permission, udummyflt_permission},
  {RFS_DIR_IOP_PERMISSION, udummyflt_permission, udummyflt_permission},
  {RFS_REG_FOP_OPEN, udummyflt_open, udummyflt_open},
  {RFS_DIR_FOP_OPEN, udummyflt_open, udummyflt_open},
  {RFS_OP_END, NULL, NULL}
};

int main(int argc, char *argv[]){
  struct urfs_conn c;
  int err;
  rfs_filter flt;
  struct rfs_filter_info filter_info = {"udummyftl", 12, 0};
  struct rfs_path_info path_info = {"/tmp", RFS_PATH_INCLUDE | RFS_PATH_SUBTREE};

  err = urfs_open(&c);
  if (err){
    printf("can't open nodfile\n");
    return(1);
  }
  if (urfs_filter_alloc(&flt, &c)){
    printf("cannot alloc filter\n");
    goto close;
  }

  err = rfs_register_filter(&flt, &filter_info);
  if (err){
    printf("rfs_register_filter failed: %d\n", err);
    goto free_filter;
  }
  
  err = rfs_set_operations(flt, op_info);
  if (err){
    printf("rfs_set_operations failed: %d\n", err);
    goto free_filter;
  }

  err = rfs_set_path(flt, &path_info);
  if (err){
    printf("rfs_set_path failed: %d\n", err);
    goto free_filter;
  }

  err = rfs_activate_filter(flt);
  if (err){
    printf("rfs_activate_filter failed: %d\n", err);
    goto free_filter;
  }
  
  err = urfs_main(&c, flt);
  if (err){
    printf("urfs_main failed: %d - %s\n", err, strerror(errno));
    goto free_filter;
  }

  err = rfs_deactivate_filter(flt);
  if (err){
    printf("rfs_deactivate_filter failed: %d\n", err);
    goto free_filter;
  }
  
  err = rfs_unregister_filter(flt);
  if (err){
    printf("rfs_unregister_filter failed: %d\n", err);
    goto free_filter;
  }

free_filter:
  urfs_filter_free(flt);

close:
  urfs_close(&c);
  return(0);
}
