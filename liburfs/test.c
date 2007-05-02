#include <stdio.h>
#include "urfs.h"

enum rfs_retv test_open(rfs_context context, struct rfs_args *args){
  printf("user callback\n");
  return(RFS_CONTINUE);
}

static struct rfs_op_info op_info[] = {
  {RFS_REG_FOP_OPEN, test_open, test_open},
  {RFS_OP_END, NULL, NULL}
};

int main(int argc, char *argv[]){
  struct urfs_conn c;
  int err;
  rfs_filter flt;
  struct rfs_filter_info filter_info = {"test", 11, 0};
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
  printf("filter registered...\n");
  
  err = rfs_set_operations(flt, op_info);
  if (err){
    printf("rfs_set_operations failed: %d\n", err);
    goto free_filter;
  }
  printf("operations set...\n");

  err = rfs_set_path(flt, &path_info);
  if (err){
    printf("rfs_set_path failed: %d\n", err);
    goto free_filter;
  }
  printf("path set...\n");

  err = rfs_activate_filter(flt);
  if (err){
    printf("rfs_activate_filter failed: %d\n", err);
    goto free_filter;
  }
  printf("filter activated...\n");
  
  printf("urfs main\n");
  urfs_main(&c, flt);

  err = rfs_deactivate_filter(flt);
  if (err){
    printf("rfs_deactivate_filter failed: %d\n", err);
    goto free_filter;
  }
  printf("filter deactivated...\n");
  
  err = rfs_unregister_filter(flt);
  if (err){
    printf("rfs_unregister_filter failed: %d\n", err);
    goto free_filter;
  }
  printf("filter unregistered...\n");

free_filter:
  urfs_filter_free(flt);

close:
  urfs_close(&c);
  return(0);
}
