#ifndef __RFS_H
#define __RFS_H

#define RFS_PATH_SINGLE		1	
#define RFS_PATH_SUBTREE	2
#define RFS_PATH_INCLUDE	4	
#define RFS_PATH_EXCLUDE	8

enum urfs_err{
  URFS_ERR_OK = 0,
  URFS_ERR_FAIL = -1,
  URFS_ERR_CANT_OPEN = -2,
  URFS_ERR_NOTFOUND = -3,
  URFS_ERR_NOMEM = -4,
};

struct urfsconn_t{
  int fd;
};

enum urfs_err urfs_open(struct urfsconn_t *n);

enum urfs_err urfs_close(struct urfsconn_t *n);

enum urfs_err urfs_filters_list(struct urfsconn_t *n, void **data, int *len);

enum urfs_err urfs_filter_list_paths(struct urfsconn_t *n, char *filter_name, void **data, int *len);

enum urfs_err urfs_filter_set_path(struct urfsconn_t *n, char *filter_name, char *path, int flags);

enum urfs_err urfs_activate_filter(struct urfsconn_t *n, char *filter_name);

enum urfs_err urfs_deactivate_filter(struct urfsconn_t *n, char *filter_name);

#endif

