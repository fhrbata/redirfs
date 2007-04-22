#include <stdio.h>
#include <string.h>
#include "urfs.h"

void usage(void){
  printf("usage: redirctl [command] [options]\n"
         "commands:\n"
	 "  list\n"
	 "  paths filter_name\n"
	 "  setpath filter_name path [include|exclude] [single|subtree]\n"
	 "  activate filter_name\n"
	 "  deactivate filter_name\n");
}

int main(int argc, char *argv[]){
  struct urfsconn_t c;
  enum urfs_err err;
  int len;
  int offset;
  void *data;

  int retval = 0;
 
  if (argc < 2){
    usage();
    return(1);
  }

  if (urfs_open(&c) != URFS_ERR_OK){
    printf("urfs_open failed\n");
    return(2);
  }

  if (strcmp(argv[1], "list") == 0){
    int namememlen;
    char *name;
    int priority;
    int active;

    err = urfs_filters_list(&c, &data, &len);
    if (err != URFS_ERR_OK){
      printf("urfs_filter_list failed\n");
      retval = 3;
      goto end;
    }
    
    if (len > 0){
      offset = 0;
      while(len - offset > 0){
        namememlen = *((int *) (data + offset));
        offset += sizeof(int);
        name = (char *) (data + offset);
        offset += namememlen;
        priority = *((int *) (data + offset));
        offset += sizeof(int);
        active = *((int *) (data + offset));
        offset += sizeof(int);
        printf("%s %d %d\n", name, priority, active);
      }
      free(data);
    }
  }
  else if (strcmp(argv[1], "paths") == 0){
    int pathmemlen;
    char *path;
    int flags;

    if (argc < 3){
      usage();
      retval = 1;
      goto end;
    }

    err = urfs_filter_list_paths(&c, argv[2], &data, &len);
    if (err == URFS_ERR_NOTFOUND){
      printf("filter named \"%s\" does not exist\n", argv[2]);
      retval = 4;
      goto end;
    }
    if (err != URFS_ERR_OK){
      printf("urfs_filter_list failed\n");
      retval = 5;
      goto end;
    }
    
    if (len > 0){
      offset = 0;
      while(len - offset > 0){
        pathmemlen = *((int *) (data + offset));
        offset += sizeof(int);
        path = (char *) (data + offset);
        offset += pathmemlen;
        flags = *((int *) (data + offset));
        offset += sizeof(int);
        printf("%s 0x%04X\n", path, flags);
      }
      free(data);
    }
  }
  else if (strcmp(argv[1], "setpath") == 0){
    int flags = 0;

    if (argc < 6){
      usage();
      retval = 1;
      goto end;
    }

    if (strcmp(argv[4], "include") == 0){
      flags |= RFS_PATH_INCLUDE;
    }
    else if (strcmp(argv[4], "exclude") == 0){
      flags |= RFS_PATH_EXCLUDE;
    }
    else{
      printf("\"include\" or \"exclude\" must be passed\n");
      usage();
      retval = 1;
      goto end;
    }

    if (strcmp(argv[5], "single") == 0){
      flags |= RFS_PATH_SINGLE;
    }
    else if (strcmp(argv[5], "subtree") == 0){
      flags |= RFS_PATH_SUBTREE;
    }
    else{
      printf("\"single\" or \"subtree\" must be passed\n");
      usage();
      retval = 1;
      goto end;
    }

    err = urfs_filter_set_path(&c, argv[2], argv[3], flags);
    if (err == URFS_ERR_NOTFOUND){
      printf("filter named \"%s\" does not exist\n", argv[2]);
      retval = 4;
      goto end;
    }
    if (err != URFS_ERR_OK){
      printf("urfs_filter_set_path failed\n");
      retval = 6;
      goto end;
    }
  }
  else if (strcmp(argv[1], "activate") == 0){
    if (argc < 3){
      usage();
      retval = 1;
      goto end;
    }

    err = urfs_activate_filter(&c, argv[2]);
    if (err == URFS_ERR_NOTFOUND){
      printf("filter named \"%s\" does not exist\n", argv[2]);
      retval = 4;
      goto end;
    }
    if (err != URFS_ERR_OK){
      printf("urfs_activate_filter failed\n");
      retval = 6;
      goto end;
    }
  }
  else if (strcmp(argv[1], "deactivate") == 0){
    if (argc < 3){
      usage();
      retval = 1;
      goto end;
    }

    err = urfs_deactivate_filter(&c, argv[2]);
    if (err == URFS_ERR_NOTFOUND){
      printf("filter named \"%s\" does not exist\n", argv[2]);
      retval = 4;
      goto end;
    }
    if (err != URFS_ERR_OK){
      printf("urfs_deactivate_filter failed\n");
      retval = 6;
      goto end;
    }
  }
  else{
    usage();
    retval = 1;
  }

end:
  urfs_close(&c);
  return(retval);
}

