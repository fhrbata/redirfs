#include <sys/mount.h>
#include <sys/kernel.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/namei.h>                                                                                  
#include <sys/proc.h>
#include <sys/vnode.h> 
#include <sys/tree.h>

#include <fs/larefs/larefs.h>
#include <fs/larefs/lrfs.h>

static MALLOC_DEFINE(M_LRFSFILTERS, "lrfs_filtes", "LRFS filters structure");


int
init_filter_list(struct lrfs_filters **list) 
{
	struct lrfs_filters *flist;

	flist = (struct lrfs_filters *)
		malloc(sizeof(struct lrfs_filters),
		M_LRFSFILTERS, M_WAITOK);

	flist->count = 0;

	SLIST_INIT(&flist->head);

	*list = flist;

	return 0;
}

int free_filter_list(struct lrfs_filters *list) 
{
	free(list, M_LRFSFILTERS);

	return 0;
}

struct larefs_filter_t *
find_filter_byname(const char *name) 
{
	struct larefs_filter_t *filter = NULL;
	int len;

	if (!name)
		return NULL;

	len = strlen(name);

	SLIST_FOREACH(filter, &registered_filters->head, entry) {
		if ((strncmp(filter->name, name, len) == 0) &&
			filter->name[len] == '\0')
			return filter;
	}

	return NULL;
}

int 
larefs_register_filter(struct larefs_filter_t *filter)
{
	registered_filters->count += 1;
	
	SLIST_INSERT_HEAD(&registered_filters->head, filter, entry);

	uprintf("registering filter: %s\norder: %d\n", filter->name, filter->order);
	return 0;
}

int
larefs_unregister_filter(struct larefs_filter_t *filter)
{

	/* We whould remove the filter from the rbtree first*/

	SLIST_REMOVE(&registered_filters->head, filter, larefs_filter_t, entry);

	registered_filters->count -= 1;

	return (0);
}
