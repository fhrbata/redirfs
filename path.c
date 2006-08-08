#include "redir.h"

struct path *path_alloc(void)
{
	struct path *path = NULL;


	path = kmalloc(sizeof(struct path), GFP_KERNEL);
	if (!path)
		return NULL;

	atomic_set(&path->p_count, 1);
	INIT_LIST_HEAD(&path->p_rdentry);
	INIT_LIST_HEAD(&path->p_rinode);
	spin_lock_init(&path->p_lock);

	return path;
}

inline struct path *path_get(struct path *path)
{
	BUG_ON(!atomic_read(&path->p_count));
	atomic_inc(&path->p_count);
	return path;
}

inline void path_put(struct path *path)
{
	if (!path || IS_ERR(path))
		return;

	BUG_ON(!atomic_read(&path->p_count));
	if (!atomic_dec_and_test(&path->p_count))
		return;

	kfree(path);
}

