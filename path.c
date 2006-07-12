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
	BUG_ON(!atomic_read(&path->p_count));
	if (!atomic_dec_and_test(&path->p_count))
		return;

	kfree(path);
}

static void path_del_all_rdentry(struct path *path)
{
	struct rdentry *rdentry;
	struct rdentry *tmp;


	spin_lock(&path->p_lock);

	list_for_each_entry_safe(rdentry, tmp, &path->p_rdentry, rd_list) {
		list_del(&rdentry->rd_list);
		rdentry_del(rdentry->rd_dentry);
		rdentry_put(rdentry);
	}

	spin_unlock(&path->p_lock);
}

static void path_del_all_rinode(struct path *path)
{
	struct rinode *rinode;
	struct rinode *tmp;

	
	spin_lock(&path->p_lock);

	list_for_each_entry_safe(rinode, tmp, &path->p_rinode, ri_list) {
		list_del(&rinode->ri_list);
		rinode_del(rinode->ri_inode);
		rinode_put(rinode);
	}

	spin_unlock(&path->p_lock);
}

int path_del(struct path *path)
{
	path_del_all_rinode(path);
	path_del_all_rdentry(path);

	return 0;
}

inline void path_add_rdentry(struct path *path, struct rdentry *rdentry)
{
	if (!rdentry)
		return;

	spin_lock(&path->p_lock);
	list_add_tail(&rdentry->rd_list, &path->p_rdentry);
	spin_unlock(&path->p_lock);
	rdentry_get(rdentry);
}

inline void path_del_rdentry(struct path *path, struct rdentry *rdentry)
{
	if (!rdentry)
		return;

	spin_lock(&path->p_lock);
	if (list_empty(&rdentry->rd_list)) {
		spin_unlock(&path->p_lock);
		return;
	}
	list_del_init(&rdentry->rd_list);
	spin_unlock(&path->p_lock);
	rdentry_put(rdentry);
}

inline void path_add_rinode(struct path *path, struct rinode *rinode)
{
	if (!rinode)
		return;

	spin_lock(&path->p_lock);
	list_add_tail(&rinode->ri_list, &path->p_rinode);
	spin_unlock(&path->p_lock);
	rinode_get(rinode);
}

inline void path_del_rinode(struct path *path, struct rinode *rinode)
{
	if (!rinode)
		return;

	if (atomic_read(&rinode->ri_nlink)) 
		return;

	spin_lock(&path->p_lock);
	if (list_empty(&rinode->ri_list)) {
		spin_unlock(&path->p_lock);
		return;
	}
	list_del_init(&rinode->ri_list);
	spin_unlock(&path->p_lock);
	rinode_put(rinode);
}
