#include "redir.h"

static int rfs_replace_ops(struct dentry *dentry, void *data)
{
	struct path *path = (struct path *)data;
	struct rdentry *rdentry;
	struct rinode *rinode;

	rdentry = rdentry_add(dentry, path);
	if (IS_ERR(rdentry)) {
		BUG();
		return PTR_ERR(rdentry);
	}

	rinode = rinode_add(dentry->d_inode, rdentry, path);
	if (IS_ERR(rinode)) {
		BUG();
		rdentry_put(rdentry);
		return PTR_ERR(rinode);
	}

	path_add_rinode(path, rinode);
	path_add_rdentry(path, rdentry);
	rdentry_put(rdentry);
	rinode_put(rinode);

	return 0;
}

static int rfs_restore_ops(struct dentry *dentry, void *data)
{
	struct path *path = (struct path *)data;
	struct rdentry *rdentry = rdentry_find(dentry);
	struct rinode *rinode = rinode_find(dentry->d_inode);

	rinode_del(dentry->d_inode);
	path_del_rinode(path, rinode);
	rdentry_del(dentry);
	path_del_rdentry(path, rdentry);
	rdentry_put(rdentry);
	rinode_put(rinode);

	return 0;
}

struct entry {
	struct list_head e_list;
	struct dentry *e_dentry;
};

int rfs_walk_dcache(struct dentry *root,
		    int (*dcb)(struct dentry *dentry, void *dentry_data),
		    void *dcb_data,
		    int (*mcb)(struct dentry *dentry, void *dentry_data),
		    void *mcb_data)
{
	LIST_HEAD(dirs);
	LIST_HEAD(sibs);
	struct entry *dir;
	struct entry *sib;
	struct entry *tmp;
	struct entry *subdir;
	struct dentry *dentry;
	struct inode *inode;
	struct inode *itmp;
	struct list_head *head;


	dir = kmalloc(sizeof(struct entry), GFP_KERNEL);
	if (!dir) {
		BUG();
		return -1;
	}

	INIT_LIST_HEAD(&dir->e_list);
	dir->e_dentry = dget(root);
	list_add_tail(&dir->e_list, &dirs);

	while (!list_empty(&dirs)) {
		dir = list_entry(dirs.next, struct entry, e_list);

		if (dcb(dir->e_dentry, dcb_data))
			goto err;

		inode = dir->e_dentry->d_inode;
		if (!inode)
			goto next_dir;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
		down(&inode->i_sem);
#else
		mutex_lock(&inode->i_mutex);
#endif
		spin_lock(&dcache_lock);

		head = &dir->e_dentry->d_subdirs;
		INIT_LIST_HEAD(&sibs);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
		list_for_each_entry(dentry, head, d_child) {
#else
		list_for_each_entry(dentry, head, d_u.d_child) {
#endif
			spin_lock(&dentry->d_lock);
			if (d_unhashed(dentry)) {
				spin_unlock(&dentry->d_lock);
				continue;
			}
			atomic_inc(&dentry->d_count);
			spin_unlock(&dentry->d_lock);

			sib = kmalloc(sizeof(struct entry), GFP_ATOMIC);
			if (!sib)
				goto err_dcache_lock;

			INIT_LIST_HEAD(&sib->e_list);
			sib->e_dentry = dentry;
			list_add_tail(&sib->e_list, &sibs);
		}

		spin_unlock(&dcache_lock);

		list_for_each_entry_safe(sib, tmp, &sibs, e_list) {
			dentry = sib->e_dentry;
			itmp = dentry->d_inode;

			if (dcb(dentry, dcb_data))
				goto err_inode_lock;

			if (!itmp || !S_ISDIR(itmp->i_mode))
				goto next_sib;

			subdir = kmalloc(sizeof(struct entry), GFP_KERNEL);
			if (!subdir) 
				goto err_inode_lock;

			INIT_LIST_HEAD(&subdir->e_list);
			subdir->e_dentry = dget(dentry);
			list_add_tail(&subdir->e_list, &dirs);

next_sib:
			list_del(&sib->e_list);
			dput(sib->e_dentry);
			kfree(sib);
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
		up(&inode->i_sem);
#else
		mutex_unlock(&inode->i_mutex);
#endif

next_dir:
		list_del(&dir->e_list);
		dput(dir->e_dentry);
		kfree(dir);
	}

	return 0;

err_dcache_lock:
	spin_unlock(&dcache_lock);
err_inode_lock:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
	up(&inode->i_sem);
#else
	mutex_unlock(&inode->i_mutex);
#endif
err:
	BUG();
	list_splice(&sibs, &dirs);
	list_for_each_entry_safe(dir, tmp, &dirs, e_list) {
		dput(dir->e_dentry);
		list_del(&dir->e_list);
		kfree(dir);
	}

	return -1;
}

static struct dentry *dentry;
static struct path* path;

static int __init rfs_init(void)
{
	struct nameidata nd;


	path = path_alloc();
	if (!path)
		return -1;

	if (rdentry_cache_create())
		return -1;

	if (rinode_cache_create())
		return -1;

	if (path_lookup("/home", LOOKUP_FOLLOW, &nd)) {
		synchronize_rcu();
		rdentry_cache_destroy();
		return -1;
	}

	dentry = dget(nd.dentry);

	rfs_walk_dcache(dentry, rfs_replace_ops, path, NULL, NULL);

	return 0;
}

static void __exit rfs_exit(void)
{
	rfs_walk_dcache(dentry, rfs_restore_ops, path, NULL, NULL);
	dput(dentry);

	path_del(path);
	path_put(path);
	synchronize_rcu();
	rdentry_cache_destroy();
	rinode_cache_destroy();
}

module_init(rfs_init);
module_exit(rfs_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <franta@redirfs.org>");
MODULE_DESCRIPTION("RedirFS - VFS callback framework");
