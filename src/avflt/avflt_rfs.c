#include "avflt.h"

#define AVFLT_REG_FOP_OPEN		0
#define AVFLT_REG_IOP_PERMISSION	1
#define AVFLT_REG_FOP_RELEASE		2

#define AVFLT_CLEAN			1
#define AVFLT_INFECTED			2

struct avflt_data {
	struct rfs_priv_data rfs_data;
	atomic_t state;
};

#define rfs_to_avflt_data(ptr) container_of(ptr, struct avflt_data, rfs_data)

static int avflt_ctl(struct rfs_ctl *ctl);

rfs_filter avflt;
static struct rfs_filter_info avflt_info = {"avflt", 666, 0, avflt_ctl};

int avflt_open = 1;
int avflt_close = 1;
int avflt_exec = 1;
spinlock_t avflt_rops_lock = SPIN_LOCK_UNLOCKED;
static struct kmem_cache *avflt_data_cache = NULL;

static struct rfs_op_info avflt_rops[] = {
	{RFS_REG_FOP_OPEN, NULL, NULL},
	{RFS_REG_IOP_PERMISSION, NULL, NULL},
	{RFS_REG_FOP_RELEASE, NULL, NULL},
	{RFS_OP_END, NULL, NULL}
};

static void avflt_data_free(struct rfs_priv_data *rfs_data)
{
	struct avflt_data *data = rfs_to_avflt_data(rfs_data);

	kmem_cache_free(avflt_data_cache, data);
}

static struct avflt_data *avflt_data_alloc(void)
{
	struct avflt_data *data;
	int err;

	data = kmem_cache_alloc(avflt_data_cache, GFP_KERNEL);
	if (!data)
		return ERR_PTR(-ENOMEM);

	err = rfs_init_data(&data->rfs_data, avflt, avflt_data_free);
	if (err) {
		 kmem_cache_free(avflt_data_cache, data);
		 return ERR_PTR(err);
	}

	atomic_set(&data->state, 0);

	return data;
}

static inline struct avflt_data *avflt_get_data(struct inode *inode)
{
	struct rfs_priv_data *rfs_data;

	int err;

	err = rfs_get_data_inode(avflt, inode, &rfs_data);
	if (err)
		return ERR_PTR(err);

	return rfs_to_avflt_data(rfs_data);
}

static inline void avflt_put_data(struct avflt_data *data)
{
	rfs_put_data(&data->rfs_data);
}

static inline struct avflt_data *avflt_attach_data(struct inode *inode)
{
	struct avflt_data *data;
	struct rfs_priv_data *data_exist;
	int err;

	data = avflt_get_data(inode);
	if (!IS_ERR(data))
		return data;

	if (PTR_ERR(data) != -ENODATA)
		return data;

	data = avflt_data_alloc();
	if (IS_ERR(data)) 
		return data;

	err = rfs_attach_data_inode(avflt, inode, &data->rfs_data, &data_exist);
	if (err) {
		if (err == -EEXIST) {
			avflt_put_data(data);
			data = rfs_to_avflt_data(data_exist);

		} else {
			avflt_put_data(data);
			return ERR_PTR(err);
		}
	}

	return data;
}

static enum rfs_retv avflt_event(struct dentry *dentry, int event,
		struct rfs_args *args)
{
	struct avflt_check *check = NULL;
	struct avflt_data *data = NULL;
	int rv;
	int state;

	if (avflt_pid_find(current->tgid))
		return RFS_CONTINUE;

	if (atomic_read(&dentry->d_inode->i_writecount) <= 0) {
		data = avflt_get_data(dentry->d_inode);
		if (!IS_ERR(data)) {
			state = atomic_read(&data->state);

			if (state == AVFLT_CLEAN) {
				avflt_put_data(data);
				return RFS_CONTINUE;

			} else if (state == AVFLT_INFECTED) {
				avflt_put_data(data);
				args->retv.rv_int = -EPERM;
				return RFS_STOP;
			}

			avflt_put_data(data);
		}
	}

	rv = avflt_request_wait();

	if (rv < 0) {
		args->retv.rv_int = rv;
		return RFS_STOP;
	}

	if (rv == 1) {
		args->retv.rv_int = 0;
		return RFS_CONTINUE;
	}

	check = avflt_check_alloc();
	if (IS_ERR(check)) {
		avflt_request_put();
		args->retv.rv_int = rv;
		return RFS_STOP;
	}

	rv = rfs_get_filename(dentry, check->fn, check->fn_size);
	if (rv) {
		args->retv.rv_int = rv;
		avflt_request_put();
		avflt_check_put(check);
		return RFS_STOP;
	}

	check->event = event;
	check->fn_len = strlen(check->fn);

	rv = avflt_request_queue(check);
	if (rv) {
		args->retv.rv_int = 0;
		avflt_request_put();
		avflt_check_put(check);
		return RFS_STOP;
	}

	rv = avflt_reply_wait(check);
	if (rv) {
		args->retv.rv_int = rv;
		avflt_check_put(check);
		return RFS_STOP;
	}
	
	data = avflt_attach_data(dentry->d_inode);
	if (IS_ERR(data)) {
		printk(KERN_WARNING "avflt_attach_data failed(%ld)\n",
				PTR_ERR(data));
		data = NULL;
	}

	if (atomic_read(&check->deny)) {
		args->retv.rv_int = -EPERM;
		state = AVFLT_INFECTED;
		rv = RFS_STOP;

	} else {
		args->retv.rv_int = 0;
		state = AVFLT_CLEAN;
		rv = RFS_CONTINUE;
	}

	if (data) {
		atomic_set(&data->state, state);
		avflt_put_data(data);
	}

	avflt_check_put(check);

	return rv;
}

static enum rfs_retv avflt_pre_open(rfs_context context, struct rfs_args *args)
{
	struct dentry *dentry = args->args.f_open.file->f_dentry;
	
	return avflt_event(dentry, AV_EVENT_OPEN, args);
}

static enum rfs_retv avflt_pre_release(rfs_context context, struct rfs_args *args)
{
	struct dentry *dentry = args->args.f_release.file->f_dentry;
	
	return avflt_event(dentry, AV_EVENT_CLOSE, args);
}


static enum rfs_retv avflt_pre_permission(rfs_context context,
		struct rfs_args *args)
{
	struct dentry *dentry;

	if (!args->args.i_permission.nd)
		return RFS_CONTINUE;

	if (!(args->args.i_permission.mask & MAY_EXEC))
		return RFS_CONTINUE;

	dentry = args->args.i_permission.nd->dentry;

	return avflt_event(dentry, AV_EVENT_EXEC, args);
}

static int avflt_ctl(struct rfs_ctl *ctl)
{
	int err = 0;

	switch (ctl->id) {
		case RFS_CTL_ACTIVATE:
			err = rfs_activate_filter(avflt);
			break;

		case RFS_CTL_DEACTIVATE:
			err = rfs_deactivate_filter(avflt);
			break;

		case RFS_CTL_SETPATH:
			err = rfs_set_path(avflt, &ctl->data.path_info); 
			break;
	}

	return err;
}

int avflt_rfs_set_ops(void)
{
	if (avflt_open) 
		avflt_rops[AVFLT_REG_FOP_OPEN].pre_cb = avflt_pre_open;
	else
		avflt_rops[AVFLT_REG_FOP_OPEN].pre_cb = NULL;

	if (avflt_exec) 
		avflt_rops[AVFLT_REG_IOP_PERMISSION].pre_cb = avflt_pre_permission;
	else
		avflt_rops[AVFLT_REG_IOP_PERMISSION].pre_cb = NULL;

	if (avflt_close) 
		avflt_rops[AVFLT_REG_FOP_RELEASE].pre_cb = avflt_pre_release;
	else
		avflt_rops[AVFLT_REG_FOP_RELEASE].pre_cb = NULL;

	return rfs_set_operations(avflt, avflt_rops);
}

static int avflt_rfs_data_cache_init(void)
{
	avflt_data_cache = kmem_cache_create("avflt_data_cache",
			sizeof(struct avflt_data),
			0, SLAB_RECLAIM_ACCOUNT,
			NULL, NULL);

	if (!avflt_data_cache)
		return -ENOMEM;

	return 0;
}

static void avflt_rfs_data_cache_exit(void)
{
	kmem_cache_destroy(avflt_data_cache);
}

int avflt_rfs_init(void)
{
	int err;

	err = avflt_rfs_data_cache_init();
	if (err)
		return err;

	err = rfs_register_filter(&avflt, &avflt_info);
	if (err) {
		avflt_rfs_data_cache_exit();
		return err;
	}

	spin_lock(&avflt_rops_lock);
	err = avflt_rfs_set_ops();
	spin_unlock(&avflt_rops_lock);
	if (err)
		goto error;

	err = rfs_activate_filter(avflt);
	if (err)
		goto error;

	return 0;

error:
	rfs_unregister_filter(avflt);
	avflt_rfs_data_cache_exit();

	return err;
}

void avflt_rfs_exit(void)
{
	int err;

	err = rfs_unregister_filter(avflt);
	if (err)
		printk(KERN_ERR "avflt: rfs_unregister_filter failed(%d)\n", err);

	avflt_rfs_data_cache_exit();
}


