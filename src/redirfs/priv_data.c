#include "redir.h"

int rfs_init_data(struct rfs_priv_data *data, rfs_filter filter, void (*cb)(struct rfs_priv_data *data))
{
	if (!data || !filter || !cb)
		return -EINVAL;

	INIT_LIST_HEAD(&data->list);
	atomic_set(&data->cnt, 1);
	data->cb = cb;
	data->flt = (rfs_filter *)flt_get((struct filter *)filter);

	return 0;
}

struct rfs_priv_data *rfs_get_data(struct rfs_priv_data *data)
{
	if (!data)
		return NULL;

	BUG_ON(!atomic_read(&data->cnt));

	atomic_inc(&data->cnt);

	return data;
}

void rfs_put_data(struct rfs_priv_data *data)
{
	struct filter *flt;

	if (!data || IS_ERR(data))
		return;

	BUG_ON(!atomic_read(&data->cnt));

	if (!atomic_dec_and_test(&data->cnt))
		return;

	flt = (struct filter *)data->flt;
	data->cb(data);
	flt_put(flt);
}

struct rfs_priv_data *rfs_find_data(struct list_head *head, struct filter *flt)
{
	struct rfs_priv_data *loop;
	struct rfs_priv_data *found;

	found = NULL;

	list_for_each_entry(loop, head, list) {
		if (loop->flt == flt) {
			found = loop;
			break;
		}
	}

	return found;
}

EXPORT_SYMBOL(rfs_init_data);
EXPORT_SYMBOL(rfs_get_data);
EXPORT_SYMBOL(rfs_put_data);

