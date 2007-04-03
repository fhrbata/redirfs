#include "redir.h"

struct chain *chain_alloc(int size)
{
	struct chain *chain;
	struct filter **flts;

	chain = kmalloc(sizeof(struct chain), GFP_KERNEL);
	flts = kmalloc(sizeof(struct filter*) * size, GFP_KERNEL);
	if (!chain || !flts) {
		kfree(chain);
		kfree(flts);
		return ERR_PTR(RFS_ERR_NOMEM);
	}

	chain->c_flts = flts;
	chain->c_flts_nr = size;
	chain->c_count = 1;
	spin_lock_init(&chain->c_lock);

	return chain;
}

struct chain *chain_get(struct chain *chain)
{
	unsigned long flags;

	if (!chain || IS_ERR(chain))
		return NULL;

	spin_lock_irqsave(&chain->c_lock, flags);
	BUG_ON(!chain->c_count);
	chain->c_count++;
	spin_unlock_irqrestore(&chain->c_lock, flags);

	return chain;
}

void chain_put(struct chain *chain)
{
	unsigned long flags;

	int i;
	int del = 0;

	if (!chain || IS_ERR(chain))
		return;

	spin_lock_irqsave(&chain->c_lock, flags);
	BUG_ON(!chain->c_count);
	chain->c_count--;
	if (!chain->c_count)
		del = 1;
	spin_unlock_irqrestore(&chain->c_lock, flags);

	if (!del)
		return;

	for (i = 0; i < chain->c_flts_nr; i++)
		flt_put(chain->c_flts[i]);

	kfree(chain->c_flts);
	kfree(chain);
}

int chain_find_flt(struct chain *chain, struct filter *flt)
{
	int i;

	if (!chain)
		return -1;

	for (i = 0; i < chain->c_flts_nr; i++) {
		if (chain->c_flts[i] == flt)
			return i;
	}

	return -1;
}

struct chain *chain_add_flt(struct chain *chain, struct filter *flt)
{
	struct chain *chain_new;
	int size;
	int i = 0;
	int j = 0;

	if (!chain) 
		size = 1;
	else
		size = chain->c_flts_nr + 1;

	chain_new = chain_alloc(size);
	if (IS_ERR(chain_new))
		return chain_new;

	if (!chain) {
		chain_new->c_flts[0] = flt_get(flt);
		return chain_new;
	}

	while (chain->c_flts[i]->f_priority < flt->f_priority) {
		chain_new->c_flts[j++] = flt_get(chain->c_flts[i++]);
	}

	chain_new->c_flts[j++] = flt_get(flt);

	while (j < chain_new->c_flts_nr) {
		chain_new->c_flts[j++] = flt_get(chain->c_flts[i++]);
	}

	return chain_new;
}

struct chain *chain_rem_flt(struct chain *chain, struct filter *flt)
{
	struct chain *chain_new;
	int i, j;

	if (chain->c_flts_nr == 1)
		return NULL;

	chain_new = chain_alloc(chain->c_flts_nr - 1);
	if (IS_ERR(chain_new))
		return chain_new;

	for (i = 0, j = 0; i < chain->c_flts_nr; i++) {
		if (chain->c_flts[i] != flt)
			chain_new->c_flts[j++] = flt_get(chain->c_flts[i]);
	}

	return chain_new;
}

void chain_get_ops(struct chain *chain, char *ops)
{
	int i, j;

	for (i = 0; i < chain->c_flts_nr; i++) {
		for (j = 0; j < RFS_OP_END; j++) {
			if (chain->c_flts[i]->f_pre_cbs[j])
				ops[j]++;
			if (chain->c_flts[i]->f_post_cbs[j])
				ops[j]++;
		}
	}
}

struct chain *chain_copy(struct chain *src)
{
	struct chain *dst;
	int i;

	if (!src)
		return NULL;

	dst = chain_alloc(src->c_flts_nr);
	if (IS_ERR(dst))
		return dst;

	for (i = 0; i < src->c_flts_nr; i++)
		dst->c_flts[i] = src->c_flts[i];

	return dst;
}

int chain_cmp(struct chain *chain1, struct chain *chain2)
{
	int i;

	if (!chain1 && !chain2)
		return 0;

	if (!chain1 || !chain2)
		return -1;

	if (chain1->c_flts_nr != chain2->c_flts_nr)
		return -1;

	for (i = 0; i < chain1->c_flts_nr; i++) {
		if (chain1->c_flts[i] != chain2->c_flts[i])
			return -1;
	}

	return 0;
}

