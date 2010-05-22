#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <fs/larefs/larefs.h>

int pre_filter_operation(void *data, struct vop_generic_args *ap);
int post_filter_operation(void *data, struct vop_generic_args *ap);

struct larefs_vop_vector dummyflt_vnodeops[] = {
	{LAREFS_OPEN, pre_filter_operation, post_filter_operation},
	{LAREFS_LOOKUP, pre_filter_operation, post_filter_operation},
	{LAREFS_BOTTOM, NULL, NULL}
};

static struct larefs_filter_t filter_conf = {
	"Dummyflt",
	dummyflt_vnodeops	
};

int
pre_filter_operation(void *data, struct vop_generic_args *ap)
{
	struct vnodeop_desc *descp = ap->a_desc;

	uprintf("Pre operation %s : %s\n", filter_conf.name, descp->vdesc_name);

	return (0);
}

int
post_filter_operation(void *data, struct vop_generic_args *ap)
{
	struct vnodeop_desc *descp = ap->a_desc;

	uprintf("Post operation %s : %s\n", filter_conf.name, descp->vdesc_name);

	return (0);
}

static int event_handler(struct module *module, int event, void *arg) {
        int err = 0;
        switch (event) {
        case MOD_LOAD:
                uprintf("Hello dummyflt is here! \n");
		err = larefs_register_filter(&filter_conf);
		uprintf("filter registration : %d\n",err);
                break;
        case MOD_UNLOAD:
                uprintf("Dummyflt is leaving\n");
		err = larefs_unregister_filter(&filter_conf);
                break;
        default:
                err = EOPNOTSUPP;
                break;
        }

        return(err);
}

static moduledata_t dummyflt_conf = {
    "hello_fsm",
     event_handler,
     NULL
};

DECLARE_MODULE(dummyflt, dummyflt_conf, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_DEPEND(dummyflt, larefs, 1, 1, 1);
