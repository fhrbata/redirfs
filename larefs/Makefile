SUBDIR=	sys/modules/larefs \
	sys/modules/dummyflt \
	sbin/larefs

# Should be built from sources tree
# SUBDIR+= lib/libpam/modules/pam_pefs

load:
	kldload sys/modules/larefs/larefs.ko
	kldload sys/modules/dummyflt/dummyflt.ko

unload:
	kldunload dummyflt
	kldunload larefs

mount:
	mount -t larefs ./sys ./test
	mount -t larefs ./sbin ./test1

umount:
	umount ./test
	umount ./test1

start:
	make 
	make load
	make mount

stop:
	make umount
	make unload

	

.include <bsd.subdir.mk>
