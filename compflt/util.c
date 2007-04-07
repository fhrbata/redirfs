#include <linux/kernel.h>

void hexdump(void *buf, unsigned int len)
{
        int i = 0;

        printk("\n");
        while (len--) {
                if (!(i % 16)) {
                        if (i) printk("\n");
                        printk("%07x ", i);
                }
                printk("%02x ", *(u8 *)buf++);
                i++;
        }
        printk("\n");
}
