#ifndef REFAULTER_H
#define REFAULTER_H

#include <linux/ioctl.h>

struct pte_protect_range {
    unsigned long start;
    unsigned long len;
};

#define REFAULTER_MAGIC 0xAA
#define REFAULTER_IOCTL_DISABLE_WRITE _IOW(REFAULTER_MAGIC, 1, struct pte_protect_range)

#endif
