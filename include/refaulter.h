#ifndef REFAULTER_H
#define REFAULTER_H

#include <linux/ioctl.h>

/*
 * page-align は要求しない
 * addr_end は呼び元的には addr_begin + size
 * addr_begin を align_down した addr から初めて
 * addr+=PAGE_SIZE で進めていき、 addr>=addr_end で終わり
 */
struct ioctl_data {
    unsigned long addr_begin; // inclusive
    unsigned long addr_end; // exclusive
};

#define REFAULTER_IOCTL_MAGIC 'h'
#define REFAULTER_IOCTL_RO_PAGES _IOR(REFAULTER_IOCTL_MAGIC, 1, struct ioctl_data)

#endif
