#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/kallsyms.h>
#include "../include/refaulter.h"

#define DEVICE_NAME "refaulter"

static int major;

static int refaulter_open(struct inode *inode, struct file *filp) {
    return 0;
}

static int refaulter_release(struct inode *inode, struct file *filp) {
    return 0;
}

static long refaulter_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct pte_protect_range range;
    unsigned long addr, end;

    if (cmd != REFAULTER_IOCTL_DISABLE_WRITE)
        return -EINVAL;

    if (copy_from_user(&range, (void __user *)arg, sizeof(range)))
        return -EFAULT;

    addr = range.start & PAGE_MASK;
    end  = PAGE_ALIGN(range.start + range.len);

    pr_info("PTE_PROTECT: Disabling write from 0x%lx to 0x%lx\n", addr, end);

    down_read(&current->mm->mmap_lock);
    for (; addr < end; addr += PAGE_SIZE) {
        pte_t *pte;
        spinlock_t *ptl;
        struct mm_struct *mm = current->mm;

        pte = get_locked_pte(mm, addr, &ptl);
        if (!pte) continue;

        if (pte_write(*pte)) {
            *pte = pte_wrprotect(*pte);
            flush_tlb_mm_range(current->mm, addr, addr + PAGE_SIZE, PAGE_SHIFT, false);
        }

        pte_unmap_unlock(pte, ptl);
    }
    /* 別案
    for (; addr < end; addr += PAGE_SIZE) {
        pgd_t *pgd = pgd_offset(current->mm, addr);
        if (pgd_none(*pgd) || pgd_bad(*pgd)) continue;

        p4d_t *p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d)) continue;

        pud_t *pud = pud_offset(p4d, addr);
        if (pud_none(*pud) || pud_bad(*pud)) continue;

        pmd_t *pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd)) continue;

        pte_t *pte;
        spinlock_t *ptl;
        pte = pte_offset_map_lock(current->mm, pmd, addr, &ptl);
        if (!pte) continue;

        if (pte_present(*pte)) {
            if (pte_write(*pte)) {
                pte_t newpte = pte_wrprotect(*pte);
                set_pte_at(current->mm, addr, pte, newpte);
                flush_tlb_mm_range(current->mm, addr, addr + PAGE_SIZE, PAGE_SHIFT, false);
                pr_info("PTE_PROTECT: Cleared _PAGE_RW at 0x%lx\n", addr);
            }
        }
        pte_unmap_unlock(pte, ptl);
    }
    */
    up_read(&current->mm->mmap_lock);

    return 0;
}

static const struct file_operations refaulter_fops = {
    .owner          = THIS_MODULE,
    .open           = refaulter_open,
    .release        = refaulter_release,
    .unlocked_ioctl = refaulter_ioctl,
};

static int __init refaulter_init(void)
{
    major = register_chrdev(0, DEVICE_NAME, &refaulter_fops);
    if (major < 0) {
        pr_err("refaulter: failed to register char device\n");
        return major;
    }

    pr_info("refaulter: module loaded, device major=%d\n", major);
    return 0;
}

static void __exit refaulter_exit(void)
{
    unregister_chrdev(major, DEVICE_NAME);
    pr_info("refaulter: module unloaded\n");
}

module_init(refaulter_init);
module_exit(refaulter_exit);

MODULE_LICENSE("GPL");
