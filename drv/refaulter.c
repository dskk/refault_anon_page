// refaulter.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/device.h>   // <-- NEW: for device_create, class_create
#include <linux/cdev.h>     // <-- NEW: for cdev_init, cdev_add
#include "../include/refaulter.h"
#include "../include/page_wrprotect_modify.h"

MODULE_LICENSE("GPL");
//MODULE_AUTHOR("Your Name");
//MODULE_DESCRIPTION("Kernel module to hook a specific address with ioctl support.");

#define JMP_OPCODE (0xE9)
#define NOP_OPCODE (0x90)
#define JMP_INST_LEN (5)

#define DEVICE_NAME "refaulter"

// -------------------------------------------------------------------
typedef void (*text_poke_funcptr_t)(void *addr, const void *opcode, size_t len);
text_poke_funcptr_t text_poke_funcptr = NULL;

// -------------------------------------------------------------------
// モジュールパラメータの定義 (変更なし)
static unsigned long target_hook_address = 0;
module_param(target_hook_address, ulong, 0644);
MODULE_PARM_DESC(target_hook_address, "Virtual address to hook");

static unsigned long text_poke_address = 0;
module_param(text_poke_address, ulong, 0644);
MODULE_PARM_DESC(text_poke_address, "Virtual address of text_poke");

static unsigned char overwrite_len = 0;
module_param(overwrite_len, byte, 0644);
MODULE_PARM_DESC(overwrite_len, "Kernel func patch length");

//static void* trampoline;
static unsigned char __attribute__((section(".text"))) trampoline[255];
static unsigned char orig_bytes[255];
static unsigned char overwrite_bytes[255];

// -------------------------------------------------------------------

static dev_t dev_num;         // <-- NEW: Dynamically allocated major/minor number
static struct class *dev_class; // <-- NEW: Device class for sysfs
static struct cdev cdev_instance; // <-- NEW: cdev structure for character device

// -------------------------------------------------------------------
// handle_pte_fault の代替処理

static vm_fault_t __noreturn my_handle_pte_fault(struct vm_fault *vmf)
{
    pr_info("refaulter: Hooked handle_pte_fault for addr=0x%lx\n", vmf->address);
    asm volatile("jmp *%0" :: "r"(trampoline));
    unreachable();
}

    /*
    typedef vm_fault_t (*orig_fn_t)(struct vm_fault *);
    orig_fn_t orig = (orig_fn_t)((unsigned long)target_func_addr + sizeof(orig_bytes));
    return orig(vmf);
    */


// -------------------------------------------------------------------
// デバイスファイルの操作関数
static int refaulter_open(struct inode *inode, struct file *file)
{
    pr_info("refaulter: Device opened.\n");
    // 必要ならここで何か初期化処理
    return 0; // 成功
}

static int refaulter_release(struct inode *inode, struct file *file)
{
    pr_info("refaulter: Device closed.\n");
    // 必要ならここで何かクリーンアップ処理
    return 0; // 成功
}

static long refaulter_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    /*
    int ret = 0;
    int user_val;

    switch (cmd) {
        case HOOK_IOC_GET_STATUS:
            // ユーザー空間にフックの有効/無効状態を返す
            ret = copy_to_user((int __user *)arg, &hook_enabled, sizeof(hook_enabled));
            if (ret != 0) {
                pr_err("refaulter: Failed to copy status to user space.\n");
                return -EFAULT;
            }
            pr_info("refaulter: Get status (enabled: %d).\n", hook_enabled);
            break;

        case HOOK_IOC_TOGGLE_ENABLE:
            // ユーザー空間から値を受け取り、フックの有効/無効を切り替える
            ret = copy_from_user(&user_val, (int __user *)arg, sizeof(user_val));
            if (ret != 0) {
                pr_err("refaulter: Failed to copy value from user space.\n");
                return -EFAULT;
            }
            hook_enabled = (user_val != 0); // 0以外なら有効
            pr_info("refaulter: Toggle enable to %d.\n", hook_enabled);

            // ここで kprobe を有効/無効にする処理などを呼び出す
            // 例: kprobe が登録済みであれば、unregister_kprobe / register_kprobe を呼び出す
            // または、handler_pre 内で hook_enabled フラグをチェックする
            break;

        default:
            pr_err("refaulter: Unknown ioctl command 0x%x\n", cmd);
            return -ENOTTY; // 不正な ioctl コマンド
    }
    */
    return 0;
}

// -------------------------------------------------------------------
// file_operations 構造体 (変更なし)
static const struct file_operations refaulter_fops = {
    .owner          = THIS_MODULE,
    .open           = refaulter_open,
    .release        = refaulter_release,
    .unlocked_ioctl = refaulter_ioctl,
};

// -------------------------------------------------------------------
// モジュールの初期化関数 (ロード時)
static int __init refaulter_init(void)
{
    int ret;
    pr_info("refaulter loading...\n");

    if (target_hook_address == 0) {
        pr_err("Error: target_hook_address not provided or is zero. Aborting.\n");
        return -EINVAL;
    }

    if (text_poke_address == 0) {
        pr_err("Error: text_poke_address not provided or is zero. Aborting.\n");
        return -EINVAL;
    }

    if (overwrite_len == 0) {
        pr_err("Error: overwrite_len not provided or is zero. Aborting.\n");
        return -EINVAL;
    }

    text_poke_funcptr = (text_poke_funcptr_t)text_poke_address;

    // NEW: 動的にメジャー/マイナー番号を割り当てる
    ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("Failed to allocate chrdev_region\n");
        return ret;
    }
    pr_info("Allocated device number %d:%d\n", MAJOR(dev_num), MINOR(dev_num));

    // NEW: cdev 構造体を初期化し、file_operations を関連付ける
    cdev_init(&cdev_instance, &refaulter_fops);
    cdev_instance.owner = THIS_MODULE;

    // NEW: カーネルに cdev を追加
    ret = cdev_add(&cdev_instance, dev_num, 1);
    if (ret < 0) {
        pr_err("Failed to add cdev\n");
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    // NEW: デバイスクラスを作成 (これが /sys/class/refaulter を作る)
    dev_class = class_create(DEVICE_NAME);
    if (IS_ERR(dev_class)) {
        pr_err("Failed to create device class\n");
        cdev_del(&cdev_instance);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(dev_class);
    }
    pr_info("Device class /sys/class/%s created\n", DEVICE_NAME);

    // NEW: デバイスを作成 (これが /dev/refaulter ノードを作る)
    if (IS_ERR(device_create(dev_class, NULL, dev_num, NULL, DEVICE_NAME))) {
        pr_err("Failed to create device\n");
        class_destroy(dev_class);
        cdev_del(&cdev_instance);
        unregister_chrdev_region(dev_num, 1);
        return -1; // エラーコードを適切に返す
    }
    pr_info("Device node /dev/%s created automatically\n", DEVICE_NAME);

    // install hook
    pr_info("kernel func hook installing... (addr=0x%lx, len=%u)\n", target_hook_address, overwrite_len);

    /*
    trampoline = __vmalloc_node_range(
        256,                        // size
        1,                          // align
        VMALLOC_START,
        VMALLOC_END,
        GFP_KERNEL,
        PAGE_KERNEL_EXEC,           // trampoline is an executable memory
        0,                          // vm_flags
        NUMA_NO_NODE,               // NUMA node
        __builtin_return_address(0)
    );
    if (!trampoline) {
        pr_err("Failed to allocate trampoline\n");
        return -ENOMEM;
    }
    */
    unsigned char* target_ptr = (unsigned char*)target_hook_address;
    int32_t jmp_offset;

    memcpy(orig_bytes, target_ptr, overwrite_len);
    pr_info("target: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", orig_bytes[0], orig_bytes[1], orig_bytes[2], orig_bytes[3], orig_bytes[4], orig_bytes[5], orig_bytes[6], orig_bytes[7], orig_bytes[8], orig_bytes[9], orig_bytes[10], orig_bytes[11], orig_bytes[12], orig_bytes[13], orig_bytes[14], orig_bytes[15]);

    text_poke_funcptr(trampoline, orig_bytes, overwrite_len);
    trampoline[overwrite_len] = JMP_OPCODE;
    jmp_offset = (int32_t)(((int64_t)target_ptr + JMP_INST_LEN) - ((int64_t)&trampoline[overwrite_len] + JMP_INST_LEN));
    text_poke_funcptr(&trampoline[overwrite_len + 1], &jmp_offset, sizeof(jmp_offset));

    overwrite_bytes[0] = JMP_OPCODE;
    jmp_offset = (int32_t)((int64_t)my_handle_pte_fault - ((int64_t)target_ptr + JMP_INST_LEN));
    memcpy(&overwrite_bytes[1], &jmp_offset, sizeof(jmp_offset));
    memset(&overwrite_bytes[JMP_INST_LEN], NOP_OPCODE, overwrite_len - JMP_INST_LEN);
    //make_kernel_text_page_rw((void*)target_ptr);
    text_poke_funcptr(target_ptr, overwrite_bytes, overwrite_len);
    pr_info("target: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", orig_bytes[0], orig_bytes[1], orig_bytes[2], orig_bytes[3], orig_bytes[4], orig_bytes[5], orig_bytes[6], orig_bytes[7], orig_bytes[8], orig_bytes[9], orig_bytes[10], orig_bytes[11], orig_bytes[12], orig_bytes[13], orig_bytes[14], orig_bytes[15]);
    //clflush_cache_range(target_ptr, overwrite_len);
    //make_kernel_text_page_ro((void*)target_ptr);

    pr_info("kernel func hook installed. (addr=0x%lx, len=%u)\n", target_hook_address, overwrite_len);

    return 0;
}

// モジュールの終了関数 (アンロード時)
static void __exit refaulter_exit(void)
{
    // uninstall hook
    pr_info("kernel func hook uninstalling... (addr=0x%lx, len=%u)\n", target_hook_address, overwrite_len);

    unsigned char* target_ptr = (unsigned char*)target_hook_address;
    text_poke_funcptr(target_ptr, orig_bytes, overwrite_len);

    /*
    make_kernel_text_page_rw((void*)target_ptr);
    memcpy(target_ptr, orig_bytes, overwrite_len);
    clflush_cache_range(target_ptr, overwrite_len);
    make_kernel_text_page_ro((void*)target_ptr);
    */

    pr_info("kernel func hook uninstalled. (addr=0x%lx, len=%u)\n", target_hook_address, overwrite_len);

    pr_info("refaulter unloading...\n");

    // NEW: 自動作成したデバイスノードとクラスを削除
    device_destroy(dev_class, dev_num);
    class_destroy(dev_class);
    cdev_del(&cdev_instance);
    unregister_chrdev_region(dev_num, 1); // <-- OLD: now unregistering dynamic region

    pr_info("refaulter unloaded.\n");
}

module_init(refaulter_init);
module_exit(refaulter_exit);
