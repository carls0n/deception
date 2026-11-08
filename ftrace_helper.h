#ifndef FTRACE_HELPER_H
#define FTRACE_HELPER_H

#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/kprobes.h>
#include <linux/version.h>

#define HOOK(_name, _hook, _orig)   \
{                                   \
    .name = (_name),                \
    .function = (_hook),            \
    .original = (_orig),            \
}

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
};

static struct ftrace_hook *fh_registered_hooks;
static size_t fh_registered_count;
static unsigned long (*fh_lookup_fn)(const char *name);

static struct ftrace_ops fh_global_ops = {
    .flags = FTRACE_OPS_FL_SAVE_REGS
           | FTRACE_OPS_FL_RECURSION
           | FTRACE_OPS_FL_IPMODIFY,
};

static inline int fh_init_lookup(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret;

    if (fh_lookup_fn)
        return 0;

    ret = register_kprobe(&kp);
    if (ret < 0)
        return ret;

    fh_lookup_fn = (unsigned long (*)(const char *))kp.addr;
    unregister_kprobe(&kp);

    return fh_lookup_fn ? 0 : -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
static inline void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                           struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    size_t i;

    if (!regs || within_module(parent_ip, THIS_MODULE))
        return;

    for (i = 0; i < fh_registered_count; i++) {
        unsigned long start = fh_registered_hooks[i].address;
        if (ip >= start && ip <= start + 16) {
            regs->ip = (unsigned long)fh_registered_hooks[i].function;
            break;
        }
    }
}
#else
static inline void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                           struct ftrace_ops *ops, struct pt_regs *regs)
{
    size_t i;

    if (!regs || within_module(parent_ip, THIS_MODULE))
        return;

    for (i = 0; i < fh_registered_count; i++) {
        unsigned long start = fh_registered_hooks[i].address;
        if (ip >= start && ip <= start + 16) {
            regs->ip = (unsigned long)fh_registered_hooks[i].function;
            break;
        }
    }
}
#endif

static inline int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    typedef unsigned long (*ftrace_location_t)(unsigned long ip);
    ftrace_location_t ftrace_location_fn;
    size_t i;
    int err;

    err = fh_init_lookup();
    if (err)
        return err;

    ftrace_location_fn = (ftrace_location_t)fh_lookup_fn("ftrace_location");
    fh_global_ops.func = (ftrace_func_t)fh_ftrace_thunk;
    fh_registered_hooks = hooks;
    fh_registered_count = count;

    for (i = 0; i < count; i++) {
        unsigned long sym_addr = fh_lookup_fn(hooks[i].name);
        unsigned long fentry_addr = 0;

        if (!sym_addr) {
            err = -ENOENT;
            goto err_rollback;
        }

        if (ftrace_location_fn)
            fentry_addr = ftrace_location_fn(sym_addr);
        if (!fentry_addr)
            fentry_addr = sym_addr;

        hooks[i].address = sym_addr;
        *((unsigned long *)hooks[i].original) = fentry_addr + MCOUNT_INSN_SIZE;

        err = ftrace_set_filter_ip(&fh_global_ops, fentry_addr, 0, 0);
        if (err)
            goto err_rollback;
    }

    err = register_ftrace_function(&fh_global_ops);
    if (err)
        goto err_rollback;

    return 0;

err_rollback:
    while (i > 0) {
        i--;
        ftrace_set_filter_ip(&fh_global_ops, hooks[i].address, 1, 0);
    }
    return err;
}

static inline void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    typedef unsigned long (*ftrace_location_t)(unsigned long ip);
    ftrace_location_t ftrace_location_fn = (ftrace_location_t)fh_lookup_fn("ftrace_location");
    size_t i;

    unregister_ftrace_function(&fh_global_ops);

    for (i = 0; i < count; i++) {
        unsigned long fentry_addr = ftrace_location_fn ? ftrace_location_fn(hooks[i].address) : 0;
        if (!fentry_addr)
            fentry_addr = hooks[i].address;
        ftrace_set_filter_ip(&fh_global_ops, fentry_addr, 1, 0);
    }
}

#endif /* FTRACE_HELPER_H */

