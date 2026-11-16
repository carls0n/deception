#ifndef FTRACE_HELPER_H
#define FTRACE_HELPER_H

#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/rcupdate.h>

static atomic_t active_hooks = ATOMIC_INIT(0);

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
    struct ftrace_ops ops;
};

static unsigned long (*fh_lookup_fn)(const char *name);

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
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!regs || within_module(parent_ip, THIS_MODULE))
        return;

    regs->ip = (unsigned long)hook->function;
}
#else
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!regs || within_module(parent_ip, THIS_MODULE))
        return;

    regs->ip = (unsigned long)hook->function;
}
#endif

static inline int fh_install_hook(struct ftrace_hook *hook)
{
    typedef unsigned long (*ftrace_location_t)(unsigned long ip);
    static ftrace_location_t ftrace_location_fn;
    unsigned long sym_addr, fentry_addr = 0;
    int err;

    err = fh_init_lookup();
    if (err)
        return err;

    if (!ftrace_location_fn)
        ftrace_location_fn = (ftrace_location_t)fh_lookup_fn("ftrace_location");

    sym_addr = fh_lookup_fn(hook->name);
    if (!sym_addr)
        return -ENOENT;

    if (ftrace_location_fn)
        fentry_addr = ftrace_location_fn(sym_addr);
    if (!fentry_addr)
        fentry_addr = sym_addr;

    hook->address = fentry_addr;
    *((unsigned long *)hook->original) = fentry_addr + MCOUNT_INSN_SIZE;

    hook->ops.func = (ftrace_func_t)fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION
                    | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err)
        return err;

    err = register_ftrace_function(&hook->ops);
    if (err) {
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        hook->address = 0;
        return err;
    }

    return 0;
}

static inline void fh_remove_hook(struct ftrace_hook *hook)
{
    if (!hook->address)
        return;

    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    hook->address = 0;
}

static inline int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;
    int err;

    for (i = 0; i < count; i++) {
        err = fh_install_hook(&hooks[i]);
        if (err) {
            while (i > 0)
                fh_remove_hook(&hooks[--i]);
            return err;
        }
    }
    return 0;
}

static inline void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
        fh_remove_hook(&hooks[i]);

    while (atomic_read(&active_hooks) > 0)
        msleep(20);

#ifdef CONFIG_TASKS_RCU
    synchronize_rcu_tasks();
#endif
    synchronize_rcu();
    msleep(50);
}

#endif /* FTRACE_HELPER_H */
