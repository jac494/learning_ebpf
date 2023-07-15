#!/usr/bin/env python3

from bcc import BPF, ct

# Good reference here for syscalls by opcode
# https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
IGNORE_SYSCALLS_MAP = {
    0: "read",
    1: "write",
    4: "stat",
    14: "rt_sigprocmask",
    16: "ioctl",
    21: "access",
    22: "pipe",
    25: "mremap",
    28: "madvise",
    47: "recvmsg",
    89: "readlink",
    102: "getuid",
    202: "futex",
    232: "epoll_wait",
    254: "inotify_add_watch",
    262: "newfstatat",
    270: "pselect6",
    318: "getrandom",
}

program = r"""BPF_PROG_ARRAY(syscall, 350);

int hello(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];
    syscall.call(ctx, opcode);
    bpf_trace_printk("Another syscall: %d", opcode);
    return 0;
}

int hello_execve(void *ctx) {
    bpf_trace_printk("Executing a program");
    return 0;
}

int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    if (ctx->args[1] == 222) {
    bpf_trace_printk("Creating a timer");
    } else if (ctx->args[1] == 226) {
        bpf_trace_printk("Deleting a timer");
    } else {
        bpf_trace_printk("Some other timer operation");
    }
    return 0;
}

int ignore_opcode(void *ctx) {
    return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_execve", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

prog_array = b.get_table("syscall")
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)

# Ignore some syscalls that come up a lot
for ignore_call_opcode in IGNORE_SYSCALLS_MAP.keys():
    prog_array[ct.c_int(ignore_call_opcode)] = ct.c_int(ignore_fn.fd)

b.trace_print()
