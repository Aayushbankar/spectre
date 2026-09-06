// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN   16
#define MAX_ARGS        16
#define ARG_MAX_LEN     128
#define ARGS_BUF_SIZE   2048
#define LAST_ARG_OFFSET (ARGS_BUF_SIZE - ARG_MAX_LEN)

struct trace_entry {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long int id;
    unsigned long int args[6];
};

struct execve_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 args_count;
    __u32 args_size;
    char  comm[TASK_COMM_LEN];
    char  args_data[ARGS_BUF_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    const char *const *argv = (const char *const *)ctx->args[1];
    if (!argv)
        return 0;

    struct execve_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    event->pid = (__u32)(id >> 32);
    event->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Default PPID fallback
    event->ppid = 1;

    unsigned int args_off = 0;
    event->args_count = 0;

    #pragma clang loop unroll(full)
    for (int i = 0; i < MAX_ARGS; i++) {
        if (args_off > LAST_ARG_OFFSET)
            break;

        const char *argp = 0;
        long ret = bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (ret < 0 || !argp)
            break;

        ret = bpf_probe_read_user_str(&event->args_data[args_off], ARG_MAX_LEN, argp);
        if (ret <= 0)
            break;

        args_off += (ret & (ARG_MAX_LEN - 1));
        event->args_count++;
    }

    event->args_size = args_off;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
