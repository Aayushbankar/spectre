#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Struct for the event we will send to userspace
struct process_event {
    __u32 pid;
    char comm[16];
};

// Define a ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// We hook the sched_process_exec tracepoint
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx) {
    struct process_event *event;

    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    // Populate event
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Submit to userspace
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
