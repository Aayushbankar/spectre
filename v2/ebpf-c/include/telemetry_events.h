// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __TELEMETRY_EVENTS_H
#define __TELEMETRY_EVENTS_H

#include <linux/types.h>

#define TASK_COMM_LEN 16

enum event_type {
    EVENT_TYPE_UNSPEC       = 0,
    EVENT_TYPE_FORK         = 1,
    EVENT_TYPE_EXEC         = 2,
    EVENT_TYPE_EXIT         = 3,
    EVENT_TYPE_FILE_OPEN    = 4,
    EVENT_TYPE_NET_CONNECT  = 5,
};

struct telemetry_header {
    __u32 type;
    __u32 payload_len;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    char  comm[TASK_COMM_LEN];
};

struct fork_event {
    __u32 child_pid;
    __u32 child_tgid;
};

struct exec_event {
    __u32 args_count;
    __u32 args_len;
};

struct exit_event {
    __u32 exit_code;
    __u32 signal_code;
    __u64 duration_ns;
};

struct file_open_event {
    __s32 ret_fd;
    __u32 flags;
    __u32 mode;
    __u32 path_len;
};

struct net_connect_event {
    __s32  ret;
    __u16  family;
    __be16 port;
    __u8   addr[16];
};

#endif
