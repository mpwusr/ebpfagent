// trace_exec.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct exec_event {
    u32 pid;
    char comm[256];
};

BPF_PERF_OUTPUT(events);

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct exec_event event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    event.pid = pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
