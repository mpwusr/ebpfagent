// trace_exec.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct exec_event {
    u32 pid;
    char comm[256];
};

void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct exec_event *event = data;
    printf("PID: %u, Command: %s\n", event->pid, event->comm);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

int main() {
    struct bpf_object *obj;
    int prog_fd, map_fd;
    struct perf_buffer *pb = NULL;

    // Load BPF program
    obj = bpf_object__open_file("trace_exec.bpf.o", NULL);
    if (!obj) {
        perror("Failed to open BPF object");
        return 1;
    }

    if (bpf_object__load(obj)) {
        perror("Failed to load BPF object");
        return 1;
    }

    // Get program FD
    prog_fd = bpf_program__fd(bpf_object__find_program_by_title(obj, "tracepoint/syscalls/sys_enter_execve"));
    if (prog_fd < 0) {
        perror("Failed to get program FD");
        return 1;
    }

    // Attach program
    if (bpf_prog_attach(prog_fd, 0, BPF_TRACE_FENTRY, 0)) {
        perror("Failed to attach BPF program");
        return 1;
    }

    // Get events map FD
    map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "events"));
    if (map_fd < 0) {
        perror("Failed to get map FD");
        return 1;
    }

    // Set up perf buffer
    pb = perf_buffer__new(map_fd, 8, handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        perror("Failed to create perf buffer");
        return 1;
    }

    printf("Monitoring process executions... Press Ctrl+C to exit.\n");

    // Poll events
    while (1) {
        perf_buffer__poll(pb, -1);
    }

    perf_buffer__free(pb);
    return 0;
}
