#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "filetracking.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, char[MAX_FILENAME_LEN]);
} inode_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, char[MAX_FILENAME_LEN]);
} data_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

#define MAJOR(dev)	((dev)>>20)
#define MINOR(dev)	((dev) & ((1U << 20) - 1))

SEC("tracepoint/block/block_dirty_buffer")
int trace_block_dirty_buffer(struct trace_event_raw_block_buffer *ctx) {
    struct event *e;
    u32 dev = BPF_CORE_READ(ctx, dev);
    u64 sector = BPF_CORE_READ(ctx, sector);
    u32 size = BPF_CORE_READ(ctx, size);
    char * filename;

    filename = bpf_map_lookup_elem(&data_map, &sector);
    if (filename == NULL) {
        return 0;
    } 
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), filename);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->data_index = sector;
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/block/block_rq_insert")
int trace_block_rq_insert(struct trace_event_raw_block_rq *ctx) {
    struct event *e;
    u32 dev = BPF_CORE_READ(ctx, dev);
    u64 sector = BPF_CORE_READ(ctx, sector);
    char * rwbs = ctx->rwbs;
    char comm[16];
    char * filename;
    u64 data_index;

    if (rwbs[0] != 'W')
        return 0;
    bpf_get_current_comm(&comm, sizeof(comm));
    int is_kthread = (comm[0] == 'k' &&
        comm[1] == 'w' && comm[2] == 'o' && comm[3] == 'r' &&
        comm[4] == 'k' && comm[5] == 'e' && comm[6] == 'r');
    if (is_kthread)
		return 0;

    // Only diect-IO write operation should reach here.
    // data_index * 4096 = sector * 512
    data_index = sector / 8;
    filename = bpf_map_lookup_elem(&data_map, &data_index);
    if (filename == NULL) {
        return 0;
    } 
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), filename);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->data_index = data_index;
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/ext4/ext4_unlink_enter")
int trace_ext4_rm(struct trace_event_raw_ext4_unlink_enter *ctx) {
    struct event *e;
    u64 ino = BPF_CORE_READ(ctx, ino);
    char * filename;
    filename = bpf_map_lookup_elem(&inode_map, &ino);
    if (filename == NULL) {
        return 0;
    }
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), filename);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->inode_index = ino;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

