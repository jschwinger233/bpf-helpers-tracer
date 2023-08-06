// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// force emitting struct into the ELF.
const struct event *_ __attribute__((unused));
const struct skbmeta *__ __attribute__((unused));

struct event {
	__u64 pc; // only used for kprobe
	__u8 type; // 0: fentry, 1: fexit; 2: kprobe
};

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 1<<29,
};

struct skbcache {
	bool matched;
};

struct bpf_map_def SEC("maps") skbcaches = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct skbcache),
	.max_entries = 100000,
};

struct skbmeta {
	__u8 header[256];
	__u32 len;
	__u32 mark;
};

struct bpf_map_def SEC("maps") skbmetas = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(struct skbmeta),
	.max_entries = 100000,
};

static __always_inline
bool pcap_filter(void *data, void* data_end)
{
	bpf_printk("%p %p\n", data, data_end);
	return data < data_end;
}

SEC("fentry/tc")
int BPF_PROG(on_entry, struct sk_buff *skb)
{
	struct skbcache cache = {};
	__u64 data_end = ((__u64*)(skb->cb))[5];
	cache.matched = pcap_filter((void *)skb->data, (void *)data_end);
	if (!cache.matched)
		return 0;

	__u64 skbaddr = (__u64)skb;
	bpf_map_update_elem(&skbcaches, &skbaddr, &cache, BPF_ANY);

	struct event ev = {};
	__builtin_memset(&ev, 0, sizeof(ev));
	ev.type = 0;
	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);

	return 0;
}

SEC("fexit/tc")
int BPF_PROG(on_exit, struct __sk_buff *skb, int ret)
{
	__u64 skbaddr = (__u64)skb;
	struct skbcache *cache = bpf_map_lookup_elem(&skbcaches, &skbaddr);
	if (!cache || !cache->matched)
		return 0;

	struct event ev = {};
	__builtin_memset(&ev, 0, sizeof(ev));
	ev.type = 1;
	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);

	bpf_map_delete_elem(&skbcaches, &skbaddr);
	return 0;
}

