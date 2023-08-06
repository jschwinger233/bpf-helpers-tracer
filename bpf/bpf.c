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
	.max_entries = 10000,
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
	.max_entries = 10000,
};

static __always_inline
bool pcap_filter(void *data, void* data_end)
{
	bpf_printk("%p %p\n", data, data_end);
	return data < data_end;
}

struct called {
	__u64 pc;
	__u64 by;
};

struct skb_location {
	__u64 off_from_bp;
	__u8 reg;
	bool from_stack;
};

struct bpf_map_def SEC("maps") skb_locations = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct called),
	.value_size = sizeof(struct location),
	.max_entries = 10000,
};

SEC("fentry/tc")
int BPF_PROG(on_entry, struct sk_buff *skb)
{
	struct skbcache cache = {};
	__u64 data_end = ((__u64*)(skb->cb))[5];
	cache.matched = pcap_filter((void *)skb->data, (void *)data_end);
	if (!cache.matched)
		return 0;

	bpf_map_update_elem(&skbcaches, &skb, &cache, BPF_ANY);

	struct event ev = {};
	__builtin_memset(&ev, 0, sizeof(ev));
	ev.type = 0;
	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
	return 0;
}

SEC("fexit/tc")
int BPF_PROG(on_exit, struct sk_buff *skb, int ret)
{
	struct skbcache *cache = bpf_map_lookup_elem(&skbcaches, &skb);
	if (!cache || !cache->matched)
		return 0;

	struct event ev = {};
	__builtin_memset(&ev, 0, sizeof(ev));
	ev.type = 1;
	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);

	bpf_map_delete_elem(&skbcaches, &skb);
	return 0;
}

static __always_inline
void read_reg(void *regval, struct pt_regs *ctx, __u8 reg)
{
	switch (reg) {
	case 0:
		bpf_probe_read_kernel(regval, sizeof(ctx->ax), (void *)&ctx->ax);
		break;
	case 1:
		bpf_probe_read_kernel(regval, sizeof(ctx->dx), (void *)&ctx->dx);
		break;
	case 2:
		bpf_probe_read_kernel(regval, sizeof(ctx->cx), (void *)&ctx->cx);
		break;
	case 3:
		bpf_probe_read_kernel(regval, sizeof(ctx->bx), (void *)&ctx->bx);
		break;
	case 4:
		bpf_probe_read_kernel(regval, sizeof(ctx->si), (void *)&ctx->si);
		break;
	case 5:
		bpf_probe_read_kernel(regval, sizeof(ctx->di), (void *)&ctx->di);
		break;
	case 6:
		bpf_probe_read_kernel(regval, sizeof(ctx->bp), (void *)&ctx->bp);
		break;
	case 7:
		bpf_probe_read_kernel(regval, sizeof(ctx->sp), (void *)&ctx->sp);
		break;
	case 8:
		bpf_probe_read_kernel(regval, sizeof(ctx->r8), (void *)&ctx->r8);
		break;
	case 9:
		bpf_probe_read_kernel(regval, sizeof(ctx->r9), (void *)&ctx->r9);
		break;
	case 10:
		bpf_probe_read_kernel(regval, sizeof(ctx->r10), (void *)&ctx->r10);
		break;
	case 11:
		bpf_probe_read_kernel(regval, sizeof(ctx->r11), (void *)&ctx->r11);
		break;
	case 12:
		bpf_probe_read_kernel(regval, sizeof(ctx->r12), (void *)&ctx->r12);
		break;
	case 13:
		bpf_probe_read_kernel(regval, sizeof(ctx->r13), (void *)&ctx->r13);
		break;
	case 14:
		bpf_probe_read_kernel(regval, sizeof(ctx->r14), (void *)&ctx->r14);
		break;
	case 15:
		bpf_probe_read_kernel(regval, sizeof(ctx->r15), (void *)&ctx->r15);
		break;
	}
	return;
}

SEC("kprobe/bpf_helper")
int bpf_helper(struct pt_regs *ctx)
{
	struct called c = {};
	c.pc = ctx->ip;
	bpf_probe_read_kernel(&c.by, sizeof(c.by), (void *)ctx->sp);
	struct skb_location *loc = bpf_map_lookup_elem(&skb_locations, &c);
	if (!loc)
		return 0;

	struct sk_buff *skb = 0;
	if (loc->from_stack)
		bpf_probe_read_kernel(&skb, sizeof(skb), (void *)ctx->bp + loc->off_from_bp);
	else
		read_reg(&skb, ctx, loc->reg);

	struct skbcache *cache = bpf_map_lookup_elem(&skbcaches, &skb);
	if (!cache || !cache->matched)
		return 0;

	struct event ev = {};
	__builtin_memset(&ev, 0, sizeof(ev));
	ev.type = 2;
	ev.pc = ctx->ip;
	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
	return 0;
}
