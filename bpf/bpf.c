// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// force emitting struct into the ELF.
const struct event *_ __attribute__((unused));

struct event {
	__u64 pc; // only used for kprobe events
	__u8 type; // 0: fentry, 1: fexit; 2: kprobe
};

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 1<<29,
};

struct bpf_map_def SEC("maps") skbmatched = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(bool),
	.max_entries = 10000,
};

static __always_inline
bool pcap_filter(void *data, void* data_end)
{
	bpf_printk("%p %p\n", data, data_end);
	return data < data_end;
}

struct bpf_map_def SEC("maps") bp2skb = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u64),
	.max_entries = 10000,
};

SEC("kprobe/tcf_classify")
int on_tcf_classify(struct pt_regs *ctx)
{
	__u64 bp = ctx->sp - 8;
	__u64 skb = ctx->di;
	bpf_printk("k tcf: %llx %llx\n", bp, skb);
	bpf_map_update_elem(&bp2skb, &bp, &skb, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcf_classify")
int off_tcf_classify(struct pt_regs *ctx)
{
	__u64 bp = ctx->sp - 16;
	bpf_printk("kp tcf: %llx\n", bp);
	bpf_map_delete_elem(&bp2skb, &bp);
	return 0;
}

SEC("fentry/tc")
int BPF_PROG(on_entry, struct sk_buff *skb)
{
	__u64 data_end = ((__u64*)(skb->cb))[5];
	bool matched = pcap_filter((void *)skb->data, (void *)data_end);
	if (!matched)
		return 0;
	bpf_map_update_elem(&skbmatched, &skb, &matched, BPF_ANY);

	struct event ev = {};
	__builtin_memset(&ev, 0, sizeof(ev));
	ev.type = 0;
	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
	return 0;
}

SEC("fexit/tc")
int BPF_PROG(on_exit, struct sk_buff *skb, int ret)
{
	bool *matched = bpf_map_lookup_elem(&skbmatched, &skb);
	if (!matched || !*matched)
		return 0;

	struct event ev = {};
	__builtin_memset(&ev, 0, sizeof(ev));
	ev.type = 1;
	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);

	bpf_map_delete_elem(&skbmatched, &skb);
	return 0;
}

SEC("kprobe/on_bpf_helper")
int on_bpf_helper(struct pt_regs *ctx)
{
	__u64 lr;
	bpf_probe_read_kernel(&lr, sizeof(lr), (void *)ctx->sp);

	// TODO: robustify this
	__u64 bp1, bp2, bp3, tcf_classify_bp;
	bpf_probe_read_kernel(&bp1, sizeof(bp1), (void *)ctx->bp);
	bpf_probe_read_kernel(&bp2, sizeof(bp2), (void *)bp1);
	bpf_probe_read_kernel(&bp3, sizeof(bp3), (void *)bp2);
	bpf_probe_read_kernel(&tcf_classify_bp, sizeof(tcf_classify_bp), (void *)bp3);
	__u64 *skb = bpf_map_lookup_elem(&bp2skb, &tcf_classify_bp);
	if (!skb)
		return 0;
	bool *matched = bpf_map_lookup_elem(&skbmatched, skb);
	if (!matched || !*matched)
		return 0;

	struct event ev = {};
	__builtin_memset(&ev, 0, sizeof(ev));
	ev.type = 2;
	ev.pc = ctx->ip;
	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
	return 0;
}