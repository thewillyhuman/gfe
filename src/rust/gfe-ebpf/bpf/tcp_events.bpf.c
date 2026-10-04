// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * Kernel side of gfe-ebpf.
 *
 * One "sockops" program, attached to the node's cgroup, so it sees exactly
 * the TCP connections of the node: the ones it accepts from clients and the
 * ones it opens to backends. It works on sockets, not on packets, and
 * therefore the same way whatever path the traffic took to get here.
 *
 * For every connection it
 *   - notes when the handshake completed (open_conns), which user space reads
 *     right after accept() to learn how long the connection sat in the
 *     accept queue;
 *   - reports the connection when it closes (closed_conns), with what only
 *     the kernel knows about it: round-trip time, retransmissions, and the
 *     TCP state it was closed from.
 *
 * The layouts below are read byte by byte by src/wire.rs. Change both.
 *
 * Deliberately self-contained: it needs clang and the kernel's uapi headers,
 * not libbpf.
 */
#include <linux/bpf.h>

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "src/wire.rs decodes these structures as little-endian"
#endif

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define AF_INET 2
#define AF_INET6 10

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long (*bpf_sock_ops_cb_flags_set)(struct bpf_sock_ops *ctx, int flags) = (void *)BPF_FUNC_sock_ops_cb_flags_set;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_output;

/* A connection, as the node sees it. IPv4 addresses are stored IPv4-mapped. */
struct conn_key {
	__u8 local_addr[16];
	__u8 peer_addr[16];
	__u16 local_port; /* host byte order */
	__u16 peer_port;  /* host byte order */
};
_Static_assert(sizeof(struct conn_key) == 36, "conn_key layout");

struct conn_open {
	__u64 established_ns; /* CLOCK_MONOTONIC */
	__u8 accepted;        /* 1: accepted by the node, 0: opened by it */
	__u8 pad[7];
};
_Static_assert(sizeof(struct conn_open) == 16, "conn_open layout");

struct conn_closed {
	struct conn_key key;
	__u8 accepted;
	__u8 state_before_close; /* BPF_TCP_* */
	__u16 pad;
	__u32 srtt_us;
	__u32 min_rtt_us;
	__u32 retransmits; /* segments */
	__u32 segments_out;
	__u64 established_ns;
	__u64 closed_ns;
	__u64 bytes_acked; /* sent and acknowledged by the peer */
	__u64 bytes_received;
};
_Static_assert(sizeof(struct conn_closed) == 88, "conn_closed layout");

/* Sized by user space to the node's connection limits before loading. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct conn_key);
	__type(value, struct conn_open);
} open_conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} closed_conns SEC(".maps");

/* Closed connections that could not be reported because the buffer was full. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost SEC(".maps");

static __always_inline void fill_key(struct bpf_sock_ops *ctx, struct conn_key *key)
{
	/*
	 * Every context field is read here, unconditionally and each on its
	 * own. The verifier only accepts context reads at constant offsets;
	 * reading inside the branches below lets the compiler merge two reads
	 * into one at a computed offset, which is rejected.
	 */
	__u32 family = ctx->family;
	__u32 local4 = ctx->local_ip4;
	__u32 peer4 = ctx->remote_ip4;
	__u32 local6[4] = { ctx->local_ip6[0], ctx->local_ip6[1], ctx->local_ip6[2], ctx->local_ip6[3] };
	__u32 peer6[4] = { ctx->remote_ip6[0], ctx->remote_ip6[1], ctx->remote_ip6[2], ctx->remote_ip6[3] };
	__u32 local_port = ctx->local_port;
	__u32 peer_port = ctx->remote_port;

	__builtin_memset(key, 0, sizeof(*key));
	if (family == AF_INET) {
		key->local_addr[10] = 0xff;
		key->local_addr[11] = 0xff;
		__builtin_memcpy(&key->local_addr[12], &local4, 4);
		key->peer_addr[10] = 0xff;
		key->peer_addr[11] = 0xff;
		__builtin_memcpy(&key->peer_addr[12], &peer4, 4);
	} else {
		__builtin_memcpy(key->local_addr, local6, 16);
		__builtin_memcpy(key->peer_addr, peer6, 16);
	}
	key->local_port = (__u16)local_port;
	/* The remote port is a big-endian 32-bit value. */
	key->peer_port = (__u16)__builtin_bswap32(peer_port);
}

SEC("sockops")
int tcp_events(struct bpf_sock_ops *ctx)
{
	struct conn_key key;

	if (ctx->family != AF_INET && ctx->family != AF_INET6)
		return 1;

	switch (ctx->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
		struct conn_open open;

		__builtin_memset(&open, 0, sizeof(open));
		open.established_ns = bpf_ktime_get_ns();
		open.accepted = ctx->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB;
		fill_key(ctx, &key);
		bpf_map_update_elem(&open_conns, &key, &open, BPF_ANY);
		/* Ask to be called again when this socket changes state. */
		bpf_sock_ops_cb_flags_set(ctx, ctx->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
		break;
	}
	case BPF_SOCK_OPS_STATE_CB: {
		struct conn_closed closed;
		struct conn_open *open;

		if (ctx->args[1] != BPF_TCP_CLOSE)
			break;
		fill_key(ctx, &key);
		open = bpf_map_lookup_elem(&open_conns, &key);
		if (!open)
			break;

		__builtin_memset(&closed, 0, sizeof(closed));
		closed.key = key;
		closed.accepted = open->accepted;
		closed.state_before_close = (__u8)ctx->args[0];
		closed.srtt_us = ctx->srtt_us >> 3; /* kept as 8 times the value */
		closed.min_rtt_us = ctx->rtt_min;
		closed.retransmits = ctx->total_retrans;
		closed.segments_out = ctx->segs_out;
		closed.established_ns = open->established_ns;
		closed.closed_ns = bpf_ktime_get_ns();
		closed.bytes_acked = ctx->bytes_acked;
		closed.bytes_received = ctx->bytes_received;

		if (bpf_ringbuf_output(&closed_conns, &closed, sizeof(closed), 0)) {
			__u32 zero = 0;
			__u64 *count = bpf_map_lookup_elem(&lost, &zero);

			if (count)
				__sync_fetch_and_add(count, 1);
		}
		bpf_map_delete_elem(&open_conns, &key);
		break;
	}
	}
	return 1;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
