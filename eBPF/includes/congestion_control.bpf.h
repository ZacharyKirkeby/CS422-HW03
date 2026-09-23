// SPDX-License-Identifier: GPL-2.0

#ifndef CONGESTION_CONTROL_BPF_H
#define CONGESTION_CONTROL_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TCP_CONG_NON_RESTRICTED 0x1
#define USEC_PER_SEC            1000000UL

struct mycc {
    __u32 loss_cwnd;
};

extern void tcp_reno_cong_avoid(struct sock *sk, __u32 ack, __u32 acked) __ksym;
extern __u32 tcp_reno_ssthresh(struct sock *sk) __ksym;
extern __u32 tcp_reno_undo_cwnd(struct sock *sk) __ksym;
extern __u32 tcp_slow_start(struct tcp_sock *tp, __u32 acked) __ksym;
extern void tcp_cong_avoid_ai(struct tcp_sock *tp, __u32 w, __u32 acked) __ksym;

static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
    return (struct tcp_sock *)sk;
}

static __always_inline struct inet_connection_sock *inet_csk(const struct sock *sk)
{
    return (struct inet_connection_sock *)sk;
}

static __always_inline void *inet_csk_ca(const struct sock *sk)
{
    return (void *)inet_csk(sk)->icsk_ca_priv;
}

#endif // CONGESTION_CONTROL_BPF_H