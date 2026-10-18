// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"

#include "congestion_control.h"
#include "congestion_helpers.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// In how linux linux's, a license is needed for bpf modules to function
char LICENSE[] SEC("license") = "GPL";

// Predominantly callbacks needed to correctly perform the algorithm

SEC("struct_ops")
void BPF_PROG(cubic_tmult_init, struct sock *sk)
{
    struct tcp_sock *tp = tmult_tcp_sk(sk);
    struct tmult_state *ca = tmult_ca(sk);

    /* cwnd <- cwnd_init. */
    tp->snd_cwnd = tmult_clamp_cwnd(tp, TMULT_INIT_CWND);

    /* reset(): W_max <- 0, W_tcp <- 0, K <- 0, ssthresh <- infinity. */
    tmult_reset(tp, ca);
}

SEC("struct_ops")
__u32 BPF_PROG(cubic_tmult_ssthresh, struct sock *sk)
{
    struct tcp_sock *tp = tmult_tcp_sk(sk);
    struct tmult_state *ca = tmult_ca(sk);
    __u32 reduced_cwnd;
    __u32 ssthresh;

    /* packetLost(): W_max <- cwnd. */
    ca->w_max = tp->snd_cwnd;

    /* ssthresh <- W_max * B. */
    ssthresh = (__u32)(((__u64)ca->w_max * TMULT_B_NUM) / TMULT_B_DEN);
    ssthresh = tmult_clamp_cwnd(tp, ssthresh);
    tp->snd_ssthresh = ssthresh;

    /* cwnd <- W_max * B. */
    reduced_cwnd = ssthresh;
    tp->snd_cwnd = reduced_cwnd;

    /* Start a new loss epoch and calculate K. */
    ca->epoch_start_ns = bpf_ktime_get_ns();
    ca->k_q10 = tmult_calc_k_q10(ca->w_max);

    return ssthresh;
}

SEC("struct_ops")
void BPF_PROG(cubic_tmult_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
    struct tcp_sock *tp = tmult_tcp_sk(sk);
    struct tmult_state *ca = tmult_ca(sk);
    __u64 now_ns;
    __u64 t_q10;
    __u64 floor;
    __u32 cubic_target;
    __u32 friendly_target;
    __u32 target;

    (void)ack;

    if (!acked)
        return;

    /* ackReceived(): slow-start case. */
    if (tp->snd_cwnd < tp->snd_ssthresh) {
        tp->snd_cwnd = tmult_clamp_cwnd(tp, (__u64)tp->snd_cwnd + 1);
        return;
    }

    now_ns = bpf_ktime_get_ns();

    /* epochStart == 0 is the pre-loss epoch; begin it on the first CA ACK. */
    if (!ca->epoch_start_ns)
        ca->epoch_start_ns = now_ns;

    t_q10 = tmult_elapsed_q10(ca, now_ns);

    /* W_tcp = C * (T_mult * (t - K))^3 + W_max. */
    cubic_target = tmult_cubic_target(ca, t_q10);
    ca->w_tcp = cubic_target;

    /* W_old = cwnd + (3B / (2-B)) * t / cwnd. */
    friendly_target = tmult_friendly_target(tp->snd_cwnd, t_q10);

    /* cwnd <- max(W_tcp, W_old). */
    target = cubic_target > friendly_target ? cubic_target : friendly_target;

    /* cwnd must always be at least W_max * beta. */
    floor = ((__u64)ca->w_max * TMULT_B_NUM) / TMULT_B_DEN;
    if (target < floor)
        target = (__u32)floor;

    tp->snd_cwnd = tmult_clamp_cwnd(tp, target);
}

SEC("struct_ops")
void BPF_PROG(cubic_tmult_cwnd_event, struct sock *sk, enum tcp_ca_event event)
{
    struct tcp_sock *tp = tmult_tcp_sk(sk);
    struct tmult_state *ca = tmult_ca(sk);

    /* timeout(): reset(). Linux reports retransmission timeout as CA_EVENT_LOSS. */
    if (event == CA_EVENT_LOSS)
        tmult_reset(tp, ca);
}

SEC("struct_ops")
__u32 BPF_PROG(cubic_tmult_undo_cwnd, struct sock *sk)
{
    /* No separate undo behavior is defined by the pseudocode. */
    return tmult_tcp_sk(sk)->snd_cwnd;
}

SEC(".struct_ops")
struct tcp_congestion_ops cubic_tmult_ops = {
    .init       = (void *)cubic_tmult_init,
    .ssthresh   = (void *)cubic_tmult_ssthresh,
    .cong_avoid = (void *)cubic_tmult_cong_avoid,
    .cwnd_event = (void *)cubic_tmult_cwnd_event,
    .undo_cwnd  = (void *)cubic_tmult_undo_cwnd,
    .flags      = TCP_CONG_NON_RESTRICTED,
    .name       = TMULT_NAME,
};