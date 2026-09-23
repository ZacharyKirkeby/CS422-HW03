#include "congestion_control.bpf.h"

// Unclear why the license thing is needed but everything has it so uh
char LICENSE[] SEC("license") = "GPL";
// this may be unneccessary but also idk

SEC("struct_ops/mycc_init")
void BPF_PROG(mycc_init, struct sock *sk)
{
    struct mycc *ca = inet_csk_ca(sk);

    ca->loss_cwnd = 0;
}

SEC("struct_ops/mycc_release")
void BPF_PROG(mycc_release, struct sock *sk)
{
    // idk
}

SEC("struct_ops/mycc_cong_avoid")
void BPF_PROG(mycc_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);

    // placeholder, ts is RENO
    if (tp->snd_cwnd <= tp->snd_ssthresh) {
        acked = tcp_slow_start(tp, acked);
        if (!acked)
            return;
    }
    tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
}

SEC("struct_ops/mycc_ssthresh")
__u32 BPF_PROG(mycc_ssthresh, struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct mycc *ca = inet_csk_ca(sk);

    ca->loss_cwnd = tp->snd_cwnd;
    return max(tp->snd_cwnd >> 1U, 2U);
}

SEC("struct_ops/mycc_undo_cwnd")
__u32 BPF_PROG(mycc_undo_cwnd, struct sock *sk)
{
    return tcp_reno_undo_cwnd(sk);
}

SEC("struct_ops/mycc_set_state")
void BPF_PROG(mycc_set_state, struct sock *sk, __u8 new_state)
{
    // TODO
}


SEC("struct_ops/mycc_pkts_acked")
void BPF_PROG(mycc_pkts_acked, struct sock *sk, const struct ack_sample *sample)
{
    // TODO
}

// a lot of placeholders loosely based on what ive seen for eBPF for reno
// rename stuff probably 
// idk FTODO : make this not suck 
SEC(".struct_ops")
struct tcp_congestion_ops mycc_ops = {
    .init        = (void *)mycc_init,
    .release     = (void *)mycc_release,
    .ssthresh    = (void *)mycc_ssthresh,
    .cong_avoid  = (void *)mycc_cong_avoid,
    .undo_cwnd   = (void *)mycc_undo_cwnd,
    .set_state   = (void *)mycc_set_state,
    .pkts_acked  = (void *)mycc_pkts_acked,
    .flags       = TCP_CONG_NON_RESTRICTED,
    .name        = "bpf_mycc",
};