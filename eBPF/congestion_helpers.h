#ifndef CUBIC_TMULT_HELPERS_H
#define CUBIC_TMULT_HELPERS_H

#include "congestion_control.h"
#include <bpf/bpf_helpers.h>

/*
 * Always inline is used bc I am telling the compiler what to do, not suggesting
 * I like efficiency for kernel adjacent functions
 * This file contains the bulk of the cubic tmult algorithm
 * Forward declarations are because i like forward declarations, fight me
 */

// Helper functions, forward declared
static __always_inline struct tcp_sock *tmult_tcp_sk(const struct sock *sk);
static __always_inline struct tmult_state *tmult_ca(const struct sock *sk); 
static __always_inline __u32 tmult_clamp_cwnd(const struct tcp_sock *tp, __u64 cwnd);
static __always_inline __u32 tmult_fls64(__u64 value);
static __always_inline __u32 tmult_cuberoot_u64(__u64 value);
static __always_inline __u32 tmult_calc_k_q10(__u32 w_max);
static __always_inline __u64 tmult_elapsed_q10(const struct tmult_state *ca, __u64 now_ns);
static __always_inline __u32 tmult_cubic_target(const struct tmult_state *ca, __u64 t_q10);
static __always_inline __u32 tmult_friendly_target(struct tmult_state *ca, __u32 cwnd, __u32 acked);
static __always_inline __u32 tmult_target_cnt(__u32 cwnd, __u32 target);
static __always_inline void tmult_cong_avoid_ai(struct tcp_sock *tp, __u32 cnt, __u32 acked);
static __always_inline void tmult_reset(struct tmult_state *ca);

static __always_inline __u32 tmult_fls64(__u64 value)
{
    __u32 bit = 0;

    if (!value)
        return 0;
    if (value >> 32) {
        value >>= 32;
        bit += 32;
    }
    if (value >> 16) {
        value >>= 16;
        bit += 16;
    }
    if (value >> 8) {
        value >>= 8;
        bit += 8;
    }
    if (value >> 4) {
        value >>= 4;
        bit += 4;
    }
    if (value >> 2) {
        value >>= 2;
        bit += 2;
    }
    if (value >> 1)
        bit++;

    return bit + 1;
}

// casts the kernel generic socket type sock to a tcp socket
static __always_inline struct tcp_sock *tmult_tcp_sk(const struct sock *sk)
{
    return (struct tcp_sock *)sk;
}

// retrieves tmult state, per conn private state
static __always_inline struct tmult_state *tmult_ca(const struct sock *sk)
{
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;

    return (struct tmult_state *)icsk->icsk_ca_priv;
}

// binds the tmult algo window to a reasonable frame
static __always_inline __u32 tmult_clamp_cwnd(const struct tcp_sock *tp, __u64 cwnd)
{
    __u64 clamp = tp->snd_cwnd_clamp;

    if (cwnd < TMULT_MIN_CWND)
        cwnd = TMULT_MIN_CWND;
    if (cwnd > clamp)
        cwnd = clamp;

    return (__u32)cwnd;
}

// this just does a cube root
static __always_inline __u32 tmult_cuberoot_u64(__u64 value)
{
    __u32 bits;
    __u32 shift;
    __u32 guess;
    __u64 square;

    // trust the process i know it looks dumb
    if (value < 1)
        return 0;
    if (value < 8)
        return 1;
    if (value < 27)
        return 2;
    if (value < 64)
        return 3;

    bits = tmult_fls64(value);
    shift = (bits + 2) / 3;

    if (shift > 22)
        shift = 22;

    guess = 1U << shift;

    square = (__u64)guess * guess;
    if (square)
        guess = (__u32)((2ULL * guess + value / square) / 3ULL);

    square = (__u64)guess * guess;
    if (square)
        guess = (__u32)((2ULL * guess + value / square) / 3ULL);

    square = (__u64)guess * guess;
    if (square)
        guess = (__u32)((2ULL * guess + value / square) / 3ULL);

    square = (__u64)guess * guess;
    if (square)
        guess = (__u32)((2ULL * guess + value / square) / 3ULL);

    square = (__u64)guess * guess;
    if (square)
        guess = (__u32)((2ULL * guess + value / square) / 3ULL);

    return guess;
}

// cubic k formula from the psuedocode
static __always_inline __u32 tmult_calc_k_q10(__u32 w_max)
{
    __u64 numerator;
    __u64 denominator;

    /* K = cbrt(W_max * (1 - B) / C), returned as Q10 seconds. */
    numerator = (__u64)w_max * TMULT_ONE_MINUS_B_NUM * TMULT_C_DEN;
    numerator <<= TMULT_CUBE_SHIFT;
    denominator = TMULT_B_DEN * TMULT_C_NUM;

    return tmult_cuberoot_u64(numerator / denominator);
}

// calculates t = currentTime - epochStart
static __always_inline __u64 tmult_elapsed_q10(const struct tmult_state *ca, __u64 now_ns)
{
    __u64 elapsed_ns;

    if (!ca->epoch_start_ns || now_ns <= ca->epoch_start_ns)
        return 0;

    elapsed_ns = now_ns - ca->epoch_start_ns;
    return (elapsed_ns << TMULT_TIME_SHIFT) / TMULT_NSEC_PER_SEC;
}

// cubic target window calculation
static __always_inline __u32 tmult_cubic_target(const struct tmult_state *ca, __u64 t_q10)
{
    __s64 scaled_t_q10 = ((__s64)t_q10 * TMULT_T_NUM) / TMULT_T_DEN;
    __s64 offset_q10 = scaled_t_q10 - (__s64)ca->k_q10;
    __u64 magnitude_q10;
    __u64 cube;
    __u64 delta;

    if (offset_q10 < 0)
        magnitude_q10 = (__u64)(-offset_q10);
    else
        magnitude_q10 = (__u64)offset_q10;

    if (magnitude_q10 > TMULT_MAX_SCALED_TIME)
        magnitude_q10 = TMULT_MAX_SCALED_TIME;

    cube = magnitude_q10 * magnitude_q10 * magnitude_q10;
    delta = (TMULT_C_NUM * cube) / (TMULT_C_DEN * (1ULL << TMULT_CUBE_SHIFT));

    if (offset_q10 < 0) {
        if (delta >= ca->w_max)
            return TMULT_MIN_CWND;
        return ca->w_max - (__u32)delta;
    }

    if (delta > 0xffffffffULL - ca->w_max)
        return 0xffffffffU;

    return ca->w_max + (__u32)delta;
}

// the fallback algorithm
static __always_inline __u32 tmult_friendly_target(struct tmult_state *ca, __u32 cwnd, __u32 acked)
{
    __u64 alpha_num;
    __u64 alpha_den;
    __u64 threshold;
    __u64 increase;

    if (!cwnd)
        return TMULT_MIN_CWND;

    if (!ca->w_tcp)
        ca->w_tcp = cwnd;

    /*
     * alpha = 3(1-B) / (1+B)
     * Increase W_tcp by one for approximately cwnd / alpha ACKed packets.
     */
    alpha_num = 3ULL * TMULT_ONE_MINUS_B_NUM;
    alpha_den = TMULT_B_DEN + TMULT_B_NUM;

    threshold = (alpha_den * cwnd + alpha_num - 1) / alpha_num;
    if (!threshold)
        threshold = 1;

    ca->friendly_acked += acked;

    increase = ca->friendly_acked / threshold;
    ca->friendly_acked %= threshold;

    if (increase > 0xffffffffULL - ca->w_tcp)
        return 0xffffffffU;

    ca->w_tcp += (__u32)increase;

    return ca->w_tcp;
}

// converts a target window into the number of ACKs between cwnd increases
static __always_inline __u32 tmult_target_cnt(__u32 cwnd, __u32 target)
{
    __u64 slow;
    __u32 diff;
    __u32 cnt;

    if (!cwnd)
        return 2;

    if (target > cwnd) {
        diff = target - cwnd;
        cnt = cwnd / diff;

        if (cnt < 2)
            cnt = 2;

        return cnt;
    }

    slow = 100ULL * cwnd;
    if (slow > 0xffffffffULL)
        slow = 0xffffffffULL;

    if (slow < 2)
        slow = 2;

    return (__u32)slow;
}

// increases cwnd according to the target rate without directly jumping to target
static __always_inline void tmult_cong_avoid_ai(struct tcp_sock *tp, __u32 cnt, __u32 acked)
{
    __u64 credit;
    __u64 delta;

    if (cnt < 2)
        cnt = 2;

    if (tp->snd_cwnd_cnt >= cnt) {
        tp->snd_cwnd_cnt = 0;
        tp->snd_cwnd = tmult_clamp_cwnd(tp, (__u64)tp->snd_cwnd + 1);
    }

    credit = (__u64)tp->snd_cwnd_cnt + acked;

    if (credit >= cnt) {
        delta = credit / cnt;
        credit -= delta * cnt;

        tp->snd_cwnd = tmult_clamp_cwnd(
            tp,
            (__u64)tp->snd_cwnd + delta
        );
    }

    tp->snd_cwnd_cnt = (__u32)credit;
}

// reset the state machine
static __always_inline void tmult_reset(struct tmult_state *ca)
{
    ca->epoch_start_ns = 0;
    ca->friendly_acked = 0;
    ca->w_max = 0;
    ca->w_tcp = 0;
    ca->k_q10 = 0;
    ca->reserved = 0;
}

#endif