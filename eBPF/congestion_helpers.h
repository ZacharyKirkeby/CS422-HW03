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
static __always_inline __u32 tmult_cuberoot_u64(__u64 value);
static __always_inline __u32 tmult_calc_k_q10(__u32 w_max);
static __always_inline __u64 tmult_elapsed_q10(const struct tmult_state *ca, __u64 now_ns);
static __always_inline __u32 tmult_cubic_target(const struct tmult_state *ca, __u64 t_q10);
static __always_inline __u32 tmult_friendly_target(__u32 cwnd, __u64 t_q10);
static __always_inline void tmult_reset(struct tmult_state *ca);

static const __u8 tmult_cbrt_table[64] = {
	0,   54,  54,  54,  118, 118, 118, 118,
	123, 129, 134, 138, 143, 147, 151, 156,
	157, 161, 164, 168, 170, 173, 176, 179,
	181, 185, 187, 190, 192, 194, 197, 199,
	200, 202, 204, 206, 209, 211, 213, 215,
	217, 219, 221, 222, 224, 225, 227, 229,
	231, 232, 234, 236, 237, 239, 240, 242,
	244, 245, 246, 248, 250, 251, 252, 254,
};

static __always_inline __u32 tmult_fls64(__u64 value)
{
	if (!value)
		return 0;

	return 64 - __builtin_clzll(value);
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
	__u32 scale;
	__u32 index;
	__u32 x;
	__u64 x2;

	if (value < 64)
		return ((__u32)tmult_cbrt_table[value] + 35) >> 6;

	bits = tmult_fls64(value);
	scale = ((bits * 84) >> 8);

	if (scale)
		scale--;

	index = (__u32)(value >> (scale * 3));

	/* verifier bound for table lookup */
	if (index >= 64)
		return 0;

	x = ((__u32)(tmult_cbrt_table[index] + 10) << scale) >> 6;

	if (x <= 1)
		return 1;

	x2 = (__u64)x * x;

	if (!x2)
		return x;

	x = (__u32)(
		(2ULL * x + value / x2) / 3ULL
	);

	return x;
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
    __s64 offset_q10 = (__s64)t_q10 - (__s64)ca->k_q10;
    __s64 scaled_q10 = (offset_q10 * TMULT_T_NUM) / TMULT_T_DEN;
    __u64 magnitude_q10;
    __u64 cube;
    __u64 delta;

    if (scaled_q10 < 0)
        magnitude_q10 = (__u64)(-scaled_q10);
    else
        magnitude_q10 = (__u64)scaled_q10;

    if (magnitude_q10 > TMULT_MAX_SCALED_TIME)
        magnitude_q10 = TMULT_MAX_SCALED_TIME;

    cube = magnitude_q10 * magnitude_q10 * magnitude_q10;
    delta = (TMULT_C_NUM * cube) / (TMULT_C_DEN * (1ULL << TMULT_CUBE_SHIFT));

    if (scaled_q10 < 0) {
        if (delta >= ca->w_max)
            return TMULT_MIN_CWND;
        return ca->w_max - (__u32)delta;
    }

    if (delta > 0xffffffffULL - ca->w_max)
        return 0xffffffffU;

    return ca->w_max + (__u32)delta;
}

// the fallback algorithm
static __always_inline __u32 tmult_friendly_target(__u32 cwnd, __u64 t_q10)
{
    __u64 numerator;
    __u64 denominator;
    __u64 increase;

    if (!cwnd)
        return TMULT_MIN_CWND;

    /* W_old = cwnd + (3B / (2-B)) * t / cwnd. */
    numerator = 3ULL * TMULT_B_NUM * t_q10;
    denominator = (2ULL * TMULT_B_DEN - TMULT_B_NUM) * TMULT_TIME_ONE * cwnd;
    increase = denominator ? numerator / denominator : 0;

    if (increase > 0xffffffffULL - cwnd)
        return 0xffffffffU;

    return cwnd + (__u32)increase;
}

// reset the state machine
static __always_inline void tmult_reset(struct tmult_state *ca)
{
    ca->epoch_start_ns = 0;
    ca->w_max = 0;
    ca->w_tcp = 0;
    ca->k_q10 = 0;
    ca->reserved = 0;
}

#endif