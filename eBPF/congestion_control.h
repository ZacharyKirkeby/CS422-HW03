#ifndef CONGESTION_CONTROL_H
#define CONGESTION_CONTROL_H

#define TMULT_NAME                  "cubic_tmult"
#define TMULT_MIN_CWND              2U
#define TMULT_INIT_CWND             10U
#define TMULT_INF_SSTHRESH          0x7fffffffU

/* C = 0.5 */
#define TMULT_C_NUM                 1ULL
#define TMULT_C_DEN                 2ULL

/* B = beta = 0.8 */
#define TMULT_B_NUM                 4ULL
#define TMULT_B_DEN                 5ULL
#define TMULT_ONE_MINUS_B_NUM       (TMULT_B_DEN - TMULT_B_NUM)

/* T_mult = 0.25 */
#define TMULT_T_NUM                 1LL
#define TMULT_T_DEN                 4LL

/* Q10 fixed-point seconds. */
#define TMULT_TIME_SHIFT            10U
#define TMULT_TIME_ONE              (1ULL << TMULT_TIME_SHIFT)
#define TMULT_CUBE_SHIFT            (3U * TMULT_TIME_SHIFT)
#define TMULT_NSEC_PER_SEC          1000000000ULL

/* Keeps cubic intermediate values inside a u64 for longer socket sessions */
#define TMULT_MAX_SCALED_TIME       (1ULL << 20)
#define TMULT_CBRT_HIGH             (1ULL << 21)
#define TMULT_CBRT_STEPS            22

#ifndef TCP_CONG_NON_RESTRICTED
#define TCP_CONG_NON_RESTRICTED     0x1UL
#endif

struct tmult_state {
    __u64 epoch_start_ns;
    __u64 friendly_acked;
    __u32 w_max;
    __u32 w_tcp;
    __u32 k_q10;
    __u32 reserved;
};

#endif