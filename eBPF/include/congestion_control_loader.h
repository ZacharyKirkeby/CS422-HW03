// SPDX-License-Identifier: GPL-2.0
// module/congestion_control_loader.c

#ifndef CONGESTION_CONTROL_LOADER_H
#define CONGESTION_CONTROL_LOADER_H

#include <stdio.h>
#include <bpf/libbpf.h>

#define BPF_OBJ_PATH "congestion_control_bpf.o"
#define STRUCT_OPS_MAP_NAME "mycc"
#define PIN_PATH "/sys/fs/bpf/mycc_link"

#endif // CONGESTION_CONTROL_LOADER_H