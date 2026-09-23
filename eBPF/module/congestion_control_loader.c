#include "congestion_control_loader.h"

int main(void) {
    struct bpf_object *obj = bpf_object__open_file(BPF_OBJ_PATH, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "failed to open %s \n", BPF_OBJ_PATH);
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "failed to load BPF object\n");
        return 1;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, STRUCT_OPS_MAP_NAME);
    if (!map) {
        fprintf(stderr, "struct_ops map '%s' not found\n", STRUCT_OPS_MAP_NAME);
        return 1;
    }

    struct bpf_link *link = bpf_map__attach_struct_ops(map);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "failed to attach struct_ops, or kernel lacks CONFIG_BPF_STRUCT_OPS?\n");
        return 1;
    }

    if (bpf_link__pin(link, PIN_PATH)) {
        fprintf(stderr, "warning: failed to pin link at %s \n", PIN_PATH);
    } else {
        printf("pinned at %s\n", PIN_PATH);
    }

    printf("registered 'bpf_mycc'. Verify with:\n");

    bpf_link__disconnect(link);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}