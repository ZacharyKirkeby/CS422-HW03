# CS422-HW03
eBPF moment

## Option 1: eBPF module

Built/tested on Arch Linux kernel `7.2.11-arch1-1`, broadly compatible with Linux Kernel 7.2.x. The module uses the running kernel's BTF information to generate `vmlinux.h`, so it should be rebuilt after any kernel update before loading.

### Dependencies

- `libbpf` 1.7.0-1
- `clang` 22.1.8
- `bpftool`
- `make`
- Linux kernel with BPF, BTF, and `struct_ops` support
- `/sys/kernel/btf/vmlinux` available
- Root/sudo access for registering and unregistering the congestion-control `struct_ops`

Linux kernel headers are not directly required for the eBPF source because the Makefile generates `vmlinux.h` from the running kernel's BTF data.

### Usage

Build the eBPF object:

```bash
cd eBPF
make clean
make
```

This generates `vmlinux.h` from:

```text
/sys/kernel/btf/vmlinux
```

and builds:

```text
cubic_tmult.bpf.o
```

Load/register the congestion-control algorithm:

```bash
sudo make load
```

Verify that it is registered:

```bash
sudo make verify
```

It should appear in:

```bash
cat /proc/sys/net/ipv4/tcp_available_congestion_control
```

as:

```text
cubic_tmult
```

Unload/unregister the algorithm with:

```bash
sudo make unload
```

### Misc Notes

- This is an eBPF `tcp_congestion_ops` implementation loaded through BPF `struct_ops`; it is not a traditional `.ko` kernel module.
- The registered congestion-control algorithm is named `cubic_tmult`.
- `TCP_CONG_NON_RESTRICTED` is set so the algorithm can be selected through the normal `TCP_CONGESTION` socket option.
- Registration does not persist across reboots. After rebooting, the module must be loaded again with `sudo make load`.
- After a kernel upgrade, run `make clean && make` before loading so that `vmlinux.h` is regenerated against the currently running kernel.
- The implementation uses integer/fixed-point arithmetic because floating-point operations are not available in eBPF kernel programs. Time values used by the CUBIC calculation are represented as Q10 fixed-point seconds.