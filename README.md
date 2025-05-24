# What is Single Packet Authorization (SPA)?

SPA is a method where access to services is controlled by requiring a special, cryptographically secure packet as a kind of "knock" before anything else is allowed. If the packet is valid, a firewall or service port is opened for a short time, or a connection is allowed.

- Purpose: Hides network services from unauthorized users.
- Used in: Tools like fwknop, Knockd, or as part of some VPNs.
- Benefit: Reduces attack surface by making services “invisible” unless authorized.

# High-Level Architecture

# Components

## Go Daemon

- Listens for UDP packets on a specific port
- Extracts and verifies HMAC
- Uses cilium/ebpf for attaching BPF programs
- Updates firewall using iptables

## eBPF Program

- Hooked via XDP (eXpress Data Path) or TC ingress to intercept packets early
- Filters packets by SPA port
- Passes matched packets to userspace using BPF_MAP_TYPE_RINGBUF or BPF_MAP_TYPE_PERF_EVENT_ARRAY

## Firewall Integration

- At startup: block all incoming traffic (iptables -P INPUT DROP)
- On valid SPA: open port 8080 (iptables -A INPUT -p tcp --dport 8080 -j ACCEPT)
- Optionally: close port after N seconds.

## Build

### install

`sudo apt install clang llvm libbpf-dev libelf-dev gcc-multilib make`
`bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h`

### compile

✅ -I bpf/ ensures the compiler sees vmlinux.h if it's there.
✅ -target bpf ensures correct bytecode generation.
✅ -g is helpful for debugging and BTF-enabled kernels.

`
clang \
 -O2 -g -Wall \
 -target bpf \
 -D\_\_TARGET_ARCH_x86 \
 -I/usr/include \
 -Ibpf/ \
 -c bpf/spa_xdp.c -o bpf/spa_xdp.o

`
