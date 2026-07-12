package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -I../../bpf" minecraftXDP ../../bpf/minecraft_xdp.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -I../../bpf" minecraftSockops ../../bpf/minecraft_sockops.bpf.c
