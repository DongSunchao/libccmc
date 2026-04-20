# ebpf/Makefile
CLANG ?= clang
BPFTOOL ?= bpftool
LIBBPF_INCLUDES := -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -I./include -I.

all: xdp_zerowin.bpf.o tc_egress.bpf.o

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

xdp_zerowin.bpf.o: xdp_zerowin.bpf.c vmlinux.h include/zeno_common.h include/zeno_proto.h include/zeno_checksum.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 $(LIBBPF_INCLUDES) -c $< -o $@

tc_egress.bpf.o: tc_egress.bpf.c vmlinux.h include/zeno_common.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 $(LIBBPF_INCLUDES) -c $< -o $@

clean:
	rm -f *.o vmlinux.h
