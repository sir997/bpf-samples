### 环境
```
bpftool libbpf libbpf-devel elf-utils kernel-source
```

### 1. 编写minimal.bpf.c
```
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    bpf_printk("BPF triggered from PID .\n");
    return 0;
}
```

### 2. 将minimal.bpf.c编译成minimal.bpf.o
```
完整：
clang -g -O2 -target bpf -D__TARGET_ARCH_x86                               -I../../../libbpf/include/uapi -I../../vmlinux/x86/ -I../../../blazesym/include -idirafter /usr/lib64/clang/15.0.7/include -idirafter /usr/local/include -idirafter /usr/include -c minimal.bpf.c -o minimal.bpf.o

精简：
clang -g -O2 -target bpf -D__TARGET_ARCH_x86  -c minimal.bpf.c -o minimal.bpf.o
```

### 3. 将minimal.bpf.o转换为minimal.skel.h
```
bpftool gen skeleton minimal.bpf.o > minimal.skel.h
```

### 4. 编写用户程序minimal.c

### 5. 编译用户态程序minimal.o
```
gcc -I/usr/src/kernels/$(uname -r)/include/uapi/ -I/usr/src/kernels/$(uname -r)/include/ -I/usr/include/bpf/ -c minimal.c -o minimal.o
```

### 6. 链接成为可执行程序minimal
```
gcc minimal.o -lbpf -lelf -lz -o minimal
```