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
```
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include "minimal.skel.h"

int main(int argc, char **argv)
{
    struct minimal_bpf *skel;
    int err;

    struct rlimit rlim = {
        .rlim_cur = 512UL << 20,
        .rlim_max = 512UL << 20,
    };

    // bpf程序需要加载到lock memory中，因此需要将本进程的lock mem配大些
    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
    {
        fprintf(stderr, "set rlimit error!\n");
        return 1;
    }

    // 第一步，打开bpf文件，返回指向xxx_bpf的指针
    skel = minimal_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "failed to open bpf skeleton\n");
        return 1;
    }

    skel->bss->mpid = getpid();

    // 第二步，加载及校验bpf程序
    err = minimal_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // 第三步，附加到指定的hook点
    err = minimal_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe`\n");

    for (;;)
    {
        printf("hello-for\n");
        fprintf(stdout, ".");
        sleep(1);
    }

cleanup:
    minimal_bpf__destroy(skel);

    return -err;
}
```

### 5. 编译用户态程序minimal.o
```
gcc -I/usr/src/kernels/$(uname -r)/include/uapi/ -I/usr/src/kernels/$(uname -r)/include/ -I/usr/include/bpf/ -c minimal.c -o minimal.o
```

### 6. 链接成为可执行程序minimal
```
gcc minimal.o -lbpf -lelf -lz -o minimal
```