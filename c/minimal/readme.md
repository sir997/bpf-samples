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
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../libbpf/include -I../vmlinux/x86/ -I../blazesym/include -idirafter /usr/lib64/clang/15.0.7/include -idirafter /usr/local/include -idirafter /usr/include -c minimal.bpf.c -o minimal.bpf.o

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

## BPF怎么跟内核交互
eBPF 程序并不能随意调用内核函数，因此，内核定义了一系列的辅助函数，用于 eBPF 程序与内核其他模块进行交互。比如bpf_trace_printk() 就是最常用的一个辅助函数，用于向调试文件系统（/sys/kernel/debug/tracing/trace_pipe）写入调试信息。

从内核 5.13 版本开始，部分内核函数（如  tcp_slow_start()、tcp_reno_ssthresh()  等）也可以被 BPF 程序直接调用了，[链接](https://lwn.net/Articles/856005/)。不过，这些函数只能在 TCP 拥塞控制算法的 BPF 程序中调用，所以本课程不会过多展开。

需要注意的是，并不是所有的辅助函数都可以在 eBPF 程序中随意使用，不同类型的 eBPF 程序所支持的辅助函数是不同的。比如，对于 Hello World 示例这类内核探针（kprobe）类型的 eBPF 程序，你可以在命令行中执行 `bpftool feature probe`来查询当前系统支持的辅助函数列表。

对于这些辅助函数的详细定义，你可以在命令行中执行 man bpf-helpers ，或者参考内核头文件 include/uapi/linux/bpf.h ，来查看它们的详细定义和使用说明。为了方便你掌握，我把常用的辅助函数整理成了一个表格，你可以在需要时参考：
![bpf-helper](docs/img/bpf-helper.webp)

而在 eBPF 程序需要大块存储时，就不能像常规的内核代码那样去直接分配内存了，而是必须通过 BPF 映射（BPF Map）来完成。接下来，我带你看看 BPF 映射的具体原理。