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