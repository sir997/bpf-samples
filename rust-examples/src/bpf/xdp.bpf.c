#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int pkt_sz = data_end - data;

    // 检查数据包是否包含以太网帧头部
    if (data + sizeof(struct ethhdr) <= data_end)
    {
        struct ethhdr *eth = data;            // 以太网帧头部
        __u16 eth_type = ntohs(eth->h_proto); // 以太网帧类型

        // 如果是IPv4数据包
        if (eth_type == ETH_P_IP)
        {
            // 获取IPv4首部的指针
            void *ip_data = data + sizeof(struct ethhdr);

            // 检查数据包是否包含足够的字节来解析IPv4首部
            if (ip_data + sizeof(struct iphdr) <= data_end)
            {
                struct iphdr *ip = ip_data;      // IPv4首部
                __u32 src_ip = ntohl(ip->saddr); // 源IP地址
                __u32 dst_ip = ntohl(ip->daddr); // 目标IP地址
                bpf_printk("src: %d, dst: %d",src_ip,dst_ip);
            }
        }
    }

    bpf_printk("packet size: %d", pkt_sz);
    return XDP_PASS;
}
