#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("cgroup/sendmsg4")
int intercept_connect_v4(struct bpf_sock_addr *ctx) {
    // Check if the connection is TCP
    if (ctx->protocol == IPPROTO_TCP) {
        // Print a message for TCP connections
        bpf_printk("Intercepted IPv4 TCP connect to %x:%d\n", ctx->user_ip4, bpf_ntohs(ctx->user_port));


    } else if (ctx->protocol == IPPROTO_UDP) {
        // Print a message for UDP connections
        bpf_printk("Intercepted IPv4 UDP connect to %x:%d\n", ctx->user_ip4, bpf_ntohs(ctx->user_port));

        __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;

        // if (bpf_htons(ctx->user_port) == 8585) {
        if (uid == 1001) {

            // redirect to localhost:8585
            ctx->user_port = bpf_htons(8585);
            ctx->user_ip4 = 0x100007f;
        }
     
    }

    return 1; // Allow the connection
}

char _license[] SEC("license") = "GPL";

