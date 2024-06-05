# poc-http3-proxy

## demo
```
./http3-proxy
./client.exe -insecure https://mitmproxy.org:443
```


## Berore running
```
sysctl -w net.core.rmem_max=7500000
sysctl -w net.core.wmem_max=7500000
```

## use eBPF to redirect sendmsg4 to local proxy
```
logs:
cat /sys/kernel/debug/tracing/trace_pipe

sudo bpftool prog show pinned "/sys/fs/bpf/bpf_connect"
sudo bpftool prog show

load:
clang -O2 -target bpf -c bpf/cgroup_inet4_connect.c -o bpf/cgroup_inet4_connect.o
sudo bpftool prog load bpf/cgroup_inet4_connect.o /sys/fs/bpf/bpf_connect
#sudo bpftool prog load cgroup_inet4_connect.o /sys/fs/bpf/bpf_connect  map name cookie_original_dst pinned /sys/fs/bpf/cookie_original_dst
sudo bpftool cgroup attach "/sys/fs/cgroup/" sendmsg4 pinned "/sys/fs/bpf/bpf_connect"
#sudo bpftool cgroup attach "/sys/fs/cgroup/my_cgroup" sendmsg4 pinned "/sys/fs/bpf/bpf_connect"
#sudo echo 89427 > /sys/fs/cgroup/my_cgroup/cgroup.procs

unload:
sudo bpftool cgroup detach "/sys/fs/cgroup/" sendmsg4 pinned "/sys/fs/bpf/bpf_connect"
#sudo bpftool cgroup detach "/sys/fs/cgroup/my_cgroup" sendmsg4 pinned "/sys/fs/bpf/bpf_connect"
sudo rm -rf "/sys/fs/bpf/bpf_connect"
```
