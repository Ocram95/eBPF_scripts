Limitation of XDP: it seems it only catches incoming traffic, i.e., from the NIC. I was not
able to catch outgoing packets, so I gave up this approach and moved to TC.

According to the internet:
tc supports symmetric (ingress and egress) program attach, and the advantage of using XDP - not having to allocate packet metadata - doesn't really buy us much here, since we want to pass our packet upstream to the Linux TCP/IP stack. If we were doing some form of firewalling or DDoS mitigation where we were dropping a lot of the received packets, doing that without the overhead of skbuff packet metadata allocation in XDP is ideal.
[https://blogs.oracle.com/linux/notes-on-bpf-6]

tc/eBPF programs on ingress and egress, XDP is ingress onlyCompared to XDP, tc BPF programs can be triggered out of ingress and also egress points in the networking data path as opposed to ingress only in the case of XDP.
[https://liuhangbin.netlify.app/post/ebpf-and-xdp/]

Loading BPF programs in TC:

# sudo tc qdisc add dev eth0 clsact
# sudo tc filter add dev eth0 ingress bpf da obj tc_fl_kern.o sec tc_flowlabel_stats
# sudo tc filter add dev eth0 egress bpf da obj tc_fl_kern.o sec tc_flowlabel_stats
[# sudo tc filter show dev eth0 ingress]
[# sudo tc filter show dev eth0 egress]

To unload BPF programs from TC:

# sudo tc filter del dev eth0 ingress
# sudo tc filter del dev eth0 egress
