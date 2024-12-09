
#include "src/kern_code/crypto_uprobe.bpf.c"
// #include "src/kern_code/fentry_traffic.bpf.c"
#include "src/kern_code/kprobe_traffic.bpf.c"
#include "src/kern_code/security_module.bpf.c"
#include "src/kern_code/tracepoint_sched.bpf.c"
#include "src/kern_code/tracepoint_net.bpf.c"
#include "src/kern_code/traffic_control.bpf.c"

char _license[] SEC("license") = "GPL";
