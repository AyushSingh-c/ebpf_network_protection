#include "utils.h"

void utils::bpf::list_prog(struct bpf_object *obj)
{
    struct bpf_program *prog_temp;
    bpf_object__for_each_program(prog_temp, obj) 
    {
        const char *prog_name = bpf_program__name(prog_temp);
        printf("Program name: %s\n", prog_name);
    }
}

struct bpf_object* utils::bpf::load_ebpf_obj(std::string filename)
{
    int err;

    struct bpf_object *obj = bpf_object__open_file(filename.c_str(), NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return obj;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return obj;
    }

    utils::bpf::list_prog(obj);

    //setup default config

    int config_map_fd = bpf_object__find_map_fd_by_name(obj, "config_map");
    if (config_map_fd < 0) {
        fprintf(stderr, "Error finding config_map fd\n");
        return obj;
    }

    struct net_prot_config default_value {0, -1};
    int config_index = 0;
    if (bpf_map_update_elem(config_map_fd, &config_index, &default_value, BPF_ANY))
    {
        fprintf(stderr, "Error finding config_map update\n");
        return obj;
    }

    return obj;
}

int utils::bpf::load_fentry_module(struct bpf_object *obj, std::string module_name)
{
    struct bpf_program *fentry_egress_prog = bpf_object__find_program_by_name(obj, module_name.c_str());
    if (!fentry_egress_prog) {
        fprintf(stderr, "Failed to find BPF program by title fentry/__dev_queue_xmit\n");
        return -1;
    }

    int fentry_egress_prog_fd;
    fentry_egress_prog_fd = bpf_program__fd(fentry_egress_prog);
    if (fentry_egress_prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program file descriptor\n");
        return -1;
    }

    struct bpf_link *fentry_egress_link = bpf_program__attach(fentry_egress_prog);
    if (libbpf_get_error(fentry_egress_link)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return -1;
    }

    // printf("Fentry BPF programs loaded and attached successfully\n");
    return 0;
}

int utils::bpf::load_kprobe_module(struct bpf_object *obj, std::string module_name, std::string hook_name)
{
    struct bpf_program *ingress_prog;
    ingress_prog = bpf_object__find_program_by_name(obj, module_name.c_str());
    if (!ingress_prog) {
        fprintf(stderr, "ERROR: finding program kprobe_netif_receive_skb failed\n");
		bpf_object__close(obj);
        return -1;
    }

    if (!bpf_program__attach_kprobe(ingress_prog, false, hook_name.c_str())) {
        fprintf(stderr, "ERROR: attaching kprobe to netif_receive_skb_core failed\n");
		bpf_object__close(obj);
        return -1;
    }

    // printf("Kprobe BPF programs loaded and attached successfully\n");
    return 0;
}

int utils::bpf::load_tracepoint_module(struct bpf_object *obj, std::string module_name, std::string submodule_name, std::string tracepoint_name)
{
    struct bpf_program *tracepoint_prog = bpf_object__find_program_by_name(obj, module_name.c_str());
    if (!tracepoint_prog) {
        fprintf(stderr, "Failed to find BPF program by title tracepoint/..\n");
        return -1;
    }

    int tracepoint_prog_fd;
    tracepoint_prog_fd = bpf_program__fd(tracepoint_prog);
    if (tracepoint_prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program file descriptor\n");
        return -1;
    }

    struct bpf_link *tracepoint_link = bpf_program__attach_tracepoint(tracepoint_prog, submodule_name.c_str(), tracepoint_name.c_str());
    if (libbpf_get_error(tracepoint_link)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return -1;
    }

    return 0;
}

int utils::bpf::load_uprobe_on_binary(struct bpf_object *obj, const std::string& bin_path, const uint64_t& hook_offset, const std::string& module_name, bool is_retprobe)
{
    if (hook_offset == 0)
    {
        // std::cerr << "ERROR: Invalid hook offset" << std::endl;
        return 0;
    }
    struct bpf_program *uprobe_ssl_read_prog = bpf_object__find_program_by_name(obj, module_name.c_str());
    if (!uprobe_ssl_read_prog) 
    {
        std::cerr << "ERROR: Failed to find BPF program" << std::endl;
        return -1;
    }
    struct bpf_link *uprobe_ssl_read_link = bpf_program__attach_uprobe(uprobe_ssl_read_prog, is_retprobe, -1, bin_path.c_str(), hook_offset); 
    if (!uprobe_ssl_read_link) 
    {
        std::cerr << "Failed to attach uprobe" << std::endl;
        return -1;
    }
    return 0;
}

std::vector<bpf_tc_hook> utils::bpf::load_tc_for_interface(struct bpf_object *obj, int interface_seq, bool should_load)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_ingress, .ifindex = interface_seq,
                .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_egress, .ifindex = interface_seq,
                .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_ingress, .handle = 1, .priority = 1);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_egress, .handle = 1, .priority = 1);

    int prog_fd_ingress = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_ingress"));
    if (prog_fd_ingress < 0) {
        fprintf(stderr, "ERROR: finding a program in BPF object file failed\n");
        return {std::move(tc_hook_ingress), std::move(tc_hook_egress)};
    }
    int prog_fd_egress = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_egress"));
    if (prog_fd_egress < 0) {
        fprintf(stderr, "ERROR: finding a program in BPF object file failed\n");
        return {std::move(tc_hook_ingress), std::move(tc_hook_egress)};
    }

    int err = bpf_tc_hook_create(&tc_hook_ingress);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create ingress TC hook: %d\n", err);
        return {std::move(tc_hook_ingress), std::move(tc_hook_egress)};
    }

    if (err == -EEXIST) 
    {
        std::cout << "Qdisc already exists, proceeding with existing qdisc" << std::endl;
    }

    err = bpf_tc_hook_create(&tc_hook_egress);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create egress TC hook: %d\n", err);
        return {std::move(tc_hook_ingress), std::move(tc_hook_egress)};
    }

    if (err == -EEXIST) 
    {
        std::cout << "Qdisc already exists, proceeding with existing qdisc" << std::endl;
    }

    if(should_load)
    {
        tc_opts_ingress.prog_fd = prog_fd_ingress;
        if (bpf_tc_attach(&tc_hook_ingress, &tc_opts_ingress)) {
            fprintf(stderr, "ERROR: attaching BPF program to TC ingress point failed\n");
            return {std::move(tc_hook_ingress), std::move(tc_hook_egress)};
        }

        tc_opts_egress.prog_fd = prog_fd_egress;
        if (bpf_tc_attach(&tc_hook_egress, &tc_opts_egress)) {
            fprintf(stderr, "ERROR: attaching BPF program to TC egress point failed\n");
            return {std::move(tc_hook_ingress), std::move(tc_hook_egress)};
        }
    }
    return {std::move(tc_hook_ingress), std::move(tc_hook_egress)};
}

void utils::bpf::unpin_maps(std::vector<std::string> maps_name)
{
    for (auto name : maps_name)
    {
        std::string ring_buff_path = "/sys/fs/bpf/" + name;
        int ring_buff_fd = bpf_obj_get(ring_buff_path.c_str());
        if (ring_buff_fd > 0) 
        {
            if (unlink(ring_buff_path.c_str()) == -1 || close(ring_buff_fd) == -1)
                std::cout << "Unable to close map" << std::endl;
        }
        else
            std::cout << "no map for u" << std::endl;
    }
}