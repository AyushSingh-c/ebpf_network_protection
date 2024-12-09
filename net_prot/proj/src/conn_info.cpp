#include "src/utilities/npshell.h"

#include <optional>
#include <thread>
#include <libelf.h>
#include <fcntl.h>
#include <gelf.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// find / -name '*libssl*' -type f 2>/dev/null -exec file {} \; | grep ELF
struct ssl_lib_info
{
    std::string ssl_path;
    uint64_t ssl_read_offset = 0x365b0;          // sudo objdump -T /lib/x86_64-linux-gnu/libssl.so.3 | grep SSL_read
    uint64_t ssl_write_offset = 0x36b20;         // sudo objdump -T /lib/x86_64-linux-gnu/libssl.so.3 | grep SSL_write
    uint64_t ssl_do_handshake_offset = 0x38960;  // sudo objdump -T /lib/x86_64-linux-gnu/libssl.so.3 | grep SSL_do_handshake
};

uint64_t get_symbol_offsets(const char* elf_path, const char* symbol_name) 
{
    if (elf_version(EV_CURRENT) == EV_NONE) {
        std::cerr << "ELF library initialization failed." << std::endl;
        return 0;
    }

    int fd = open(elf_path, O_RDONLY, 0);
    if (fd < 0) {
        std::cerr << "Failed to open ELF file." << std::endl;
        return 0;
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) {
        std::cerr << "elf_begin() failed." << std::endl;
        close(fd);
        return 0;
    }

    Elf_Scn* section = nullptr;
    GElf_Shdr section_header;
    while ((section = elf_nextscn(elf, section)) != nullptr) {
        gelf_getshdr(section, &section_header);
        if (section_header.sh_type == SHT_SYMTAB || section_header.sh_type == SHT_DYNSYM) {
            Elf_Data* data = elf_getdata(section, nullptr);
            int symbol_count = section_header.sh_size / section_header.sh_entsize;
            for (int i = 0; i < symbol_count; ++i) {
                GElf_Sym symbol;
                gelf_getsym(data, i, &symbol);
                const char* name = elf_strptr(elf, section_header.sh_link, symbol.st_name);
                if (name && std::strcmp(name, symbol_name) == 0) {
                    elf_end(elf);
                    close(fd);
                    return symbol.st_value;
                }
            }
        }
    }

    std::cerr << "Symbol not found." << std::endl;
    elf_end(elf);
    close(fd);
    return 0;
}

bool load_fentries(utils::net_prot_utils& prot)
{
    if (utils::bpf::load_fentry_module(prot.obj, "fentry_dev_queue_xmit") != 0)
    {
        std::cout << "Unable to load bpf fentry_dev_queue_xmit module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }

    // kernel check - for 5.17 it worked not above i think
    // if (utils::bpf::load_fentry_module(prot.obj, "fentry_netif_receive_skb") != 0)
    // {
    //     std::cout << "Unable to load bpf fentry_netif_receive_skb module" << std::endl;
	//     bpf_object__close(prot.obj);
    //     return false;
    // }

	if (utils::bpf::load_fentry_module(prot.obj, "fentry_tcp_connect") != 0)
    {
        std::cout << "Unable to load bpf fentry_tcp_connect module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }

	if (utils::bpf::load_fentry_module(prot.obj, "fentry_tcp_conn_request") != 0)
    {
        std::cout << "Unable to load bpf fentry_tcp_conn_request module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }

	if (utils::bpf::load_fentry_module(prot.obj, "fentry_tcp_close") != 0)
    {
        std::cout << "Unable to load bpf fentry_tcp_close module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }

	if (utils::bpf::load_fentry_module(prot.obj, "fentry_tcp_fin") != 0)
    {
        std::cout << "Unable to load bpf fentry_tcp_fin module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }
    return true;
}

bool load_kprobes(utils::net_prot_utils& prot)
{
    if (utils::bpf::load_kprobe_module(prot.obj, "kprobe_dev_queue_xmit", "__dev_queue_xmit") != 0)
    {
        std::cout << "Unable to load bpf kprobe_dev_queue_xmit module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }

    // kernel check - for 5.17 it worked not above i think
    // if (utils::bpf::load_kprobe_module(prot.obj, "kprobe_netif_receive_skb", "__netif_receive_skb_core") != 0)
    // {
    //     std::cout << "Unable to load bpf kprobe_netif_receive_skb module" << std::endl;
	//     bpf_object__close(prot.obj);
    //     return false;
    // }

	if (utils::bpf::load_kprobe_module(prot.obj, "kprobe_tcp_connect", "tcp_connect") != 0)
    {
        std::cout << "Unable to load bpf kprobe_tcp_connect module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }

	if (utils::bpf::load_kprobe_module(prot.obj, "kprobe_tcp_conn_request", "tcp_conn_request") != 0)
    {
        std::cout << "Unable to load bpf kprobe_tcp_conn_request module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }

	if (utils::bpf::load_kprobe_module(prot.obj, "kprobe_tcp_close", "tcp_close") != 0)
    {
        std::cout << "Unable to load bpf kprobe_tcp_close module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }

	if (utils::bpf::load_kprobe_module(prot.obj, "kprobe_tcp_fin", "tcp_fin") != 0)
    {
        std::cout << "Unable to load bpf kprobe_tcp_fin module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }
    return true;
}

bool load_hooks(utils::net_prot_utils& prot, std::vector<bpf_tc_hook>& tc_hooks, bool should_load_tc)
{
	std::string filename = "/home/ayush/WD.Internal.PoC/Linux/ebpf/net_prot/proj/bin/src/kern_code/ebpf_wrapper_tc_uprobe_fentry_trace_lsm.bpf.o";
	// std::string filename = "/home/ayush/WD.Internal.PoC/Linux/ebpf/net_prot/proj/bin/src/kern_code/ebpf_wrapper_tc_uprobe_kprobe_trace_lsm.bpf.o";

	prot.obj = utils::bpf::load_ebpf_obj(filename);
    if (prot.obj == NULL)
    {
        std::cout << "Unable to load bpf object" << std::endl;
        return false;
    }

    if (load_fentries(prot) == false)
    {
        return false;
    }
    // if (load_kprobes(prot) == false)
    // {
    //     return false;
    // }

	if (utils::bpf::load_tracepoint_module(prot.obj, "handle_fork", "sched", "sched_process_fork") != 0)
    {
        std::cout << "Unable to load bpf handle_fork/sched/sched_process_fork module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }

	if (utils::bpf::load_tracepoint_module(prot.obj, "handle_exec", "sched", "sched_process_exec") != 0)
    {
        std::cout << "Unable to load bpf handle_fork/sched/sched_process_exec module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }

	if (utils::bpf::load_tracepoint_module(prot.obj, "handle_exit", "sched", "sched_process_exit") != 0)
    {
        std::cout << "Unable to load bpf handle_fork/sched/sched_process_exit module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }

    if (utils::bpf::load_tracepoint_module(prot.obj, "trace_netif_receive_skb", "net", "netif_receive_skb") != 0)
    {
        std::cout << "Unable to load bpf trace_netif_receive_skb/net/netif_receive_skb module" << std::endl;
	    bpf_object__close(prot.obj);
        return false;
    }

    int interface_list[4] = {1, 2, 3, 4};
	for (auto interface_seq : interface_list)
	{
		auto temp = utils::bpf::load_tc_for_interface(prot.obj, interface_seq, should_load_tc);
		tc_hooks.emplace_back(std::move(temp[0]));
		tc_hooks.emplace_back(std::move(temp[1])); 
	}

    struct bpf_program *send_sock_lsm_prog;
    send_sock_lsm_prog = bpf_object__find_program_by_name(prot.obj, "bpf_socket_sendmsg");
    if(!bpf_program__attach_lsm(send_sock_lsm_prog))
    {
        fprintf(stderr, "ERROR: attaching kprobe to bpf_socket_sendmsg failed\n");
		bpf_object__close(prot.obj);
        return false;
    }

    struct bpf_program *recv_sock_lsm_prog;
    recv_sock_lsm_prog = bpf_object__find_program_by_name(prot.obj, "bpf_socket_recvmsg");
    if(!bpf_program__attach_lsm(recv_sock_lsm_prog))
    {
        fprintf(stderr, "ERROR: attaching kprobe to bpf_socket_recvmsg failed\n");
		bpf_object__close(prot.obj);
        return false;
    }

    

    std::vector<struct ssl_lib_info> ssl_libs {
        {
            "/usr/lib/x86_64-linux-gnu/libssl.so.3",
            get_symbol_offsets("/usr/lib/x86_64-linux-gnu/libssl.so.3", "SSL_read"),
            get_symbol_offsets("/usr/lib/x86_64-linux-gnu/libssl.so.3", "SSL_write"),
            get_symbol_offsets("/usr/lib/x86_64-linux-gnu/libssl.so.3", "SSL_do_handshake")
        },
        {
            "/usr/lib/x86_64-linux-gnu/libnspr4.so",
            get_symbol_offsets("/usr/lib/x86_64-linux-gnu/libnspr4.so", "PR_Read"),
            get_symbol_offsets("/usr/lib/x86_64-linux-gnu/libnspr4.so", "PR_Write"),
            0
        },
        {
            "/usr/lib/x86_64-linux-gnu/libnspr4.so",
            get_symbol_offsets("/usr/lib/x86_64-linux-gnu/libnspr4.so", "PR_Recv"),
            get_symbol_offsets("/usr/lib/x86_64-linux-gnu/libnspr4.so", "PR_Send"),
            0
        },
        {
            "/lib/x86_64-linux-gnu/libnspr4.so",
            get_symbol_offsets("/lib/x86_64-linux-gnu/libnspr4.so", "PR_Read"),
            get_symbol_offsets("/lib/x86_64-linux-gnu/libnspr4.so", "PR_Write"),
            0
        },
        {
            "/lib/x86_64-linux-gnu/libnspr4.so",
            get_symbol_offsets("/lib/x86_64-linux-gnu/libnspr4.so", "PR_Recv"),
            get_symbol_offsets("/lib/x86_64-linux-gnu/libnspr4.so", "PR_Send"),
            0
        },
        {
            "/snap/firefox/4793/usr/lib/firefox/libnspr4.so",
            get_symbol_offsets("/snap/firefox/4793/usr/lib/firefox/libnspr4.so", "PR_Read"),
            get_symbol_offsets("/snap/firefox/4793/usr/lib/firefox/libnspr4.so", "PR_Write"),
            0
        },
        {
            "/snap/firefox/4793/usr/lib/firefox/libnspr4.so",
            get_symbol_offsets("/snap/firefox/4793/usr/lib/firefox/libnspr4.so", "PR_Recv"),
            get_symbol_offsets("/snap/firefox/4793/usr/lib/firefox/libnspr4.so", "PR_Send"),
            0
        },
        {
            "/snap/firefox/5134/usr/lib/firefox/libnspr4.so",
            get_symbol_offsets("/snap/firefox/5134/usr/lib/firefox/libnspr4.so", "PR_Read"),
            get_symbol_offsets("/snap/firefox/5134/usr/lib/firefox/libnspr4.so", "PR_Write"),
            0
        },
        {
            "/snap/firefox/5134/usr/lib/firefox/libnspr4.so",
            get_symbol_offsets("/snap/firefox/5134/usr/lib/firefox/libnspr4.so", "PR_Recv"),
            get_symbol_offsets("/snap/firefox/5134/usr/lib/firefox/libnspr4.so", "PR_Send"),
            0
        },
        {
            "/snap/core22/1621/usr/lib/x86_64-linux-gnu/libssl.so.3",
            get_symbol_offsets("/snap/core22/1621/usr/lib/x86_64-linux-gnu/libssl.so.3", "SSL_read"),
            get_symbol_offsets("/snap/core22/1621/usr/lib/x86_64-linux-gnu/libssl.so.3", "SSL_write"),
            get_symbol_offsets("/snap/core22/1621/usr/lib/x86_64-linux-gnu/libssl.so.3", "SSL_do_handshake")
        },
        {
            "/snap/core22/1663/usr/lib/x86_64-linux-gnu/libssl.so.3",
            get_symbol_offsets("/snap/core22/1663/usr/lib/x86_64-linux-gnu/libssl.so.3", "SSL_read"),
            get_symbol_offsets("/snap/core22/1663/usr/lib/x86_64-linux-gnu/libssl.so.3", "SSL_write"),
            get_symbol_offsets("/snap/core22/1663/usr/lib/x86_64-linux-gnu/libssl.so.3", "SSL_do_handshake")
        },
        {
            "/snap/gnome-42-2204/176/usr/lib/x86_64-linux-gnu/libnspr4.so",
            get_symbol_offsets("/snap/gnome-42-2204/176/usr/lib/x86_64-linux-gnu/libnspr4.so", "PR_Read"),
            get_symbol_offsets("/snap/gnome-42-2204/176/usr/lib/x86_64-linux-gnu/libnspr4.so", "PR_Write"),
            0
        },
        {
            "/snap/gnome-42-2204/176/usr/lib/x86_64-linux-gnu/libnspr4.so",
            get_symbol_offsets("/snap/gnome-42-2204/176/usr/lib/x86_64-linux-gnu/libnspr4.so", "PR_Recv"),
            get_symbol_offsets("/snap/gnome-42-2204/176/usr/lib/x86_64-linux-gnu/libnspr4.so", "PR_Send"),
            0
        }
    };
    for (auto ssl_lib: ssl_libs)
    {
        std::cout << "openssl lib path: " << ssl_lib.ssl_path << " SSL_read offset: " << ssl_lib.ssl_read_offset << " SSL_write offset: " << ssl_lib.ssl_write_offset << " SSL_do_handshake offset: " << ssl_lib.ssl_do_handshake_offset << std::endl;
        if (utils::bpf::load_uprobe_on_binary(prot.obj, ssl_lib.ssl_path, ssl_lib.ssl_read_offset, "handle_ssl_rw_enter", false) != 0)
        {
            std::cout << "Unable to load bpf handle_ssl_rw_enter module as uprobe to openssl" << std::endl;
            bpf_object__close(prot.obj);
            return false;
        }
        
        if (utils::bpf::load_uprobe_on_binary(prot.obj, ssl_lib.ssl_path, ssl_lib.ssl_read_offset, "handle_ssl_read_exit", true) != 0)
        {
            std::cout << "Unable to load bpf handle_ssl_read_exit module as uprobe to openssl" << std::endl;
            bpf_object__close(prot.obj);
            return false;
        }

        if (utils::bpf::load_uprobe_on_binary(prot.obj, ssl_lib.ssl_path, ssl_lib.ssl_write_offset, "handle_ssl_rw_enter", false) != 0)
        {
            std::cout << "Unable to load bpf handle_ssl_rw_enter module as uprobe to openssl" << std::endl;
            bpf_object__close(prot.obj);
            return false;
        }

        if (utils::bpf::load_uprobe_on_binary(prot.obj, ssl_lib.ssl_path, ssl_lib.ssl_write_offset, "handle_ssl_write_exit", true) != 0)
        {
            std::cout << "Unable to load bpf handle_ssl_write_exit module as uprobe to openssl" << std::endl;
            bpf_object__close(prot.obj);
            return false;
        }

        if (ssl_lib.ssl_do_handshake_offset !=0 && utils::bpf::load_uprobe_on_binary(prot.obj, ssl_lib.ssl_path, ssl_lib.ssl_do_handshake_offset, "handle_ssl_do_handshake_entry", false) != 0)
        {
            std::cout << "Unable to load bpf handle_ssl_do_handshake_entry module as uprobe to openssl" << std::endl;
            bpf_object__close(prot.obj);
            return false;
        }

        if (ssl_lib.ssl_do_handshake_offset !=0 && utils::bpf::load_uprobe_on_binary(prot.obj, ssl_lib.ssl_path, ssl_lib.ssl_do_handshake_offset, "handle_ssl_do_handshake_exit", true) != 0)
        {
            std::cout << "Unable to load bpf handle_ssl_do_handshake_exit module as uprobe to openssl" << std::endl;
            bpf_object__close(prot.obj);
            return false;
        }
    }

	return true;
}

void join_optional_threads(std::optional<std::thread>& t)
{
	if (t->joinable()) 
	{
        t->join();
    }
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv << "tc ok?" << std::endl;
        return 1;
    }
	class utils::net_prot_utils prot{};
	prot.init();

	std::cout << "printing in file " << prot.get_output_file_path() << std::endl;
	
	std::optional<std::thread> pkt_info_thread, conn_info_thread, conn_data_thread, proc_info_thread, ssl_data_thread;

	std::vector<bpf_tc_hook> tc_hooks;
	if (!load_hooks(prot, tc_hooks, std::atoi(argv[1]) == 1))
	{
		std::cout << "Unable to load all the hooks. Exiting......." << std::endl;
		goto cleanup;
	}

	pkt_info_thread.emplace(prot.start_ring_buff_polling, "/sys/fs/bpf/pkt_info_ring_buff", prot.handle_event_pkt_info);
	conn_info_thread.emplace(prot.start_ring_buff_polling, "/sys/fs/bpf/connection_setup_ring_buff", prot.handle_event_conn_setup);
	conn_data_thread.emplace(prot.start_ring_buff_polling, "/sys/fs/bpf/pkt_data_ring_buff", prot.handle_event_pkt_data);
	proc_info_thread.emplace(prot.start_ring_buff_polling, "/sys/fs/bpf/proc_info_buff", prot.handle_proc_info);
	ssl_data_thread.emplace(prot.start_ring_buff_polling, "/sys/fs/bpf/perf_SSL_events", prot.handle_event_ssl_data);

	np_shell::setup_np_shell();

	join_optional_threads(pkt_info_thread);
	join_optional_threads(conn_data_thread);
	join_optional_threads(conn_info_thread);
	join_optional_threads(proc_info_thread);
	join_optional_threads(ssl_data_thread);

cleanup:
	for (auto hook : tc_hooks)
		bpf_tc_hook_destroy(&hook);
	utils::bpf::unpin_maps(std::vector<std::string>{"connection_config", "connection_setup_ring_buff", "pkt_info_ring_buff", "pkt_data_ring_buff", "blocked_ips", "blocked_ports", "isolation_pids", "proc_info_buff", "config_map", "perf_SSL_events", "SSL_carry_info", "redirect_ips", "redirect_endpoints", "reverse_redirect_endpoints", "isolation_network_tuple"});
	bpf_object__close(prot.obj);	
	

	return 0;
}
