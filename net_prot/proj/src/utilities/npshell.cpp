// #include <format>
#include <regex>

#include "npshell.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#define SOCKET_PATH "/tmp/net_prot_socket"

namespace
{
    const std::regex ipv4_regex(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2}))");
    const std::regex ipv4_port_regex(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,5}))");
    const std::regex ipv6_regex(R"(([0-9a-fA-F:]+)\/(\d{1,3}))");
    const std::regex ipv6_port_regex(R"(([0-9a-fA-F:]+)\/(\d{1,5}))");
    const std::regex port_regex(R"(\d{1,5})");
    std::vector<std::string> default_isolation_paths {
        "/usr/sbin/sshd",
        "/usr/sbin/avahi-daemon",
        "/usr/lib/systemd/systemd-resolved",
        "/usr/sbin/NetworkManager",
        "/home/ayush/.vscode-server/code-384ff7382de624fb94dbaf6da11977bba1ecd427",
        "/home/ayush/.vscode-server/cli/servers/Stable-384ff7382de624fb94dbaf6da11977bba1ecd427/server/node",
        "/opt/microsoft/mdatp/sbin/wdavdaemon",
        "/opt/microsoft/mdatp/sbin/telemetryd_v2",
        "/opt/microsoft/mdatp/sbin/wdavdaemonclient"
    };
    
    void handle_client(int client_fd) 
    {
        struct np_shell::sock_data received_data;
        if (recv(client_fd, &received_data, sizeof(received_data), 0) < 0) {
            perror("recv");
            close(client_fd);
            return;
        }

        // Handle data
        utils::net_prot_utils::configure_isolation(received_data.isolation_setup);

        // Clean up
        close(client_fd);
    }

    void socket_server() {
        int server_fd;
        struct sockaddr_un addr;

        // Create socket
        server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_fd < 0) {
            perror("socket");
            exit(EXIT_FAILURE);
        }

        // Bind socket to a path
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
        unlink(SOCKET_PATH); // Remove any existing socket

        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        // Listen for connections
        if (listen(server_fd, 5) < 0) {
            perror("listen");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        while (true) 
        {
            // Accept a connection
            int client_fd = accept(server_fd, NULL, NULL);
            if (client_fd < 0) {
                perror("accept");
                close(server_fd);
                exit(EXIT_FAILURE);
            }

            // Handle client in a new thread
            std::thread(handle_client, client_fd).detach();
        }

        // Clean up
        close(server_fd);
        unlink(SOCKET_PATH);
    }
}

void np_shell::setup_np_shell()
{
    for (auto path : default_isolation_paths)
    {
        utils::net_prot_utils::add_isolation_path(path);
    }
    utils::net_prot_utils::reset_isolated_pid_map();
    std::thread(socket_server).detach();
    while(1)
    {
        std::string input;
        std::cout << "> ";
        std::getline(std::cin, input);
        
        if (input == "exit")
        {
            break;
        }
        else if (input.compare(0, 12, "block v4 ips") == 0)
        {
            std::smatch match;
            std::string::const_iterator searchStart(input.cbegin());
            while (std::regex_search(searchStart, input.cend(), match, ipv4_regex)) 
            {
                std::cout << "blocking connections for ip: " << match[0] << std::endl;
                utils::net_prot_utils::block_ip_util(match[0].str(), std::stoi(match[2]));
                searchStart = match.suffix().first;
            }
        }
        else if (input.compare(0, 14, "unblock v4 ips") == 0)
        {
            std::smatch match;
            std::string::const_iterator searchStart(input.cbegin());
            while (std::regex_search(searchStart, input.cend(), match, ipv4_regex)) 
            {
                std::cout << "unblocking connections for ip: " << match[0] << std::endl;
                utils::net_prot_utils::unblock_ip_util(match[0].str(), std::stoi(match[2]));
                searchStart = match.suffix().first;
            }
        }
        else if (input.compare(0, 12, "block v6 ips") == 0)
        {
            std::smatch match;
            std::string::const_iterator searchStart(input.cbegin());
            while (std::regex_search(searchStart, input.cend(), match, ipv6_regex)) 
            {
                std::cout << "blocking connections for ip: " << match[0] << "/" << std::stoi(match[1]) << std::endl;
                utils::net_prot_utils::block_ip_util(match[0].str(), std::stoi(match[1]));
                searchStart = match.suffix().first;
            }
        }
        else if (input.compare(0, 14, "unblock v6 ips") == 0)
        {
            std::smatch match;
            std::string::const_iterator searchStart(input.cbegin());
            while (std::regex_search(searchStart, input.cend(), match, ipv6_regex)) 
            {
                std::cout << "unblocking connections for ip: " << match[0] << "/" << std::stoi(match[1]) << std::endl;
                utils::net_prot_utils::unblock_ip_util(match[0].str(), std::stoi(match[1]));
                searchStart = match.suffix().first;
            }
        }
        else if (input.compare(0, 11, "block ports") == 0)
        {
            std::smatch match;
            std::string::const_iterator searchStart(input.cbegin());
            while (std::regex_search(searchStart, input.cend(), match, port_regex)) 
            {
                std::cout << "blocking connections for port: " << std::stoi(match.str()) << std::endl;
                utils::net_prot_utils::block_port_util(std::stoi(match.str()));
                searchStart = match.suffix().first;
            }
        }
        else if (input.compare(0, 13, "unblock ports") == 0)
        {
            std::smatch match;
            std::string::const_iterator searchStart(input.cbegin());
            while (std::regex_search(searchStart, input.cend(), match, port_regex)) 
            {
                std::cout << "unblocking connections for port: " << std::stoi(match.str()) << std::endl;
                utils::net_prot_utils::unblock_port_util(std::stoi(match.str()));
                searchStart = match.suffix().first;
            }
        }
        else if (input.compare(0, 17, "block domain name") == 0)
        {
            std::string prefix = "block domain name ";
            size_t pos = input.find(prefix);
            if (pos != std::string::npos) 
            {
                std::string domain = input.substr(pos + prefix.length());
                std::cout << "blocking domain name: " << domain << std::endl;
                utils::net_prot_utils::block_domain_util(domain);
            } 
            else
                std::cout << "retry :(" << std::endl;
        }
        else if (input.compare(0, 19, "unblock domain name") == 0)
        {
            std::string prefix = "unblock domain name ";
            size_t pos = input.find(prefix);
            if (pos != std::string::npos) 
            {
                std::string domain = input.substr(pos + prefix.length());
                std::cout << "unblocking domain name: " << domain << std::endl;
                utils::net_prot_utils::unblock_domain_util(domain);
            } 
            else
                std::cout << "retry :(" << std::endl;
        }
        else if (input.compare(0, 15, "isolation start") == 0)
        {
            //change config
            utils::net_prot_utils::configure_isolation(true);
            
        }
        else if (input.compare(0, 13, "isolation end") == 0)
        {
            //change config
            utils::net_prot_utils::configure_isolation(false);
        }
        else if (input.compare(0, 26, "isolation add process path") == 0)
        {
            //change isolation_paths and parse proc file to modify isolation_pids - fix O(n^2)
            std::string prefix = "isolation add process path ";
            size_t pos = input.find(prefix);
            if (pos != std::string::npos) 
            {
                std::string path = input.substr(pos + prefix.length());
                std::cout << "adding isolation for path: " << path << std::endl;
                utils::net_prot_utils::add_isolation_path(path);
                utils::net_prot_utils::reset_isolated_pid_map();
            } 
            else
                std::cout << "retry :(" << std::endl;
        }
        else if (input.compare(0, 29, "isolation remove process path") == 0)
        {
            //change isolation_paths and parse proc file to modify isolation_pids - fix O(n^2)
            std::string prefix = "isolation remove process path ";
            size_t pos = input.find(prefix);
            if (pos != std::string::npos) 
            {
                std::string path = input.substr(pos + prefix.length());
                std::cout << "removeing isolation for path: " << path << std::endl;
                utils::net_prot_utils::remove_isolation_path(path);
                utils::net_prot_utils::reset_isolated_pid_map();
            } 
            else
                std::cout << "retry :(" << std::endl;
        }
        else if (input.compare(0, 28, "setup redirection connection") == 0) // setup redirection connection v4 169.254.4.2/5001 192.168.1.1/5001
        {
            std::istringstream iss(input.substr(29));
            std::string version;
            iss >> version;
            
            if (version == "v4")
            {
                std::smatch match;
                std::string::const_iterator searchStart(input.cbegin());
                std::vector<struct redirection_endpoint_mac> redirection_endpoints;
                while (std::regex_search(searchStart, input.cend(), match, ipv4_port_regex)) 
                {
                    redirection_endpoints.emplace_back(utils::net_specific::get_redirection_endpoint(match[1], std::stoi(match[2])));
                    searchStart = match.suffix().first;
                }
                if (redirection_endpoints.size() != 2)
                {
                    std::cout << "retry :(" << std::endl;
                }
                else
                {
                    utils::net_prot_utils::add_honeypot_endpoint(redirection_endpoints[0], redirection_endpoints[1]);
                }
            }
            else if (version == "v6")
            {
                std::smatch match;
                std::string::const_iterator searchStart(input.cbegin());
                std::vector<struct redirection_endpoint_mac> redirection_endpoints;
                while (std::regex_search(searchStart, input.cend(), match, ipv6_port_regex)) 
                {
                    redirection_endpoints.emplace_back(utils::net_specific::get_redirection_endpoint(match[1], std::stoi(match[2])));
                    searchStart = match.suffix().first;
                }
                if (redirection_endpoints.size() != 2)
                {
                    std::cout << "retry :(" << std::endl;
                }
                else
                {
                    utils::net_prot_utils::add_honeypot_endpoint(redirection_endpoints[0], redirection_endpoints[1]);
                }
            }
            else
            {
                std::cout << "retry :(" << std::endl;
            }
        }
        else if (input.compare(0, 16, "add malicious ip") == 0) // add malicious ip v4 169.254.2.2/0
        {
            ip_lpm_key ip_key;
            std::istringstream iss(input.substr(17));
            std::string version;
            iss >> version;

            if (version == "v4")
            {
                std::smatch match;
                std::string::const_iterator searchStart(input.cbegin());
                while (std::regex_search(searchStart, input.cend(), match, ipv4_regex)) 
                {
                    ip_key = utils::common::get_blocking_ip_key(match[0], std::stoi(match[2]));
                    std::cout << "adding malicious ip: " 
                    << int(ip_key.addr.addr.ipv4[0]) << "." << int(ip_key.addr.addr.ipv4[1]) << "." << int(ip_key.addr.addr.ipv4[2]) << "." << int(ip_key.addr.addr.ipv4[3])
                    << "with subnet: " << match[2] << ", " << int(ip_key.prefix_len) << std::endl;
                    searchStart = match.suffix().first;
                }
            }
            else if (version == "v6")
            {
                std::smatch match;
                std::string::const_iterator searchStart(input.cbegin());
                while (std::regex_search(searchStart, input.cend(), match, ipv6_regex)) 
                {
                    ip_key = utils::common::get_blocking_ip_key(match[0], std::stoi(match[1]));
                    std::cout << "adding malicious ip: " 
                    << int(ip_key.addr.addr.ipv6[0]) << "." << int(ip_key.addr.addr.ipv6[1]) << "." << int(ip_key.addr.addr.ipv6[2]) << "." << int(ip_key.addr.addr.ipv6[3])
                    << std::endl;
                    searchStart = match.suffix().first;
                }
            }
            else
            {
                std::cout << "retry :(" << std::endl;
            }

            utils::net_prot_utils::configure_ip_for_redirection(ip_key, true);
        }
        else if (input.compare(0, 19, "remove malicious ip") == 0)
        {
            ip_lpm_key ip_key;
            std::istringstream iss(input.substr(20));
            std::string version;
            iss >> version;

            if (version == "v4")
            {
                std::smatch match;
                std::string::const_iterator searchStart(input.cbegin());
                while (std::regex_search(searchStart, input.cend(), match, ipv4_regex)) 
                {
                    ip_key = utils::common::get_blocking_ip_key(match[0], std::stoi(match[2]));
                    std::cout << "removing malicious ip: " 
                    << int(ip_key.addr.addr.ipv4[0]) << "." << int(ip_key.addr.addr.ipv4[1]) << "." << int(ip_key.addr.addr.ipv4[2]) << "." << int(ip_key.addr.addr.ipv4[3])
                    << std::endl;
                    searchStart = match.suffix().first;
                }
            }
            else if (version == "v6")
            {
                std::smatch match;
                std::string::const_iterator searchStart(input.cbegin());
                while (std::regex_search(searchStart, input.cend(), match, ipv6_regex)) 
                {
                    ip_key = utils::common::get_blocking_ip_key(match[0], std::stoi(match[1]));
                    std::cout << "removing malicious ip: " 
                    << int(ip_key.addr.addr.ipv6[0]) << "." << int(ip_key.addr.addr.ipv6[1]) << "." << int(ip_key.addr.addr.ipv6[2]) << "." << int(ip_key.addr.addr.ipv6[3])
                    << std::endl;
                    searchStart = match.suffix().first;
                }
            }
            else
            {
                std::cout << "retry :(" << std::endl;
            }

            utils::net_prot_utils::configure_ip_for_redirection(ip_key, false);
        }
        else
        {
            std::cout << "retry :(" << std::endl;
        }

    }
    utils::net_prot_utils::running = false;
}