#ifndef _OPTIONS_H_
#define _OPTIONS_H_

#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <iostream>
#include <set>
#include <vector>

using std::string;
using std::vector;

// these types are needed for boost::program_options validation mechanism
struct uid_value {
    uid_value() = default;
    explicit uid_value(uid_t u) : uid(u) {}
    operator uid_t () const { return uid; }
    uid_t uid = 0;
};
struct gid_value {
    gid_value() = default;
    explicit gid_value(gid_t g) : gid(g) {}
    operator gid_t () const { return gid; }
    gid_t gid = 0;
};


struct server_parameters {
    static constexpr const char * def_config_file = "/etc/resmtp/resmtp.conf";
    static constexpr const char * def_pid_file = "/var/run/resmtp/resmtp.pid";

    // [proto://]host_name[:port][/url]
    // [proto://]host_name[:port]
    struct remote_point {
        std::string m_proto;
        std::string m_host_name;
        unsigned int m_port;
        std::string m_url;
    };

    // host_name[:weight]
    struct backend_host {
        backend_host(std::string s, uint32_t w) : host_name(s), weight(w) {}
        std::string host_name;
        uint32_t weight;            // 0..100; 0 - off, 100 - max
    };

    bool m_foreground;

    uint32_t m_log_level;

    uint32_t m_worker_count;

    string m_pid_file;

    uid_value m_uid;
    gid_value m_gid;

    vector<string> m_listen_points;
    vector<string> m_ssl_listen_points;

    string mon_listen_point;

    // max number of incoming connections
    uint32_t m_connection_count_limit;
    // max number of incoming connections per IP
    uint32_t m_client_connection_count_limit;

    bool m_use_local_relay;
    remote_point m_local_relay_host;

    std::vector<std::string> backend_hosts_str;
    // initialized from backend_hosts_str
    std::vector<backend_host> backend_hosts;
    // all backend hosts have the same TCP port
    uint16_t backend_port;

    std::string m_smtp_banner;

    //
    // DNS settings
    //
    bool m_use_system_dns_servers;
    std::string m_custom_dns_servers;
    // actual values, not directly from config file
    std::vector<std::string> m_dns_servers;

    // check if client doesn't send anything before greeting
    bool m_socket_check;

    // tarpitting delay
    uint32_t m_tarpit_delay_seconds;

    // DNS BL
    bool m_rbl_active;
    std::string m_rbl_hosts;

    // DNS WL
    std::string m_dnswl_host;

    // maximum number of recipients
    uint32_t m_max_rcpt_count;

    // SPF check timeout
    time_t m_spf_timeout;

    // DKIM check timeout
    time_t m_dkim_timeout;

    time_t frontend_cmd_timeout;
    time_t frontend_data_timeout;

    time_t backend_connect_timeout;
    time_t backend_cmd_timeout;
    time_t backend_data_timeout;

    uint32_t m_message_size_limit;

//    bool m_remove_headers;
//    std::string m_remove_headers_list;
//    boost::unordered_set<std::string> m_remove_headers_set;

    // remove extra CRLF at the beginning of message DATA?
    bool m_remove_extra_cr;

    // config: number of allowed recipients
    std::string m_ip_config_file;

    bool m_use_tls;
    std::string m_tls_cert_file;
    std::string m_tls_key_file;

    // max number of errors an SMTP client allowed to make
    uint32_t m_hard_error_limit;

    bool parse_config(int _argc, char* _argv[], std::ostream& _out) noexcept;
    bool init_dns_settings() noexcept;
    bool init_backend_hosts_settings() noexcept;
};

#endif
