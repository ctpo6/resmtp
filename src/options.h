#ifndef _OPTIONS_H_
#define _OPTIONS_H_

#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "log.h"


namespace r = resmtp;

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
struct log_value {
    log_value() = default;
    explicit log_value(r::log l) : log_(l) {}
    operator r::log() const { return log_; }
    operator int() const { return static_cast<int>(log_); }
    r::log log_ = r::log::notice;
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


    // don't daemonize
    bool m_foreground;

    // value of this variable is mapped to syslog priority
    log_value log_level;

    string m_pid_file;

    // number of SMTP connections worker threads
    uint32_t m_worker_count;

    uid_value m_uid;
    gid_value m_gid;

    // plain SMTP listen point
    // ex.: "0.0.0.0:25"
    vector<string> m_listen_points;
    vector<string> m_ssl_listen_points;

    // monitoring listen point
    // ex: "0.0.0.0:11311"
    string mon_listen_point;

    // max number of incoming connections
    uint32_t m_connection_count_limit;
    // max number of incoming connections per IP
    uint32_t m_client_connection_count_limit;

    bool m_use_local_relay;
    remote_point m_local_relay_host;

    vector<string> backend_hosts_str;
    // initialized from backend_hosts_str
    vector<backend_host> backend_hosts;
    // all backend hosts have the same TCP port
    uint16_t backend_port;

    // spamhaus log file name
    // can be empty
    // ex.: /spool/logs/resmtp/spamhaus.log
    // default: empty
    string spamhaus_log_file;

    // SMTP greeting string
    string m_smtp_banner;

    //
    // DNS settings
    //
    bool m_use_system_dns_servers;
    string m_custom_dns_servers;
    // actual values, not directly from config file
    vector<string> m_dns_servers;

    // check if client doesn't send anything before greeting
    bool m_socket_check;

    // tarpitting delay
    uint32_t m_tarpit_delay_seconds;

    // DNSBL hosts
    vector<string> dnsbl_hosts;
    // DNSWL host
    string dnswl_host;

    // maximum number of recipients
    uint32_t m_max_rcpt_count;

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
    string m_ip_config_file;

    bool m_use_tls;
    string m_tls_cert_file;
    string m_tls_key_file;

    // max number of errors an SMTP client allowed to make
    uint32_t m_hard_error_limit;

    // return: false - program must correctly exit, true - proceed
    // on error throws exception
    bool parse_config(int argc, char* argv[]);

    bool init_dns_settings() noexcept;
    bool init_backend_hosts_settings() noexcept;
};

#endif
