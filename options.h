#if !defined(_CONFIG_H_)
#define _CONFIG_H_

#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <iostream>
#include <set>
#include <vector>

#include <boost/asio/ip/tcp.hpp>
#include <boost/unordered_set.hpp>

#include "rc_clients/greylisting.h"

#if defined(HAVE_CONFIG_H)
#include "../config.h"
#endif

struct uid_value
{
  public:
    uid_value () : uid (0) {}
    uid_value (uid_t const& u) : uid (u) {}
    operator uid_t () const { return uid; }
    uid_t uid;
};

struct gid_value
{
  public:
    gid_value () : gid (0) {}
    gid_value (gid_t const& g) : gid (g) {}
    operator gid_t () const { return gid; }
    gid_t gid;
};

struct server_parameters {

    struct remote_point {
        // [proto://]host_name[:port][/url]
        // [proto://]host_name[:port]
        std::string m_proto;
        std::string m_host_name;
        unsigned int m_port;
        std::string m_url;
    };

    std::vector<std::string> m_listen_points;

    std::vector<std::string> m_ssl_listen_points;

    std::string m_smtp_banner;

    unsigned int m_worker_count;

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

    bool m_rbl_active;
    std::string m_rbl_hosts;

    // whitelist DNS server
    std::string m_dnswl_host;

    uint32_t m_log_level;


    std::string m_aliases_file;

    unsigned int m_max_rcpt_count;

    // RC

    std::string m_rc_host_listconf;
    std::vector< std::pair<std::string,
                           boost::asio::ip::tcp::endpoint> > m_rc_host_list;
    int m_rc_port;
    int m_rc_timeout;
    int m_rc_verbose;
    int m_rc_check;

    // SPF

    time_t m_spf_timeout;

    // DKIM

    time_t m_dkim_timeout;

    time_t m_relay_connect_timeout;
    time_t m_relay_cmd_timeout;
    time_t m_relay_data_timeout;

    time_t m_smtpd_cmd_timeout;
    time_t m_smtpd_data_timeout;

    bool m_allow_percent_hack;

    remote_point m_relay_host;

    remote_point m_local_relay_host;
    bool m_use_local_relay;

    bool m_foreground;

    std::string m_pid_file;

    unsigned int m_client_connection_count_limit;
    unsigned int m_connection_count_limit;

    unsigned int m_message_size_limit;

    bool m_remove_headers;
    std::string m_remove_headers_list;
    boost::unordered_set<std::string> m_remove_headers_set;

    bool m_remove_extra_cr;

    uid_value m_uid;
    gid_value m_gid;

    std::string greylisting_config_file_;
    greylisting_options greylisting_;
    bool use_greylisting_;
    bool add_xyg_after_greylisting_;

    std::string m_ip_config_file;
    std::string m_profiler_log;

    bool m_use_tls;

    std::string m_tls_key_file;
    std::string m_tls_cert_file;
    std::string m_tls_ca_file;

    bool m_use_auth;
    bool m_auth_after_tls;

    int m_hard_error_limit;

    bool parse_config(int _argc, char* _argv[], std::ostream& _out) noexcept;
    bool init_dns_settings() noexcept;
};

extern server_parameters g_config;

extern const char *temp_error;
extern const char *temp_user_error;
extern const char *perm_user__error;


#endif //_CONFIG_H_
