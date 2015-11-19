#include "options.h"

#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/types.h>

#include <algorithm>
#include <fstream>
#include <functional>
#include <exception>
#include <memory>

#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <boost/function_output_iterator.hpp>
#include <boost/iterator/transform_iterator.hpp>
#include <boost/program_options.hpp>

#include <resolv.h>

#include "log.h"

using namespace std;

namespace ba = boost::asio;
namespace bpo = boost::program_options;

const char *temp_error = "451 4.7.1 Service unavailable - try again later";
const char *temp_user_error = "451 4.7.1 Requested action aborted: error in processing";
const char *perm_user_error = "550 Requested action not taken: mailbox unavailable";

server_parameters g_config;

template <typename T>
struct get_first : public std::unary_function<T, typename T::first_type&>
{
    typename T::first_type& operator()(T& x)
    {
        return x.first;
    }

    const typename T::first_type& operator()(const T& x) const
    {
        return x.first;
    }
};

template <typename T>
struct get_second : public std::unary_function<T, typename T::second_type&>
{
    typename T::second_type& operator()(T& x)
    {
        return x.second;
    }

    const typename T::second_type& operator()(const T& x) const
    {
        return x.second;
    }
};

/*
 * Get the part of the string before delimiting substring.
 *
 * _pos in: starting position;
 *      out: pos of the first char after delim
 */
std::string get_part(const std::string &_str,
                     const std::string &_delim,
                     std::string::size_type &_pos) {
    std::string part;
    std::string::size_type pos = _str.find(_delim, _pos);
    if (pos != std::string::npos) {
        part = _str.substr(_pos, pos - _pos);
        _pos = pos + _delim.length();
    }
    return part;
}


void validate(boost::any& v,
              std::vector<std::string> const& values,
              uid_value* target_type, int)
{
    using namespace boost::program_options;
    validators::check_first_occurrence (v);
    std::string const& s = validators::get_single_string (values);

    // check for number
    try {
        v = boost::any (uid_value(boost::lexical_cast<uid_t> (s)));
        return;
    }
    catch (std::bad_cast const&) {}

    // resolve by getpwnam
    struct passwd *pwd = ::getpwnam (s.c_str ());
    if (pwd)
    {
        v = boost::any (uid_value(pwd->pw_uid));
        ::endpwent ();
        return;
    }

    ::endpwent ();
    throw validation_error(validation_error::invalid_option_value, "invalid user name");
}


void validate(boost::any& v,
              std::vector<std::string> const& values,
              gid_value* target_type, int) {
    using namespace boost::program_options;

    validators::check_first_occurrence (v);
    std::string const& s = validators::get_single_string(values);

    // check for number
    try {
        v = boost::any(gid_value(boost::lexical_cast<gid_t>(s)));
        return;
    } catch (std::bad_cast const&) {}

    // resolve by getpwnam
    struct group *g = ::getgrnam(s.c_str());
    if (g) {
        v = boost::any(gid_value(g->gr_gid));
        ::endgrent();
        return;
    }

    ::endgrent();
    throw validation_error(validation_error::invalid_option_value,
                           "invalid group name");
}

#if 0
bool parse_strong_http_with_out_port(const std::string &_str,
                                     server_parameters::remote_point &_point) {
    std::string::size_type pos = 0;
    std::string buffer = get_part(_str, "://", pos);

    PDBG0("_str = %s", _str.c_str());

    buffer = get_part(_str, "/", pos);

    if (!buffer.empty())
    {
        _point.m_host_name = buffer;
    }

    if (pos < (_str.length() - 1 ))
    {
        _point.m_url = _str.substr(pos-1, _str.length() - pos + 1);
    }

    _point.m_proto = "http";

    return true;
}
#endif

void validate(boost::any& v,
              std::vector<std::string> const& values,
              server_parameters::remote_point* target_type, int) {
    boost::program_options::validators::check_first_occurrence(v);
    std::string const& s = boost::program_options::validators::get_single_string(values);

    PDBG0("s = %s", s.c_str());

    server_parameters::remote_point rp;

    rp.m_port = 0;

    std::string::size_type pos = 0;
    std::string buffer = get_part(s, "://", pos);
    if (!buffer.empty()) {
        rp.m_proto = buffer;
    }

    buffer = get_part(s, ":", pos);
    if (!buffer.empty()) {
        rp.m_host_name = buffer;

        buffer = get_part(s, "/", pos);

        if (!buffer.empty()) {
            rp.m_port = atoi(buffer.c_str());
            rp.m_url = s.substr(pos-1, s.length() - pos + 1);
        } else {
            std::string tmp = s.substr(pos,s.length() - pos);
            rp.m_port = atoi(tmp.c_str());
        }
    } else {
        buffer = get_part(s, "/", pos);
        if (!buffer.empty()) {
            rp.m_host_name = buffer;
        }

        rp.m_url = s.substr(pos-1, s.length() - pos + 1);
    }

    if (rp.m_proto.empty() && rp.m_port > 0) {
#ifdef __linux__
        struct servent result_buf;
        struct servent *result;
        char buffer[1024];
        int err = getservbyport_r(htons(rp.m_port),"tcp", &result_buf, buffer, sizeof(buffer), &result);
        if (err == 0 && result != nullptr) {
            rp.m_proto = result->s_name;
        }
#else
        rp.m_proto = "smtp";
#endif
    }

    if (!rp.m_proto.empty() && rp.m_port == 0) {
#ifdef __linux__
        struct servent result_buf;
        struct servent *result;
        char buffer[1024];
        int err = getservbyname_r(rp.m_proto.c_str(),"tcp", &result_buf, buffer, sizeof(buffer), &result);
        if ((err == 0) && (result != NULL)) {
            rp.m_port = ntohs(result->s_port);
        }
#else
        rp.m_port = 25;
#endif
    }

    if (rp.m_port == 0) {
        throw boost::program_options::validation_error(
                    boost::program_options::validation_error::invalid_option_value,
                    "missing port number or service name");
    }

    v = boost::any(rp);
}


bool server_parameters::init_dns_settings() noexcept {
    if (m_use_system_dns_servers) {
        // get DNS servers from libresolv
        typedef struct __res_state TResState;
        std::unique_ptr<TResState> rs(new TResState);
        if(res_ninit(rs.get()) != 0) {
            return false;
        }
        if(rs->nscount <= 0) {
            return false;
        }
        for(int i = 0; i < rs->nscount; ++i) {
            ba::ip::address_v4 addr(
                static_cast<unsigned long>(htonl(rs->nsaddr_list[i].sin_addr.s_addr)));
            m_dns_servers.push_back(addr.to_string());
        }
    } else {
        // get space separated list of DNS hosts from config file
        std::istringstream iss(m_custom_dns_servers);
        std::copy(std::istream_iterator<std::string>(iss),
                  std::istream_iterator<std::string>(),
                  std::back_inserter(m_dns_servers));
    }
    return true;
}


#define DEF_CONFIG      "/etc/resmtp/resmtp.conf"
#define DEF_PID_FILE    "/var/run/resmtp.pid"
bool server_parameters::parse_config(int _argc,
                                     char* _argv[],
                                     std::ostream &os) noexcept {
    try {
        std::string config_file;
        bpo::options_description command_line_opt("Command line options");
        command_line_opt.add_options()
                ("version,v", "print version")
                ("help,h", "print help")
                ("fg,f", "run at foreground")
                ("pid-file,p", bpo::value<std::string>(&m_pid_file)->default_value(DEF_PID_FILE), "name of pid file.")
                ("config,c", bpo::value<std::string>(&config_file)->default_value(DEF_CONFIG), "name of configuration file.")
                ;

        bpo::options_description config_options("Configuration");

        config_options.add_options()
                ("log_level", bpo::value<uint32_t>(&m_log_level)->default_value(0), "log output level 0|1|2")

                ("listen", bpo::value<std::vector<std::string>>(&m_listen_points), "listen on host:port")
                ("ssl_listen", bpo::value<std::vector<std::string>>(&m_ssl_listen_points), "SSL listen on host:port")

                ("user", bpo::value<uid_value>(&m_uid), "set uid after port bindings")
                ("group", bpo::value<gid_value>(&m_gid), "set gid after port bindings")

                ("use_system_dns_servers", bpo::value<bool>(&m_use_system_dns_servers)->default_value(true), "use host's DNS servers settings?")
                ("custom_dns_servers", bpo::value<std::string>(&m_custom_dns_servers), "custom DNS servers IP addresses list")

                ("socket_check", bpo::value<bool>(&m_socket_check)->default_value(false), "check socket emptiness before sending greeting ?")

                ("tarpit_delay_seconds", bpo::value<uint32_t>(&m_tarpit_delay_seconds)->default_value(0), "tarpit delay")

                ("smtp_banner", bpo::value<std::string>(&m_smtp_banner), "smtp banner")
                ("workers", bpo::value<uint32_t>(&m_worker_count), "workers count")
                ("rbl_check", bpo::value<bool>(&m_rbl_active)->default_value(false), "RBL active ?")
                ("rbl_hosts", bpo::value<std::string>(&m_rbl_hosts), "RBL hosts list")
                ("dnswl_host", bpo::value<std::string>(&m_dnswl_host), "DNSWL host")

                ("spf_timeout", bpo::value<time_t>(&m_spf_timeout)->default_value(15), "spf calculation timeout")
                ("dkim_timeout", bpo::value<time_t>(&m_dkim_timeout)->default_value(15), "dkim calculation timeout")

                ("smtpd_recipient_limit", bpo::value<uint32_t>(&m_max_rcpt_count)->default_value(100), "maximum recipient per mail")

                ("smtpd_client_connection_count_limit", bpo::value<uint32_t>(&m_client_connection_count_limit)->default_value(50), "maximum connection per ip")
                ("smtpd_connection_count_limit", bpo::value<uint32_t>(&m_connection_count_limit)->default_value(10000), "maximum connection")

                ("smtpd_hard_error_limit", bpo::value<uint32_t>(&m_hard_error_limit)->default_value(100), "maximum number of errors that a remote SMTP client is allowed to make")

                ("relay_connect_timeout", bpo::value<time_t>(&m_relay_connect_timeout), "smtp relay connect timeout")
                ("relay_cmd_timeout", bpo::value<time_t>(&m_relay_cmd_timeout), "smtp relay command timeout")
                ("relay_data_timeout", bpo::value<time_t>(&m_relay_data_timeout), "smtp relay data send timeout")

                ("smtpd_command_timeout", bpo::value<time_t>(&m_smtpd_cmd_timeout), "smtpd command timeout")
                ("smtpd_data_timeout", bpo::value<time_t>(&m_smtpd_data_timeout), "smtpd data timeout")

                ("use_local_relay", bpo::value<bool>(&m_use_local_relay)->default_value(false), "use local (LMTP) relay ?")
                ("local_relay_host", bpo::value<remote_point>(&m_local_relay_host), "local (LMTP) relay")
                ("relay_host", bpo::value<remote_point>(&m_relay_host), "relay")

                ("backend_host", bpo::value<std::vector<std::string>>(&backend_hosts), "backend hosts")
                ("backend_port", bpo::value<uint16_t>(&backend_port), "backend hosts TCP port")

                ("message_size_limit", bpo::value<uint32_t>(&m_message_size_limit)->default_value(10240000), "Message size limit")

                ("remove_headers", bpo::value<bool>(&m_remove_headers)->default_value(false), "Remove headers on/off")
                ("remove_headers_list", bpo::value<std::string>(&m_remove_headers_list), "List of headers to remove")

                ("remove_extra_cr", bpo::value<bool>(&m_remove_extra_cr)->default_value(true), "Remove extra carriage returns on/off")

                ("ip_config_file", bpo::value<std::string>(&m_ip_config_file), "IP address depended config params")

                ("use_tls", bpo::value<bool>(&m_use_tls)->default_value(false), "Use TLS ?")
                ("tls_key_file", bpo::value<std::string>(&m_tls_key_file), "Use a private key from file")
                ("tls_cert_file", bpo::value<std::string>(&m_tls_cert_file), "Use a certificate from file")
                ("tls_CAfile", bpo::value<std::string>(&m_tls_ca_file), "Use a certificate chain from a file. ")

                ("use_auth",bpo::value<bool>(&m_use_auth)->default_value(false), "Use auth ?")
                ("use_auth_after_tls", bpo::value<bool>(&m_use_tls)->default_value(false), "Use auth only after TLS ?")
                ;

        bpo::variables_map vm;
        bpo::positional_options_description p;

        bpo::store(bpo::command_line_parser(_argc, _argv).options(command_line_opt).run(), vm);
        notify(vm);

        m_foreground = (vm.count("fg") != 0);

        if (vm.count("help")) {
            os << command_line_opt << std::endl;
            return false;
        }

        if (vm.count("version")) {
            os << "0.0.1" << std::endl;
            return false;
        }

        std::ifstream ifs(config_file.c_str());
        if (!ifs) {
            os << "Can not open config file: " << config_file << std::endl;
            return false;
        }
        store(parse_config_file(ifs, config_options, true), vm);
        notify(vm);

        if (m_remove_headers) {
            if (m_remove_headers_list.empty()) {
                os << "Config file error: remove_headers_list param not specified" << std::endl;
                return false;
            }
            std::ifstream ifs( m_remove_headers_list.c_str(), std::ios_base::in );
            while (ifs && !ifs.eof()) {
                std::string header;
                ifs >> header;
                if (!header.empty()) {
                    m_remove_headers_set.insert( boost::trim_copy( boost::to_lower_copy(header) ) );
                }
            }
            if (m_remove_headers_set.empty()) {
                os << "Config file error: remove_headers_list: config file \"" << m_remove_headers_list << "\" invalid" << std::endl;
                return false;
            }
        }

        // debug
#if 1
        for(auto &host : backend_hosts) {
            os << "backend_host = " << host << endl;
        }
        os << "backend_port = " << backend_port << endl;
#endif

    } catch (const std::exception& e) {
        os << "Config file error:" << e.what() << std::endl;
        return false;
    }

    return true;
}
