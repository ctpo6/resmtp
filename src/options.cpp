#include "options.h"

#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/types.h>

#include <algorithm>
#include <exception>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <unordered_map>

#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <boost/function_output_iterator.hpp>
#include <boost/iterator/transform_iterator.hpp>
#include <boost/program_options.hpp>
#include <boost/tokenizer.hpp>

#include <resolv.h>

#include "global.h"

using namespace std;

namespace ba = boost::asio;
namespace bpo = boost::program_options;

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
string get_part(const string &_str,
                const string &_delim,
                string::size_type &_pos) {
    string part;
    string::size_type pos = _str.find(_delim, _pos);
    if (pos != string::npos) {
        part = _str.substr(_pos, pos - _pos);
        _pos = pos + _delim.length();
    }
    return part;
}


void validate(boost::any &v,
              const vector<string> &values,
              log_value *, int)
{
    using namespace boost::program_options;
    validators::check_first_occurrence (v);
    const string &s = validators::get_single_string(values);

    static const unordered_map<string, log_value> map = {
        {"crit", log_value(r::log::crit)}
        ,{"err", log_value(r::log::err)}
        ,{"warning", log_value(r::log::warning)}
        ,{"notice", log_value(r::log::notice)}
        ,{"info", log_value(r::log::info)}
        ,{"debug", log_value(r::log::debug)}
        ,{"buffers", log_value(r::log::buffers)}
    };

    try {
        v = boost::any(map.at(s));
    } catch (const std::out_of_range &) {
        throw validation_error(validation_error::invalid_option_value);
    }
}


void validate(boost::any& v,
              std::vector<std::string> const& values,
              uid_value *, int)
{
    using namespace boost::program_options;
    validators::check_first_occurrence (v);
    std::string const& s = validators::get_single_string (values);

    // check for number
    try {
        v = boost::any(uid_value(boost::lexical_cast<uid_t> (s)));
        return;
    }
    catch (std::bad_cast const&) {}

    // resolve by getpwnam
    struct passwd *pwd = ::getpwnam (s.c_str ());
    if (pwd)
    {
        v = boost::any(uid_value(pwd->pw_uid));
        ::endpwent ();
        return;
    }

    ::endpwent ();
    throw validation_error(validation_error::invalid_option_value);
}


void validate(boost::any& v,
              std::vector<std::string> const& values,
              gid_value* target_type, int)
{
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
    throw validation_error(validation_error::invalid_option_value);
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

void validate(boost::any &v,
              const std::vector<std::string> &values,
              server_parameters::remote_point* target_type,
              int)
{
    using namespace boost::program_options;
    validators::check_first_occurrence(v);
    string const& s = validators::get_single_string(values);

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
        throw validation_error(validation_error::invalid_option_value);
    }

    v = boost::any(rp);
}


void server_parameters::init_dns_settings()
{
  dns_ip.clear();
  
  if (dns_ip_str.empty()) {
    // get host configured DNS servers addresses using libresolv
    static struct __res_state rs;
    if (res_ninit(&rs) != 0 || rs.nscount <= 0) {
      throw std::runtime_error("failed to obtain DNS server settings: the argument for option 'dns_ip' is also empty");
    }
    dns_ip.reserve(rs.nscount);
    for (int i = 0; i < rs.nscount; ++i) {
      dns_ip.emplace_back((unsigned long) htonl(rs.nsaddr_list[i].sin_addr.s_addr));
    }
  }
  else {
    // get DNS servers addresses from cfg
    dns_ip.reserve(dns_ip_str.size());
    for (const auto &s : dns_ip_str) {
      boost::system::error_code ec;
      auto addr(ba::ip::address_v4::from_string(s, ec));
      if (ec) {
        throw std::runtime_error(util::strf("the argument for option 'dns_ip' is invalid: %s", s.c_str()));
      }
      dns_ip.push_back(addr);
    }
  }
}


void server_parameters::init_white_ip_settings()
{
  white_ip.clear();
  if (white_ip_str.empty()) return; // nothing to do

  white_ip.reserve(white_ip_str.size());
  for (const auto &s : white_ip_str) {
    boost::system::error_code ec;
    auto addr(ba::ip::address_v4::from_string(s, ec));
    if (ec) {
      throw std::runtime_error(util::strf("the argument for option 'white_ip' is invalid: %s", s.c_str()));
    }
    white_ip.push_back(addr);
  }
}

void server_parameters::init_backend_hosts_settings()
{
  using namespace boost;
  
  backend_hosts.clear();
  backend_hosts.reserve(backend_hosts_str.size());

  for (auto &s : backend_hosts_str) {
    tokenizer<char_separator<char>> t(s, char_separator<char>(" \t"));

    // get host name
    auto it = t.begin();
    string host_name(*it++);

    // get host weight
    uint32_t weight = 100;
    if (it != t.end()) {
      try {
        weight = boost::lexical_cast<uint32_t>(*it);
      }
      catch (const boost::bad_lexical_cast &e) {
        weight = 101; // make it >100 to be processed as error below
      }
      if (weight > 100) {
        throw std::runtime_error(util::strf("the argument for option 'backend_host' is invalid: %s %s",
                                            host_name.c_str(),
                                            it->c_str()));
      }
    }
    if (!weight) { // by assigning weight == 0 host is disabled
      continue;
    }

    backend_hosts.emplace_back(std::move(host_name), weight);
  }

  if (backend_hosts.empty()) {
    // no enabled hosts (i.e. with weight > 0)
    throw std::runtime_error("no enabled backend hosts (check 'backend_host' entries)");
  }
}


bool server_parameters::parse_config(int argc, char * argv[])
{
    bpo::options_description common_opt;
    common_opt.add_options()
            ("log,l", bpo::value<log_value>(&log_level), "log level: crit, err, warning, notice, info, debug, buffers")
            ("pid,p", bpo::value<string>(&m_pid_file)->default_value(def_pid_file), "pid file path")
            ;

    bpo::options_description command_line_opt("Command line options");
    command_line_opt.add_options()
            ("help,h", "print help")
            ("version,v", "print version")
            ("check,C", "check config only (not thoroughly indeed)")
            ("foreground,f", "run at foreground (don't daemonize)")
            ("config,c", bpo::value<std::string>(&config_file_)->default_value(def_config_file), "path to configuration file")
            ;
    command_line_opt.add(common_opt);

    bpo::options_description config_opt;
    config_opt.add_options()
            ("listen", bpo::value<vector<string>>(&m_listen_points), "listen on host:port")
            ("ssl_listen", bpo::value<vector<string>>(&m_ssl_listen_points), "SSL listen on host:port")

            ("monitoring_listen", bpo::value<string>(&mon_listen_point)->default_value("localhost:11311"), "monitoring listen on host:port")

            ("spamhaus_log_file", bpo::value<string>(&spamhaus_log_file), "spamhaus log file path")

            ("user", bpo::value<uid_value>(&m_uid), "set uid after port bindings")
            ("group", bpo::value<gid_value>(&m_gid), "set gid after port bindings")

            ("dsn_ip", bpo::value<vector<string>>(&dns_ip_str), "DNS servers IP addresses list")

            ("socket_check", bpo::value<bool>(&m_socket_check)->default_value(false), "check socket emptiness before sending greeting ?")

            ("tarpit_delay_seconds", bpo::value<uint32_t>(&m_tarpit_delay_seconds)->default_value(0), "tarpit delay")

            ("smtp_banner", bpo::value<string>(&m_smtp_banner), "smtp banner")

            ("workers", bpo::value<uint32_t>(&m_worker_count), "workers count")

            ("white_ip", bpo::value<vector<string>>(&white_ip_str), "white IP addresses list")

            ("dnsbl_host", bpo::value<vector<string>>(&dnsbl_hosts), "DNSBL hosts list")
            ("dnswl_host", bpo::value<string>(&dnswl_host), "DNSWL host")

            ("smtpd_recipient_limit", bpo::value<uint32_t>(&m_max_rcpt_count)->default_value(100), "maximum recipient per mail")

            ("smtpd_client_connection_count_limit", bpo::value<uint32_t>(&m_client_connection_count_limit)->default_value(0), "max number of connections per IP (0 - unlimited)")
            ("smtpd_connection_count_limit", bpo::value<uint32_t>(&m_connection_count_limit)->default_value(0), "total max number of connections (0 - unlimited)")

            ("smtpd_hard_error_limit", bpo::value<uint32_t>(&m_hard_error_limit)->default_value(100), "maximum number of errors that a remote SMTP client is allowed to make")

            ("frontend_cmd_timeout", bpo::value<time_t>(&frontend_cmd_timeout)->default_value(600), "smtpd command timeout")
            ("frontend_data_timeout", bpo::value<time_t>(&frontend_data_timeout)->default_value(600), "smtpd data timeout")

            ("backend_connect_timeout", bpo::value<time_t>(&backend_connect_timeout)->default_value(60), "smtp relay connect timeout")
            ("backend_cmd_timeout", bpo::value<time_t>(&backend_cmd_timeout)->default_value(120), "smtp relay command timeout")
            ("backend_data_timeout", bpo::value<time_t>(&backend_data_timeout)->default_value(300), "smtp relay data send timeout")

            ("use_local_relay", bpo::value<bool>(&m_use_local_relay)->default_value(false), "use local (LMTP) relay ?")
            ("local_relay_host", bpo::value<remote_point>(&m_local_relay_host), "local (LMTP) relay")

            ("backend_host", bpo::value<vector<string>>(&backend_hosts_str), "backend host")
            ("backend_port", bpo::value<uint16_t>(&backend_port), "backend hosts TCP port")

            ("message_size_limit", bpo::value<uint32_t>(&m_message_size_limit)->default_value(10240000), "Message size limit")

            ("remove_extra_cr", bpo::value<bool>(&m_remove_extra_cr)->default_value(true), "Remove extra carriage returns on/off")

            ("ip_config_file", bpo::value<string>(&m_ip_config_file), "IP address depended config params")

            ("use_tls", bpo::value<bool>(&m_use_tls)->default_value(false), "support TLS ?")
            ("tls_cert_file", bpo::value<string>(&m_tls_cert_file), "use a certificate from file")
            ("tls_key_file", bpo::value<string>(&m_tls_key_file), "use a private key from file")
            ;
    config_opt.add(common_opt);

    bpo::variables_map vm;

    bpo::store(bpo::command_line_parser(argc, argv).options(command_line_opt).run(), vm);
    notify(vm);

    if (vm.count("help")) {
        cout << command_line_opt << endl;
        return false;
    }

    if (vm.count("version")) {
        cout << g::app_version() << endl;
        return false;
    }

    m_foreground = (vm.count("foreground") != 0);

    std::ifstream ifs(config_file_.c_str());
    if (!ifs) {
        throw std::runtime_error("can't open config file");
    }
    store(parse_config_file(ifs, config_opt, true), vm);
    notify(vm);

#if 0
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
#endif

    // initialize white IP settings
    init_white_ip_settings();
    // initialize DNS servers settings
    init_dns_settings();
    // initialize backend hosts settings
    init_backend_hosts_settings();
    
    if (vm.count("check")) {
        cout << "config check (" << config_file_ << "): ok" << endl;
        return false;
    }

    return true;
}
