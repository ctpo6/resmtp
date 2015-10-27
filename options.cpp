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

#include <boost/program_options.hpp>
#include <boost/format.hpp>
#include <boost/asio.hpp>
#include <boost/iterator/transform_iterator.hpp>
#include <boost/function_output_iterator.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <resolv.h>

#include "host_seq_resolver.h"


#if defined(HAVE_HOSTSEARCH_HOSTSEARCH_H)
#include <hostsearch/hostsearch.h>
#endif

namespace ba = boost::asio;

const char *temp_error = "451 4.7.1 Service unavailable - try again later";
const char *temp_user_error = "451 4.7.1 Requested action aborted: error in processing";
const char *perm_user_error = "550 Requested action not taken: mailbox unavailable";

server_parameters g_config;

template <typename T>
struct get_first : public std::unary_function<T, typename T::first_type&>
{
    typename T::first_type& operator()(T& x) const
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
    typename T::second_type& operator()(T& x) const
    {
        return x.second;
    }

    const typename T::second_type& operator()(const T& x) const
    {
        return x.second;
    }
};

std::string get_part(const std::string &_str, const std::string &_delim, std::string::size_type &_pos)
{

    std::string part;
    std::string::size_type pos = _str.find(_delim, _pos);

    if (pos != std::string::npos)
    {
        part = _str.substr( _pos, pos - _pos);
        _pos = pos + _delim.length();
    }

    return part;
}

void validate (boost::any& v, std::vector<std::string> const& values, uid_value* target_type, int)
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
    //
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

void validate (boost::any& v, std::vector<std::string> const& values, gid_value* target_type, int)
{
    using namespace boost::program_options;
    validators::check_first_occurrence (v);
    std::string const& s = validators::get_single_string (values);

    // check for number
    try {
        v = boost::any (gid_value(boost::lexical_cast<gid_t> (s)));
        return;
    }
    catch (std::bad_cast const&) {}

    // resolve by getpwnam
    //
    struct group *g = ::getgrnam (s.c_str ());
    if (g)
    {
        v = boost::any (gid_value(g->gr_gid));
        ::endgrent ();
        return;
    }

    ::endgrent ();
    throw validation_error(validation_error::invalid_option_value, "invalid group name");
}

bool parse_strong_http_with_out_port(const std::string &_str, server_parameters::remote_point &_point)
{

    std::string::size_type pos = 0;

    std::string buffer = get_part(_str, "://", pos);

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

void validate (boost::any& v, std::vector<std::string> const& values, server_parameters::remote_point* target_type, int)
{
    boost::program_options::validators::check_first_occurrence (v);
    std::string const& s =  boost::program_options::validators::get_single_string (values);

    server_parameters::remote_point rp;

    rp.m_port = 0;

    std::string::size_type pos = 0;

    std::string buffer = get_part(s, "://", pos);

    if (!buffer.empty())
    {
        rp.m_proto = buffer;
    }

    buffer = get_part(s, ":", pos);


    if (!buffer.empty())
    {
        rp.m_host_name = buffer;

        buffer = get_part(s, "/", pos);

        if (!buffer.empty())
        {
            rp.m_port = atoi(buffer.c_str());

            rp.m_url = s.substr(pos-1, s.length() - pos + 1);
        }
        else
        {
            std::string tmp = s.substr(pos,s.length() - pos);

            rp.m_port = atoi(tmp.c_str());
        }

    }
    else
    {
        buffer = get_part(s, "/", pos);

        if (!buffer.empty())
        {
            rp.m_host_name = buffer;
        }

        rp.m_url = s.substr(pos-1, s.length() - pos + 1);

    }


    if (rp.m_proto.empty() && rp.m_port > 0)
    {

        if (rp.m_port == 1234)
        {
            rp.m_proto = "lmtp";
        }
        else
        {
            struct servent result_buf;
            struct servent *result;
            char buffer[1024];

#ifdef __linux__
            int err = getservbyport_r(htons(rp.m_port),"tcp", &result_buf, buffer, sizeof(buffer), &result);

            if ((err == 0) && (result != NULL))
            {
                rp.m_proto = result->s_name;
            }
#else
	    rp.m_proto = "smtp";
#endif
        }
    }


    if (!rp.m_proto.empty() && rp.m_port == 0)
    {
        if (rp.m_proto == "lmtp")
        {
            rp.m_port = 1234;

        }
        else
        {
            struct servent result_buf;
            struct servent *result;
            char buffer[1024];

#ifdef __linux__
            int err = getservbyname_r(rp.m_proto.c_str(),"tcp", &result_buf, buffer, sizeof(buffer), &result);

            if ((err == 0) && (result != NULL))
            {
                rp.m_port = ntohs(result->s_port);
            }
#else
            rp.m_port = 25;
#endif
        }
    }


    if (rp.m_port == 0)
    {
        throw boost::program_options::validation_error(boost::program_options::validation_error::invalid_option_value, "missing port number or service name");
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
bool server_parameters::parse_config(int _argc, char* _argv[], std::ostream& _out) noexcept
{
    try
    {
        std::string config_file;

        namespace bpo = boost::program_options;
        bpo::options_description command_line_opt("Command line options");

        command_line_opt.add_options()
                ("version,v", "print version string")
                ("help,h", "produce help message")
                ("fg,f", "run at foreground")
                ("pid-file,p", bpo::value<std::string>(&m_pid_file)->default_value(DEF_PID_FILE), "name of pid file.")
                ("config,c", bpo::value<std::string>(&config_file)->default_value(DEF_CONFIG), "name of configuration file.")
                ;

        bpo::options_description config_options("Configuration");

        config_options.add_options()
                ("listen", bpo::value< std::vector< std::string > >(&m_listen_points), "listen on host:port")
                ("ssl_listen", bpo::value< std::vector<std::string> >(&m_ssl_listen_points), "SSL listen on host:port")
                ("user", bpo::value<uid_value>(&m_uid), "set uid after port bindings")
                ("group", bpo::value<gid_value>(&m_gid), "set gid after port bindings")

                ("use_system_dns_servers", bpo::value<bool>(&m_use_system_dns_servers)->default_value(true), "use host's DNS servers settings?")
                ("custom_dns_servers", bpo::value<std::string>(&m_custom_dns_servers), "custom DNS servers IP addresses list")

                ("socket_check", bpo::value<bool>(&m_socket_check)->default_value(false), "check socket emptiness before sending greeting ?")

                ("tarpit_delay_seconds", bpo::value<uint32_t>(&m_tarpit_delay_seconds)->default_value(0), "tarpit delay")

                ("smtp_banner", bpo::value<std::string>(&m_smtp_banner), "smtp banner")
                ("workers", bpo::value<unsigned int>(&m_worker_count), "workers count")
                ("rbl_check", bpo::value<bool>(&m_rbl_active)->default_value(false), "RBL active ?")
                ("rbl_hosts", bpo::value<std::string>(&m_rbl_hosts), "RBL hosts list")
                ("dnswl_host", bpo::value<std::string>(&m_dnswl_host), "DNSWL host")
                ("log_level", bpo::value<uint32_t>(&m_log_level)->default_value(0), "log output level 0|1|2")

                ("spf_timeout", bpo::value<time_t>(&m_spf_timeout)->default_value(15), "spf calculation timeout")
                ("dkim_timeout", bpo::value<time_t>(&m_dkim_timeout)->default_value(15), "dkim calculation timeout")

                ("aliases", bpo::value<std::string>(&m_aliases_file), "aliases file")

                ("smtpd_recipient_limit", bpo::value<unsigned int>(&m_max_rcpt_count)->default_value(100), "maximum recipient per mail")
                ("smtpd_client_connection_count_limit", bpo::value<unsigned int>(&m_client_connection_count_limit)->default_value(5), "maximum connection per ip")
                ("smtpd_connection_count_limit", bpo::value<unsigned int>(&m_connection_count_limit)->default_value(1000), "maximum connection")
                ("smtpd_hard_error_limit", bpo::value<int>(&m_hard_error_limit)->default_value(20), "maximal number of errors a remote SMTP client is allowed to make")

                ("so_primary", bpo::value<remote_point>(&m_so_primary_host), "so host")
                ("so_secondary", bpo::value<remote_point>(&m_so_secondary_host), "so secondary")
//                ("so_fallback_time", bpo::value<time_t>(&m_so_fallback_time), "so falback time")
//                ("so_return_time", bpo::value<time_t>(&m_so_return_time), "so return time")
                ("so_connect_timeout", bpo::value<time_t>(&m_so_connect_timeout), "so connect timeout")
                ("so_data_timeout", bpo::value<time_t>(&m_so_timeout), "so session timeout")
#if defined(HAVE_HOSTSEARCH_HOSTSEARCH_H)
                ("so_file_path", bpo::value<std::string>(&m_so_file_path), "so libhostsearch path")
                ("so_port", bpo::value<int>(&m_so_port)->default_value(2525), "so port used only for so_file_path")
#endif

                ("relay_connect_timeout", bpo::value<time_t>(&m_relay_connect_timeout), "smtp relay connect timeout")
                ("relay_cmd_timeout", bpo::value<time_t>(&m_relay_cmd_timeout), "smtp relay command timeout")
                ("relay_data_timeout", bpo::value<time_t>(&m_relay_data_timeout), "smtp relay data send timeout")

                ("smtpd_command_timeout", bpo::value<time_t>(&m_smtpd_cmd_timeout), "smtpd command timeout")
                ("smtpd_data_timeout", bpo::value<time_t>(&m_smtpd_data_timeout), "smtpd data timeout")
                ("allow_percent_hack", bpo::value<bool>(&m_allow_percent_hack)->default_value(true), "use percent hack")

                ("fallback_relay_host", bpo::value<remote_point>(&m_relay_host), "relay")
                ("local_relay_host", bpo::value<remote_point>(&m_local_relay_host), "local relay")
                ("use_local_relay", bpo::value<bool>(&m_use_local_relay), "use local relay ?")

                ("so_check", bpo::value<bool>(&m_so_check)->default_value(false), "SO on/off")
                ("so_trust_xyandexspam", bpo::value<bool>(&so_trust_xyandexspam_)->default_value(false),
                        "Trust X-Yandex-Spam header field?")

                ("so_try", bpo::value<unsigned int>(&m_so_try)->default_value(3), "SO try")

                ("rc_host_list", bpo::value<std::string>(&m_rc_host_listconf)->default_value("/etc/yamail/rchost_list.conf"), "rc host list")
                ("rc_port", bpo::value<int>(&m_rc_port)->default_value(8888), "rc port")
                ("rc_timeout", bpo::value<int>(&m_rc_timeout)->default_value(1), "rc timeout in secs")
                ("rc_verbose", bpo::value<int>(&m_rc_verbose)->default_value(0), "rc verbose on/off")
                ("rc_check", bpo::value<int>(&m_rc_check)->default_value(0), "rc on/off")

                ("message_size_limit", bpo::value<unsigned int>(&m_message_size_limit)->default_value(10240000), "Message size limit")

                ("remove_headers", bpo::value<bool>(&m_remove_headers)->default_value(false), "Remove headers on/off")
                ("remove_headers_list", bpo::value<std::string>(&m_remove_headers_list), "List of headers to remove")

                ("remove_extra_cr", bpo::value<bool>(&m_remove_extra_cr)->default_value(true), "Remove extra carriage returns on/off")

                ("ip_config_file", bpo::value<std::string>(&m_ip_config_file), "IP address depended config params")
                ("profiler_log", bpo::value<std::string>(&m_profiler_log), "Profiler log path")

                ("use_tls", bpo::value<bool>(&m_use_tls)->default_value(false), "Use TLS ?")
                ("tls_key_file", bpo::value<std::string>(&m_tls_key_file), "Use a private key from file")
                ("tls_cert_file", bpo::value<std::string>(&m_tls_cert_file), "Use a certificate from file")
                ("tls_CAfile", bpo::value<std::string>(&m_tls_ca_file), "Use a certificate chain from a file. ")

                ("use_auth",bpo::value<bool>(&m_use_auth)->default_value(false), "Use auth ?")
                ("use_auth_after_tls", bpo::value<bool>(&m_use_tls)->default_value(false), "Use auth only after TLS ?")

                ("use_greylisting", bpo::value<bool>(&use_greylisting_), "Use greylisting ?")
                ("greylisting_config_file", bpo::value<std::string>(&greylisting_config_file_), "The name of the greylisting configuration file")
                ("enable_so_after_greylisting", bpo::value<bool>(&enable_so_after_greylisting_)->default_value(false), "if set to true, SO checks will be made for all "
                        "messages irregardless of their greylisting checks status")
                ("add_xyg_after_greylisting", bpo::value<bool>(&add_xyg_after_greylisting_)->default_value(true), "if set to true, fake X-Yandex-Greylisting "
                        "header will be appended for messages sent to SO hosts")
                ;

        bpo::variables_map vm;
        bpo::positional_options_description p;

        bpo::store(bpo::command_line_parser(_argc, _argv).options(command_line_opt).run(), vm);

        notify(vm);


        m_foreground = (vm.count("fg") != 0);

        if (vm.count("help"))
        {
            _out << command_line_opt << std::endl;
            return false;
        }

        if (vm.count("version"))
        {
            _out << "0.0.1" << std::endl;
            return false;
        }

        std::ifstream ifs(config_file.c_str());

        if (!ifs)
        {
            _out << "Can not open config file: " << config_file << std::endl;
            return false;
        }
        else
        {
            store(parse_config_file(ifs, config_options, true), vm);
            notify(vm);
        }

        if (m_remove_headers)
        {
            if (m_remove_headers_list.empty())
            {
                _out << "Config file error: remove_headers_list param not specified" << std::endl;
                return false;
            }
            std::ifstream ifs ( m_remove_headers_list.c_str(), std::ios_base::in );
            while ( ifs && !ifs.eof() )
            {
                std::string header;
                ifs >> header;
                if ( !header.empty() )
                    m_remove_headers_set.insert( boost::trim_copy( boost::to_lower_copy(header) ) );
            }
            if ( m_remove_headers_set.empty() )
            {
                _out << "Config file error: remove_headers_list: config file \"" << m_remove_headers_list << "\" invalid" << std::endl;
                return false;
            }
        }

        if (use_greylisting_)
        {
            try
            {
                greylisting_options_parser parser(greylisting_);
                parser.parse_from_file(greylisting_config_file_.c_str());
            }
            catch (const std::exception& e)
            {
                _out << "Config file error: greylisting_config_file: config file \"" << greylisting_config_file_ << "\" invalid: "
                     << e.what();

                return false;
            }
        }

        if (m_rc_check)
        {
            if (m_rc_host_listconf.empty())
            {
                _out << "Config file error: rc_host_list param not specified" << std::endl;
                return false;
            }

            // Try and parse RC config & resolve RC hosts
            std::ifstream ifs( m_rc_host_listconf.c_str(), std::ios_base::in );
            typedef boost::asio::ip::tcp::endpoint endpoint_t;
            while (ifs && !ifs.eof())
            {
                std::string host;
                ifs >> host;
                if (!host.empty())
                    m_rc_host_list.push_back( std::make_pair(host, endpoint_t()));
            }
            typedef std::vector< std::pair<std::string,
                    boost::asio::ip::tcp::endpoint> > rclist_t;
            resolve_host_sequence<endpoint_t>(
                boost::make_transform_iterator<get_first<rclist_t::value_type> >(m_rc_host_list.begin()),
                boost::make_transform_iterator<get_first<rclist_t::value_type> >(m_rc_host_list.end()),
                boost::make_transform_iterator<get_second<rclist_t::value_type> >(m_rc_host_list.begin()),
                m_rc_port);
            std::sort(m_rc_host_list.begin(), m_rc_host_list.end());
            if (m_rc_host_list.empty())
            {
                _out << "Config file error: rc_host_list: config file "
                     << m_rc_host_listconf << " invalid" << std::endl;
                return false;
            }
        }

#if defined(HAVE_HOSTSEARCH_HOSTSEARCH_H)
        if (m_so_check && !m_so_file_path.empty())
        {
	    char big_buffer[1024];
            if ((bbUrls2(m_so_file_path.c_str(), big_buffer, 1024) == 0) && (big_buffer[0] != 0))
            {
                m_so_primary_host.m_host_name = big_buffer;
                m_so_primary_host.m_port = m_so_port;
            }
        }

        if (m_bb_check && !m_bb_file_path.empty())
        {

            char big_buffer[1024];

            if ((bbUrls2(m_bb_file_path.c_str(), big_buffer, 1024) == 0) && (big_buffer[0] != 0))
            {
                if (parse_strong_http_with_out_port(std::string(big_buffer), m_bb_primary_host))
                {
                    m_bb_primary_host.m_port = m_bb_port;
                }
            }
        }
#endif

        return true;
    }
    catch(std::exception& e)
    {
        _out << "Config file error:" << e.what() << std::endl;
        return false;
    }
}

