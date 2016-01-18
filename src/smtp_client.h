#ifndef _SMTP_CLIENT_H_
#define _SMTP_CLIENT_H_

#include <functional>
#include <memory>

#include <boost/asio/ssl.hpp>
#include <boost/noncopyable.hpp>

#include "net/dns_resolver.hpp"

#include "check.h"
#include "envelope.h"
#include "options.h"
#include "smtp_backend_manager.h"


using std::string;
using std::vector;


class smtp_client :
        public std::enable_shared_from_this<smtp_client>,
        private boost::noncopyable {
public:

    smtp_client(boost::asio::io_service &io_service,
                smtp_backend_manager &bm);

    typedef std::function<void ()> complete_cb_t;

#if 0
    void start(const check_data_t &_data,
               complete_cb_t complete,
               envelope_ptr _envelope,
               const server_parameters::remote_point &_remote,
               const char *_proto_name,
               const std::vector<std::string> &dns_servers);
#endif

    void start(const check_data_t &_data,
               complete_cb_t complete,
               envelope_ptr _envelope,
               const vector<string> &dns_servers);

    void stop();

    const check_data_t & check_data() const { return m_data; }

protected:

    void start_with_next_backend();

    smtp_backend_manager &backend_mgr;

    boost::asio::ip::tcp::socket m_socket;
    boost::asio::io_service::strand strand_;

    // used to resolve backend server
    y::net::dns::resolver m_resolver;

    bool m_lmtp;

    bool m_use_xclient;
    bool m_use_pipelining;

    string m_read_buffer;

    complete_cb_t cb_complete;

    envelope_ptr m_envelope;

    enum class proto_state_t {
        start = 0,
        resolved,
        connected,
        after_hello,
        after_xclient,
        after_hello_xclient,
        after_mail,
        after_rcpt,
        after_data,
        after_dot,
        after_quit,
        error
    };
    // !!! update this function together with enum
    static const char * get_proto_state_name(proto_state_t st);

    proto_state_t m_proto_state;

    check_data_t m_data;

    smtp_backend_manager::backend_host backend_host;
    string backend_host_ip;

    string m_line_buffer;

    // our request to backend
    boost::asio::streambuf client_request;

    boost::asio::streambuf backend_response;

    envelope::rcpt_list_t::iterator m_current_rcpt;

    uint32_t m_timer_value;
    boost::asio::deadline_timer m_timer;


    void do_stop();

    void start_read_line();

    void handle_read_smtp_line(const boost::system::error_code &ec);

    bool process_answer(std::istream &_stream);

    void handle_simple_connect(const boost::system::error_code &ec);
    void handle_connect(const boost::system::error_code &ec,
                        y::net::dns::resolver::iterator);
    void handle_resolve(const boost::system::error_code &ec,
                        y::net::dns::resolver::iterator);

    void handle_write_request(const boost::system::error_code &ec, size_t sz, const std::string& s);
    void handle_write_data_request(const boost::system::error_code &ec, size_t sz);

    void handle_timer(const boost::system::error_code &ec);
    void restart_timeout();

    // log delivery status for each recipient
    check::chk_status report_rcpt(bool success,
                                  string log_msg,
                                  string remote_answer);


    // called on error (protocol, network, etc.) after connection with backend was established
    void fault(string log_msg,
               string remote_answer);
    // called on backend host resolve or connection error
    void fault_backend();
    // called when all backends are currently unavailable
    void fault_all_backends();

    void success();

    void on_backend_ip_address();
    void on_backend_conn();

    void log(uint32_t prio, string msg) noexcept;
};

typedef std::shared_ptr<smtp_client> smtp_client_ptr;

#endif // _SMTP_CLIENT_H_
