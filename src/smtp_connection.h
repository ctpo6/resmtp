#ifndef _SMTP_CONNECTION_H_
#define _SMTP_CONNECTION_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>
#include <boost/optional.hpp>
#include <boost/range/iterator_range.hpp>

#include "net/dns_resolver.hpp"

#include "adkim.h"
#include "buffers.h"
#include "envelope.h"
#include "eom_parser.h"
#include "monitor.h"
#include "rbl.h"
#include "smtp_client.h"


using std::string;

class smtp_connection_manager;
class smtp_backend_manager;

class smtp_connection :
        public std::enable_shared_from_this<smtp_connection>,
        private boost::noncopyable {
public:

    smtp_connection(
            boost::asio::io_service &_io_service,
            smtp_connection_manager &_manager,
            smtp_backend_manager &bmgr,
            boost::asio::ssl::context& _context);

    ~smtp_connection() = default;

    boost::asio::ip::tcp::socket& socket();

    void start(bool force_ssl);
    void stop();

    const boost::asio::ip::address & remote_address() const { return m_connected_ip; }

protected:

    typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket_t;

    typedef ystreambuf::mutable_buffers_type ymutable_buffers;
    typedef ystreambuf::const_buffers_type yconst_buffers;
    typedef ybuffers_iterator<yconst_buffers> yconst_buffers_iterator;

    typedef std::function<bool (smtp_connection *, const string &, std::ostream&)> proto_func_t;
    typedef std::unordered_map<string, proto_func_t> proto_map_t;

    typedef enum {
        STATE_START = 0,
        STATE_HELLO,
        STATE_AFTER_MAIL,
        STATE_RCPT_OK,
        STATE_BLAST_FILE,
        STATE_CHECK_RCPT,
        STATE_CHECK_DATA,
        STATE_CHECK_MAILFROM
    } proto_state_t;
    static const char * get_proto_state_name(proto_state_t st);

    typedef enum {
        ssl_none = 0,
        ssl_hand_shake,
        ssl_active
    } ssl_state_t;


    boost::asio::io_service &io_service_;
    boost::asio::io_service::strand strand_;
    ssl_socket_t m_ssl_socket;

    uint32_t m_timer_value = 0;
    boost::asio::deadline_timer m_timer;

    boost::asio::deadline_timer m_timer_spfdkim;

    boost::asio::deadline_timer m_tarpit_timer;

    boost::asio::streambuf m_response;

    // map: smtp command name -> command handler ptr
    proto_map_t m_proto_map;

    proto_state_t m_proto_state;
    ssl_state_t ssl_state_;


    void handle_write_request(const boost::system::error_code& ec);
    void handle_ssl_handshake(const boost::system::error_code& ec);
    void handle_last_write_request(const boost::system::error_code& ec);

    void handle_read(const boost::system::error_code &ec, std::size_t size);
    void handle_read_helper(std::size_t size);
    bool handle_read_command_helper(const yconst_buffers_iterator& b, const yconst_buffers_iterator& e, yconst_buffers_iterator& parsed, yconst_buffers_iterator& read);
    bool handle_read_data_helper(const yconst_buffers_iterator& b, const yconst_buffers_iterator& e, yconst_buffers_iterator& parsed, yconst_buffers_iterator& read);
    void start_read();

    //---
    void add_new_command(const char *_command, proto_func_t _func);
    bool execute_command(string cmd, std::ostream &_response);

    bool smtp_quit(const std::string& _cmd, std::ostream &_response);
    bool smtp_noop(const std::string& _cmd, std::ostream &_response);
    bool smtp_rset(const std::string& _cmd, std::ostream &_response);
    bool smtp_ehlo(const std::string& _cmd, std::ostream &_response);
    bool smtp_helo(const std::string& _cmd, std::ostream &_response);
    bool smtp_mail(const std::string& _cmd, std::ostream &_response);
    bool smtp_rcpt(const std::string& _cmd, std::ostream &_response);
    bool smtp_data(const std::string& _cmd, std::ostream &_response);
    bool smtp_starttls(const std::string& _cmd, std::ostream &_response);


    //---
    bool hello( const std::string &_host);

    bool m_ehlo;
    boost::asio::ip::address m_connected_ip;
    string m_remote_host_name;
    string m_helo_host;

    //---
    uint32_t msg_count_mail_from = 0;
    uint32_t msg_count_sent = 0;

    //---
    smtp_connection_manager &m_manager;
    smtp_backend_manager &backend_mgr;

    //---
    y::net::dns::resolver m_resolver;

    void handle_back_resolve(const boost::system::error_code& ec, y::net::dns::resolver::iterator it);
    void handle_dnsbl_check();
    void start_proto();

    void handle_start_hello_write(const boost::system::error_code& _error, bool _close);

    // should connection be opened via SSL/TLS
    bool m_force_ssl;

    // SPF
    string m_smtp_from;
    bool m_smtp_delivery_pending = false;
    boost::optional<string> m_spf_result;
    boost::optional<string> m_spf_expl;
    std::shared_ptr<class spf_check> spf_check_;

    void handle_spf_check(boost::optional<std::string> result, boost::optional<std::string> expl);
    void handle_spf_timeout(const boost::system::error_code& ec);

    // DKIM
    typedef std::shared_ptr<dkim_check> dkim_check_ptr;
    dkim_check_ptr dkim_check_;
    dkim_check::DKIM_STATUS m_dkim_status;
    string m_dkim_identity;
    bool has_dkim_headers_;

    void handle_dkim_check(dkim_check::DKIM_STATUS status, const std::string& identity);
    void handle_dkim_timeout(const boost::system::error_code& ec);

    // BL & WL CHECK
    rbl_client_ptr m_dnsbl_check;
    // don't look to 'rbl' - it is actually used as an whitelist checker
    bool wl_status;
    rbl_client_ptr m_dnswl_check;

    //--
    check_rcpt_t m_check_rcpt;

    void end_mail_from_command(bool _start_spf, bool _start_async, std::string _addr, const std::string &_response);

    void handle_bb_result_helper();

    //---
    smtp_client_ptr m_smtp_client;

    check_data_t m_check_data;

    void start_check_data();
    void smtp_delivery_start();
    void end_check_data();
    void end_lmtp_proto();
    void smtp_delivery();

    //---
    envelope_ptr m_envelope;

    ystreambuf buffers;

    eom_parser eom_parser_;
    crlf_parser crlf_parser_;
    std::string m_session_id;

    // ---
    uint32_t m_max_rcpt_count;
    bool read_pending = false;

    uint32_t m_error_count = 0;

    bool tarpit = false;

    using close_status_t = resmtp::monitor::conn_close_status_t;
    close_status_t close_status = close_status_t::ok;

    void handle_timer(const boost::system::error_code &ec);
    void restart_timeout();
    void cancel_timer();

    void send_response(
            boost::function<void(const boost::system::error_code &)> handler);
    void send_response2(
            boost::function<void(const boost::system::error_code &)> handler);

    // check is performed in the STATE_START before sending the greeting msg:
    // if there is something in the read buffer, it indicates that the client
    // isn't RFC compliant
    bool check_socket_read_buffer_is_empty();

    void on_connection_tarpitted();
    void on_connection_close();

    void log(uint32_t prio, string msg) noexcept;
};

typedef std::shared_ptr<smtp_connection> smtp_connection_ptr;

#endif // _SMTP_CONNECTION_H_
