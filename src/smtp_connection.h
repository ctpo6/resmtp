#ifndef _SMTP_CONNECTION_H_
#define _SMTP_CONNECTION_H_

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>

#if 0
#include <boost/asio.hpp>
#else
#include "asio/asio.hpp"
#endif
#include <boost/noncopyable.hpp>
#include <boost/optional.hpp>
#include <boost/range/iterator_range.hpp>

#include "net/dns_resolver.hpp"

#include "buffers.h"
#include "envelope.h"
#include "eom_parser.h"
#include "log.h"
#include "monitor.h"
#include "rbl.h"
#include "smtp_client.h"

using std::string;

class smtp_connection_manager;
class smtp_backend_manager;

class smtp_connection :
  public std::enable_shared_from_this<smtp_connection>,
  private boost::noncopyable
{
public:

  smtp_connection(
                  asio::io_service &_io_service,
                  smtp_connection_manager &_manager,
                  smtp_backend_manager &bmgr,
                  asio::ssl::context &_context);

  ~smtp_connection();

  
  // called by connection manager
  // start_error_msg - if not empty, this string must be sent after connection was established
  void start(bool force_ssl, string start_error_msg);
  
  // called by connection manager
  void stop();

  asio::ip::tcp::socket & socket()
  {
    return m_ssl_socket.next_layer();
  }
  
  const asio::ip::tcp::socket & socket() const
  {
    return m_ssl_socket.next_layer();
  }
  
  const asio::ip::address & remote_address() const noexcept
  {
    if (remote_address_.is_unspecified()) {
      try {
        // if disconnected, remote_endpoint() throws exception
        remote_address_ = socket().remote_endpoint().address();
      }
      catch (...) {}
    }
    return remote_address_;
  }

#ifdef RESMTP_FTR_SSL_RENEGOTIATION    
  // must be called by SSL info callback in SSL_CB_HANDSHAKE_START state
  void handle_ssl_handshake_start() noexcept;
#endif    

  enum proto_state_t
  {
    STATE_START = 0,
    STATE_HELLO,
    STATE_AFTER_MAIL,
    STATE_RCPT_OK,
    STATE_BLAST_FILE,
    STATE_CHECK_DATA,
    STATE_STOP,
    STATE_MAX
  };
  static const char * get_proto_state_name(int st);
  
  enum ssl_state_t
  {
    ssl_none = 0,
    // received STARTTLS command, need to start SSL hand shake
    ssl_start_hand_shake,
    // SSL hand shake is in progress
    ssl_hand_shake,
    // SSL connection established
    ssl_active
  };
  static const char * get_ssl_state_name(int st);

  proto_state_t get_proto_state() const { return static_cast<proto_state_t>(proto_state_.load(std::memory_order_acquire)); }
  proto_state_t get_proto_state_reset_changed()
  {
    proto_state_changed_ = false;
    return get_proto_state();
  }
  bool get_proto_state_changed() const { return proto_state_changed_; }
  
  ssl_state_t get_ssl_state() const { return static_cast<ssl_state_t>(ssl_state_.load(std::memory_order_acquire)); }

private:
  
  void init_proto_state(proto_state_t st)
  {
    proto_state_changed_ = false;
    proto_state_ = st;
  }
    
  int set_proto_state(proto_state_t st)
  {
    int prev_proto_state = proto_state_.exchange(st);
    if (prev_proto_state != st) {
      proto_state_changed_ = true;
    }
    return prev_proto_state;
  }
  
  typedef asio::ssl::stream<asio::ip::tcp::socket> ssl_socket_t;

  typedef ystreambuf::mutable_buffers_type ymutable_buffers;
  typedef ystreambuf::const_buffers_type yconst_buffers;
  typedef ybuffers_iterator<yconst_buffers> yconst_buffers_iterator;

  typedef std::function<bool (smtp_connection *, const string &, std::ostream &) > proto_func_t;
  typedef std::unordered_map<string, proto_func_t> proto_map_t;

  using close_status_t = resmtp::monitor::conn_close_status_t;

  // map: smtp command name -> command handler ptr
  static const proto_map_t smtp_command_handlers;

  asio::io_service &io_service_;
  smtp_connection_manager &m_manager;
  smtp_backend_manager &backend_mgr;

  // should connection be opened via SSL/TLS
  bool m_force_ssl;
  // if not empty, session must be stopped right after connection established
  string start_error_msg_;

  asio::io_service::strand strand_;
  ssl_socket_t m_ssl_socket;

  // timers
  uint32_t m_timer_value = 0;
  asio::deadline_timer m_timer;
  asio::deadline_timer m_tarpit_timer;
  
  y::net::dns::resolver m_resolver;

  // state
  std::atomic<int> proto_state_;
  std::atomic<bool> proto_state_changed_; // for monitoring of hanged sessions
  std::atomic<int> ssl_state_;

  std::unique_ptr<envelope> m_envelope;

  //----------------------------------------------------------------------------
  
  smtp_client_ptr m_smtp_client;

  rbl_client_ptr m_dnsbl_check;
  rbl_client_ptr m_dnswl_check;

  bool is_blacklisted;
  string bl_status_str;
  bool is_whitelisted;
  bool tarpit = false;

  // this flag is raised once we have ever tried to start the SMTP client
  // used to monitor connections closed by clients prior they began sending a mail
  bool smtp_client_started = false;

  close_status_t close_status = close_status_t::ok;


  ystreambuf buffers;
  asio::streambuf m_response;

  bool m_ehlo;
  
  mutable asio::ip::address remote_address_;
  string m_remote_host_name;
  string m_helo_host;

  string m_session_id;

  uint32_t m_max_rcpt_count;

  uint32_t m_error_count = 0;

  uint32_t msg_count_mail_from = 0;
  uint32_t msg_count_sent = 0;

  check_data_t m_check_data;

  eom_parser eom_parser_;
  crlf_parser crlf_parser_;

  bool read_pending = false;

  bool spamhaus_log_pending = true;

#ifdef RESMTP_FTR_SSL_RENEGOTIATION    
  bool ssl_renegotiated_ = false;
#endif    

  void handle_back_resolve(const asio::error_code &ec,
                           y::net::dns::resolver::iterator it);
  void handle_dnsbl_check();
  void handle_dnswl_check();
  void start_proto();

  void handle_handshake_start_hello_write(const asio::error_code& ec, bool f_close);

  void handle_write_request(const asio::error_code& ec);
  void handle_starttls_response_write_request(const asio::error_code& ec);
  void handle_last_write_request(const asio::error_code& ec);

  void start_read();
  void handle_read(const asio::error_code &ec, size_t size);
  void handle_read_helper(size_t size);
  bool handle_read_command_helper(const yconst_buffers_iterator& b, const yconst_buffers_iterator& e, yconst_buffers_iterator& parsed, yconst_buffers_iterator& read);
  bool handle_read_data_helper(const yconst_buffers_iterator& b, const yconst_buffers_iterator& e, yconst_buffers_iterator& parsed, yconst_buffers_iterator& read);

  //---
  bool execute_command(string cmd, std::ostream &_response);
  bool smtp_quit(const string& _cmd, std::ostream &_response);
  bool smtp_noop(const string& _cmd, std::ostream &_response);
  bool smtp_rset(const string& _cmd, std::ostream &_response);
  bool smtp_ehlo(const string& _cmd, std::ostream &_response);
  bool smtp_helo(const string& _cmd, std::ostream &_response);
  bool smtp_mail(const string& _cmd, std::ostream &_response);
  bool smtp_rcpt(const string& _cmd, std::ostream &_response);
  bool smtp_data(const string& _cmd, std::ostream &_response);
  bool smtp_starttls(const string& _cmd, std::ostream &_response);

  void start_check_data();
  void smtp_delivery_start();
  void end_check_data();
  void end_lmtp_proto();
  void smtp_delivery();

  void handle_timer(const asio::error_code &ec);
  void restart_timeout();

  void send_response(boost::function<void(const asio::error_code &) > handler,
                     bool force_do_not_tarpit = false);
  void send_response2(const asio::error_code &ec,
                      boost::function<void(const asio::error_code &) > handler);

  // check is performed in the STATE_START before sending the greeting msg:
  // if there is something in the read buffer, it indicates that the client
  // isn't RFC compliant
  bool check_socket_read_buffer_is_empty();

  void on_connection_tarpitted();
  void on_connection_close();

  void log_spamhaus(const string &client_host_address,
                    const string &helo,
                    const string &client_host_name);

  void log(resmtp::log prio, const std::string &msg) noexcept;
  void log(const std::pair<resmtp::log, string> &msg) noexcept;
};

typedef std::shared_ptr<smtp_connection> smtp_connection_ptr;

#endif // _SMTP_CONNECTION_H_
