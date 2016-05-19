#ifndef _SMTP_CONNECTION_H_
#define _SMTP_CONNECTION_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>

#include <boost/asio.hpp>
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


namespace ba = boost::asio;
namespace bs = boost::system;

using std::string;


class smtp_connection_manager;
class smtp_backend_manager;

class smtp_connection :
  public std::enable_shared_from_this<smtp_connection>,
  private boost::noncopyable
{
public:

  smtp_connection(
                  ba::io_service &_io_service,
                  smtp_connection_manager &_manager,
                  smtp_backend_manager &bmgr,
                  ba::ssl::context &_context);

  ~smtp_connection();

  ba::ip::tcp::socket& socket() noexcept { return m_ssl_socket.next_layer(); }

  void start(bool force_ssl);
  void stop();

  const ba::ip::address & remote_address() const noexcept { return m_connected_ip; }

#ifdef RESMTP_FTR_SSL_RENEGOTIATION    
  // must be called by SSL info callback in SSL_CB_HANDSHAKE_START state
  void handle_ssl_handshake_start() noexcept;
#endif    

private:

  typedef ba::ssl::stream<ba::ip::tcp::socket> ssl_socket_t;

  typedef ystreambuf::mutable_buffers_type ymutable_buffers;
  typedef ystreambuf::const_buffers_type yconst_buffers;
  typedef ybuffers_iterator<yconst_buffers> yconst_buffers_iterator;

  typedef std::function<bool (smtp_connection *, const string &, std::ostream &) > proto_func_t;
  typedef std::unordered_map<string, proto_func_t> proto_map_t;

  using close_status_t = resmtp::monitor::conn_close_status_t;

  typedef enum
  {
    STATE_START = 0,
    STATE_HELLO,
    STATE_AFTER_MAIL,
    STATE_RCPT_OK,
    STATE_BLAST_FILE,
    STATE_CHECK_DATA
  } proto_state_t;
  static const char * get_proto_state_name(proto_state_t st);

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

  // map: smtp command name -> command handler ptr
  static const proto_map_t smtp_command_handlers;

  ba::io_service &io_service_;
  smtp_connection_manager &m_manager;
  smtp_backend_manager &backend_mgr;

  // should connection be opened via SSL/TLS
  bool m_force_ssl;

  ba::io_service::strand strand_;
  ssl_socket_t m_ssl_socket;

  y::net::dns::resolver m_resolver;

  rbl_client_ptr m_dnsbl_check;
  rbl_client_ptr m_dnswl_check;

  smtp_client_ptr m_smtp_client;

  proto_state_t m_proto_state = STATE_START;
  ssl_state_t ssl_state_;

  bool is_blacklisted;
  string bl_status_str;
  bool is_whitelisted;
  bool tarpit = false;

  // this flag is raised once we have ever tried to start the SMTP client
  // used to monitor connections closed by clients prior they began sending a mail
  bool smtp_client_started = false;

  close_status_t close_status = close_status_t::ok;

  std::unique_ptr<envelope> m_envelope;

  ystreambuf buffers;
  ba::streambuf m_response;

  bool m_ehlo;
  ba::ip::address m_connected_ip;
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

  // timers
  uint32_t m_timer_value = 0;
  ba::deadline_timer m_timer;
  ba::deadline_timer m_tarpit_timer;

#ifdef RESMTP_FTR_SSL_RENEGOTIATION    
  bool ssl_renegotiated_ = false;
#endif    

  void handle_back_resolve(const bs::error_code &ec,
                           y::net::dns::resolver::iterator it);
  void handle_dnsbl_check();
  void handle_dnswl_check();
  void start_proto();

  void handle_handshake_start_hello_write(const bs::error_code& ec, bool f_close);

  void handle_write_request(const bs::error_code& ec);
  void handle_starttls_response_write_request(const bs::error_code& ec);
  void handle_last_write_request(const bs::error_code& ec);

  void start_read();
  void handle_read(const bs::error_code &ec, size_t size);
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

  void handle_timer(const bs::error_code &ec);
  void restart_timeout();

  void send_response(boost::function<void(const bs::error_code &) > handler,
                     bool force_do_not_tarpit = false);
  void send_response2(const boost::system::error_code &ec,
                      boost::function<void(const bs::error_code &) > handler);

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
