#include "server.h"

#include <signal.h>

#include <iostream>
#include <string>

#include <boost/algorithm/string/compare.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread/thread.hpp>

#include "global.h"
#include "util.h"

using namespace std;

#ifdef RESMTP_FTR_SSL_RENEGOTIATION
static void ssl_info_cb(const SSL *ssl, int where, int ret)
{
  if (where & SSL_CB_HANDSHAKE_START) {
    smtp_connection *conn = reinterpret_cast<smtp_connection *>
      (SSL_get_ex_data(const_cast<SSL *>(ssl), resmtp::server::get_ssl_connection_idx()));
    if (conn) {
      conn->handle_ssl_handshake_start();
    }
  }
}
#endif

namespace resmtp {

#ifdef RESMTP_FTR_SSL_RENEGOTIATION
int server::ssl_connection_idx_ = -1;
int server::get_ssl_connection_idx() noexcept
{
  return ssl_connection_idx_;
}
#endif

server::server(const server_parameters &cfg)
  : m_io_service_pool_size(cfg.m_worker_count)
  , m_io_service()
  , m_ssl_context(asio::ssl::context::sslv23)
  //    , m_ssl_context(m_io_service, asio::ssl::context::tlsv12_server)
  , mon_io_service()
  , mon_acceptor(new acceptor_t(mon_io_service))
  , mon_socket(mon_io_service)
  , debug_info_acceptor(new acceptor_t(mon_io_service))
  , debug_info_socket(mon_io_service)
  , m_connection_manager(cfg.m_connection_count_limit,
                         cfg.m_client_connection_count_limit,
                         cfg.n_quit_after_)
  , backend_mgr(cfg.backend_hosts, cfg.backend_port)
{
  m_acceptors.reserve(cfg.m_ssl_listen_points.size() + cfg.m_listen_points.size());
  
  if (cfg.m_use_tls) {
#ifdef RESMTP_FTR_SSL_RENEGOTIATION    
    ssl_connection_idx_ = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (ssl_connection_idx_ == -1) {
      throw runtime_error("failed SSL_CTX_get_ex_new_index");
    }
#endif    
    
    SSL_CTX *ssl_ctx = m_ssl_context.native_handle();
    
    //        m_ssl_context.set_verify_mode(asio::ssl::context::verify_peer | asio::ssl::context::verify_client_once);
    m_ssl_context.set_verify_mode(asio::ssl::context::verify_none);
    m_ssl_context.set_options(asio::ssl::context::default_workarounds |
                              asio::ssl::context::no_compression |
                              asio::ssl::context::no_sslv2 |
                              asio::ssl::context::no_sslv3);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    
    const char * ciphers = "ALL:+HIGH:!LOW:!MEDIUM:!EXPORT:!aNULL:!3DES:!ADH:!RC4:@STRENGTH";
    if (SSL_CTX_set_cipher_list(m_ssl_context.native_handle(), ciphers) == 0) {
      throw std::runtime_error(util::strf("failed to set TLS ciphers: '%s'", ciphers));
    }

    try {
      if (!cfg.m_tls_cert_file.empty()) {
        m_ssl_context.use_certificate_chain_file(cfg.m_tls_cert_file);
      }
      if (!cfg.m_tls_key_file.empty()) {
        m_ssl_context.use_private_key_file(cfg.m_tls_key_file, asio::ssl::context::pem);
      }
    }
    catch (const asio::system_error &e) {
      throw std::runtime_error(util::strf("failed to load TLS key / certificate file: key='%s' cert='%s', error='%s'",
                                          cfg.m_tls_key_file.c_str(),
                                          cfg.m_tls_cert_file.c_str(),
                                          e.what()));
    }

#ifdef RESMTP_FTR_SSL_RENEGOTIATION    
    // needed to block client initiated renegotiations
    SSL_CTX_set_info_callback(ssl_ctx, ssl_info_cb);
#endif    
    
    for (auto &s : cfg.m_ssl_listen_points) {
      setup_acceptor(s, true);
    }
  }

  for (auto &s : cfg.m_listen_points) {
    setup_acceptor(s, false);
  }

  if (m_acceptors.empty()) {
    throw std::runtime_error("failed to setup SMTP connection acceptors");
  }

  if (!setup_mon_acceptor(cfg.mon_listen_point)) {
    throw std::runtime_error("failed to setup monitoring connection acceptor");
  }

  // configured to mon port + 1
  if (!setup_debug_info_acceptor(cfg.mon_listen_point)) {
    throw std::runtime_error("failed to setup debug info connection acceptor");
  }

  if (cfg.m_gid && setgid(cfg.m_gid) == -1) {
    throw std::runtime_error("failed to change process group id");
  }

  if (cfg.m_uid && setuid(cfg.m_uid) == -1) {
    throw std::runtime_error("failed to change process user id");
  }
}


void server::run()
{
    // start monitor
    mon_thread = boost::thread( [this](){ mon_io_service.run(); } );
    // start SMTP
    for (uint32_t i = 0; i < m_io_service_pool_size; ++i) {
        m_threads_pool.create_thread( [this](){ m_io_service.run(); } );
    }
}

void server::stop()
{
  {
    boost::mutex::scoped_lock lock(mutex_);
    
    asio::error_code ec;
    
    // stop monitor & debug info
    mon_acceptor->close(ec);
    debug_info_acceptor->close(ec);
    

    // stop SMTP acceptors
    for (auto &a : m_acceptors) {
      a.close(ec);
    }
  }

  // abort all sessions
  m_connection_manager.stop_all();

  m_threads_pool.join_all();
  mon_thread.join();
}

void server::gracefully_stop()
{
  g::set_stop_flag();

  // stop SMTP acceptors and wait all sessions finished
  for (auto &a : m_acceptors) {
    a.close();
  }
  
  m_threads_pool.join_all();

  // stop monitor
  mon_acceptor->close();
  mon_thread.join();
}


bool server::setup_mon_acceptor(const string &addr)
{
    string::size_type pos = addr.find(":");
    if (pos == string::npos) {
        return false;
    }

    asio::ip::tcp::resolver resolver(mon_io_service);
    asio::ip::tcp::resolver::query query(addr.substr(0, pos), addr.substr(pos+1));
    asio::ip::tcp::endpoint ep = *resolver.resolve(query);

    mon_acceptor->open(ep.protocol());
    mon_acceptor->set_option(asio::ip::tcp::acceptor::reuse_address(true));
    mon_acceptor->bind(ep);
    mon_acceptor->listen();
    mon_acceptor->async_accept(mon_socket,
                               boost::bind(&server::handle_mon_accept,
                                           this,
                                           asio::placeholders::error));
    return true;
}

bool server::setup_debug_info_acceptor(const string &addr)
{
  string::size_type pos = addr.find(":");
  if (pos == string::npos) {
    return false;
  }

  // port is set to monitoring port + 1
  uint16_t port = 0;
  try {
    port = boost::lexical_cast<uint16_t>(addr.substr(pos + 1)) + 1;
  }
  catch (const boost::bad_lexical_cast &) {}
  if (!port) {
    return false;
  }
  
  asio::ip::tcp::resolver resolver(mon_io_service);
  asio::ip::tcp::resolver::query query(addr.substr(0, pos), std::to_string((unsigned)port));
  asio::ip::tcp::endpoint ep = *resolver.resolve(query);

  debug_info_acceptor->open(ep.protocol());
  debug_info_acceptor->set_option(asio::ip::tcp::acceptor::reuse_address(true));
  debug_info_acceptor->bind(ep);
  debug_info_acceptor->listen();
  debug_info_acceptor->async_accept(debug_info_socket,
                                    boost::bind(&server::handle_debug_info_accept,
                                                this,
                                                asio::placeholders::error));
  return true;
}


bool server::setup_acceptor(const std::string& address, bool ssl)
{
  string::size_type pos = address.find(":");
  if (pos == string::npos) {
    return false;
  }

  asio::ip::tcp::resolver resolver(m_io_service);
  asio::ip::tcp::resolver::query query(address.substr(0, pos), address.substr(pos + 1));
  asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);

  shared_ptr<smtp_connection> conn(new smtp_connection(m_io_service,
                                                       m_connection_manager,
                                                       backend_mgr,
                                                       m_ssl_context));

  m_acceptors.emplace_back(m_io_service);
  acceptor_t *acceptor = &m_acceptors[m_acceptors.size() - 1];

  acceptor->open(endpoint.protocol());
  acceptor->set_option(asio::ip::tcp::acceptor::reuse_address(true));
  acceptor->bind(endpoint);
  acceptor->listen(2047);

  acceptor->async_accept(conn->socket(),
                         boost::bind(&server::handle_accept,
                                     this,
                                     acceptor,
                                     conn,
                                     ssl,
                                     asio::placeholders::error));
  return true;
}


void server::handle_mon_accept(const asio::error_code &ec)
{
  if (ec == asio::error::operation_aborted) {
    return;
  }

  if (!ec) {
    ostream os(&mon_response);
    get_mon_response(os);
    asio::async_write(mon_socket,
                    mon_response,
                    boost::bind(&server::handle_mon_write_request,
                                this,
                                asio::placeholders::error,
                                asio::placeholders::bytes_transferred));
  }
  else {
    mon_acceptor->async_accept(mon_socket,
                               boost::bind(&server::handle_mon_accept,
                                           this,
                                           asio::placeholders::error));
  }
}

void server::handle_debug_info_accept(const asio::error_code &ec)
{
  if (ec == asio::error::operation_aborted) {
    return;
  }

  if (!ec) {
    ostream os(&debug_info_response);
    get_debug_info_response(os);
    asio::async_write(debug_info_socket,
                      debug_info_response,
                      boost::bind(&server::handle_debug_info_write_request,
                                  this,
                                  asio::placeholders::error,
                                  asio::placeholders::bytes_transferred));
  }
  else {
    debug_info_acceptor->async_accept(debug_info_socket,
                                      boost::bind(&server::handle_debug_info_accept,
                                                  this,
                                                  asio::placeholders::error));
  }
}

void server::handle_mon_write_request(const asio::error_code &ec,
																			size_t)
{
    if (ec == asio::error::operation_aborted) {
        return;
    }

    asio::error_code unused_ec;
    mon_socket.shutdown(asio::ip::tcp::socket::shutdown_both, unused_ec);
    mon_socket.close(unused_ec);

    mon_acceptor->async_accept(mon_socket,
                               boost::bind(&server::handle_mon_accept,
                                           this,
                                           asio::placeholders::error));
}

void server::handle_debug_info_write_request(const asio::error_code &ec,
                                             size_t)
{
  if (ec == asio::error::operation_aborted) {
    return;
  }

  asio::error_code unused_ec;
  debug_info_socket.shutdown(asio::ip::tcp::socket::shutdown_both, unused_ec);
  debug_info_socket.close(unused_ec);

  debug_info_acceptor->async_accept(debug_info_socket,
                                    boost::bind(&server::handle_debug_info_accept,
                                                this,
                                                asio::placeholders::error));
}

void server::get_mon_response(std::ostream &os)
{
  g::mon().print(os);
  m_connection_manager.print_status_info(os);
}

void server::get_debug_info_response(std::ostream &os)
{
  m_connection_manager.print_debug_info(os);
}

void server::handle_accept(acceptor_t *acceptor,
                           shared_ptr<smtp_connection> conn,
                           bool force_ssl,
                           const asio::error_code &ec)
{
  if (ec == asio::error::operation_aborted) {
    return;
  }

  boost::mutex::scoped_lock lock(mutex_);

  if (!ec) {
    try {
      // if remote point didn't close the socket right after connected
      if (!conn->remote_address().is_unspecified()) {
        m_connection_manager.start(conn, force_ssl);
      }
    }
    catch (const std::exception &e) {
      g::log().msg(Log::pstrf(log::notice,
                              "ERROR: start() exception: %s",
                              e.what()));
    }

    try {
      conn.reset(new smtp_connection(m_io_service,
                                     m_connection_manager,
                                     backend_mgr,
                                     m_ssl_context));
    }
    catch (const std::exception &e) {
      // most likely resolver object failed
      g::log().msg(Log::pstrf(log::alert,
                              "ERROR: smtp_connection() exception: %s",
                              e.what()));
      raise(SIGTERM); // stop the program
      return;
    }
  }
  else {
    if (ec != asio::error::not_connected) {
      g::log().msg(Log::pstrf(log::err,
                              "ERROR: accept failed: %s",
                              ec.message().c_str()));
    }
  }

  acceptor->async_accept(conn->socket(),
                         boost::bind(&server::handle_accept,
                                     this,
                                     acceptor,
                                     conn,
                                     force_ssl,
                                     asio::placeholders::error));
}

}
