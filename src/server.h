#ifndef _SERVER_H_
#define _SERVER_H_

#include <memory>
#include <ostream>
#include <string>
#include <vector>

#if 0
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#else
#include "asio/asio.hpp"
#include "asio/asio/ssl.hpp"
#endif
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>

#include "global.h"
#include "smtp_backend_manager.h"
#include "smtp_connection.h"
#include "smtp_connection_manager.h"

using std::string;
using std::vector;

namespace resmtp {

class server : private boost::noncopyable
{
public:
  server(const server_parameters &cfg);

  void run();
  void stop();
  void gracefully_stop();

#ifdef RESMTP_FTR_SSL_RENEGOTIATION    
  static int get_ssl_connection_idx() noexcept;
#endif    

private:
  using acceptor_t = asio::ip::tcp::acceptor;

  bool setup_acceptor(const string &address, bool ssl);
  void handle_accept(acceptor_t *acceptor,
                     std::shared_ptr<smtp_connection> conn,
                     bool force_ssl,
                     const asio::error_code &ec);

  bool setup_mon_acceptor(const string &addr);
  void handle_mon_accept(const asio::error_code &ec);
  void handle_mon_write_request(const asio::error_code &ec,
                                size_t sz);
  void get_mon_response(std::ostream &os);

  bool setup_debug_info_acceptor(const string &addr);
  void handle_debug_info_accept(const asio::error_code &ec);
  void handle_debug_info_write_request(const asio::error_code &ec,
                                       size_t sz);
  void get_debug_info_response(std::ostream &os);


  const uint32_t m_io_service_pool_size;

  asio::io_service m_io_service;
  asio::ssl::context m_ssl_context;

  // used both for mon and debug info
  asio::io_service mon_io_service;

  std::unique_ptr<acceptor_t> mon_acceptor;
  asio::ip::tcp::socket mon_socket;
  asio::streambuf mon_response;

  std::unique_ptr<acceptor_t> debug_info_acceptor;
  asio::ip::tcp::socket debug_info_socket;
  asio::streambuf debug_info_response;

  smtp_connection_manager m_connection_manager;
  smtp_backend_manager backend_mgr;

  vector<acceptor_t> m_acceptors;

  boost::thread mon_thread;
  boost::thread_group m_threads_pool;

  mutable boost::mutex mutex_;

#ifdef RESMTP_FTR_SSL_RENEGOTIATION    
  // stores the value obtained by SSL_get_ex_new_index()
  static int ssl_connection_idx_;
#endif    
};
}

#endif
