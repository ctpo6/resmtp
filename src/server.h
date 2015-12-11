#ifndef _SERVER_H_
#define _SERVER_H_

#include <list>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>

#include "options.h"
#include "smtp_backend_manager.h"
#include "smtp_connection.h"
#include "smtp_connection_manager.h"

namespace resmtp {
class server : private boost::noncopyable {
public:
    server(const server_parameters &cfg);

    void run();

    void stop();

private:
    typedef boost::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor_ptr;
    typedef std::list<acceptor_ptr> acceptor_list;

    bool setup_acceptor(const std::string& address, bool ssl);
    void handle_accept(acceptor_list::iterator acceptor, smtp_connection_ptr _connection, bool force_ssl, const boost::system::error_code& e);

    const uint32_t m_io_service_pool_size;

    boost::asio::io_service m_io_service;
    boost::asio::ssl::context m_ssl_context;

    smtp_connection_manager m_connection_manager;
    smtp_backend_manager backend_mgr;

    acceptor_list m_acceptors;

    boost::thread_group m_threads_pool;

    boost::mutex m_mutex;
};
}

#endif
