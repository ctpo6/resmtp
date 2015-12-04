#include "server.h"

#include <iostream>

#include <boost/algorithm/string/compare.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/make_shared.hpp>
#include <boost/thread/thread.hpp>

#include "log.h"

namespace ba = boost::asio;

using std::string;

server::server(std::size_t _io_service_pool_size, uid_t _user, gid_t _group) :
    m_ssl_context(m_io_service, ba::ssl::context::sslv23),
          m_io_service_pool_size(_io_service_pool_size)
{

    if (g_config.m_use_tls)
    {
        try
        {
            //            m_ssl_context.set_verify_mode (ba::ssl::context::verify_peer | ba::ssl::context::verify_client_once);
            m_ssl_context.set_verify_mode (ba::ssl::context::verify_none);

            m_ssl_context.set_options (
                ba::ssl::context::default_workarounds
                | ba::ssl::context::no_sslv2 );


            if (!g_config.m_tls_cert_file.empty())
            {
                m_ssl_context.use_certificate_chain_file(g_config.m_tls_cert_file);
            }
            if (!g_config.m_tls_key_file.empty())
            {
                m_ssl_context.use_private_key_file(g_config.m_tls_key_file, ba::ssl::context::pem);
            }
        }
        catch (std::exception const& e)
        {
            throw std::runtime_error(str(boost::format("Can't load TLS key / certificate file: file='%1%', error='%2%'") % g_config.m_tls_key_file % e.what()));
        }
    }

    for(auto &s: g_config.m_listen_points) {
        setup_acceptor(s, false);
    }
    if (g_config.m_use_tls) {
        for(auto &s: g_config.m_ssl_listen_points) {
            setup_acceptor(s, true);
        }
    }
    if (m_acceptors.empty()) {
        throw std::logic_error("No address to bind to!");
    }

    if (_group && (setgid(_group) == -1))
    {
        g_log.msg(MSG_CRITICAL, "Cannot change process group id !");
        throw std::exception();
    }

    if (_user && (setuid(_user) == -1))
    {
        g_log.msg(MSG_CRITICAL, "Cannot change process user id !");
        throw std::exception();
    }

}

bool server::setup_acceptor(const std::string& address, bool ssl)
{
    string::size_type pos = address.find(":");
    if (pos == string::npos) {
        return false;
    }

    ba::ip::tcp::resolver resolver(m_io_service);
    ba::ip::tcp::resolver::query query(address.substr(0, pos), address.substr(pos+1));
    ba::ip::tcp::endpoint endpoint = *resolver.resolve(query);

    smtp_connection_ptr connection = boost::make_shared<smtp_connection>(
                m_io_service, m_connection_manager, m_ssl_context);

    boost::shared_ptr<ba::ip::tcp::acceptor> acceptor =
            boost::make_shared<ba::ip::tcp::acceptor>(m_io_service);
    m_acceptors.push_front(acceptor);

    acceptor->open(endpoint.protocol());
    acceptor->set_option(ba::ip::tcp::acceptor::reuse_address(true));
    acceptor->bind(endpoint);
    acceptor->listen();

    acceptor->async_accept(connection->socket(),
                           boost::bind(&server::handle_accept,
                                       this,
                                       m_acceptors.begin(),
                                       connection,
                                       ssl,
                                       ba::placeholders::error));
    return true;
}


void server::run() {
    for (std::size_t i = 0; i < m_io_service_pool_size; ++i) {
        m_threads_pool.create_thread( [this](){ m_io_service.run(); } );
    }
}


void server::stop() {
    boost::mutex::scoped_lock lock(m_mutex);
    for (auto a: m_acceptors) {
        a->close();
    }
    lock.unlock();

    m_threads_pool.join_all();
    m_acceptors.clear();
}

void server::handle_accept(acceptor_list::iterator acceptor, smtp_connection_ptr _connection, bool _force_ssl, const boost::system::error_code& e)
{
    boost::mutex::scoped_lock lock(m_mutex);

    if (e == ba::error::operation_aborted)
        return;

    if (!e) {
        try {
            _connection->start( _force_ssl );
        } catch (const boost::system::system_error &e) {
            if (e.code() != ba::error::not_connected) {
                g_log.msg(MSG_NORMAL, str(boost::format("Accept exception: %1%") % e.what()));
            }
        }
        _connection.reset(new smtp_connection(m_io_service, m_connection_manager, m_ssl_context));
    } else {
        if (e != ba::error::not_connected) {
            g_log.msg(MSG_NORMAL, str(boost::format("Accept error: %1%") % e.message()));
        }
    }

    (*acceptor)->async_accept(_connection->socket(),
            boost::bind(&server::handle_accept, this, acceptor, _connection, _force_ssl, ba::placeholders::error)
                           );
}
