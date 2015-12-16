#include "server.h"

#include <iostream>

#include <boost/algorithm/string/compare.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread/thread.hpp>

#include "log.h"

using namespace std;
namespace ba = boost::asio;

namespace resmtp {

server::server(const server_parameters &cfg)
    : m_io_service_pool_size(cfg.m_worker_count)
    , m_ssl_context(m_io_service, ba::ssl::context::sslv23)
    , m_connection_manager(cfg.m_connection_count_limit,
                           cfg.m_client_connection_count_limit)
    , backend_mgr(cfg.backend_hosts, cfg.backend_port)
{
    if (cfg.m_use_tls) {
        try {
//            m_ssl_context.set_verify_mode(ba::ssl::context::verify_peer | ba::ssl::context::verify_client_once);
            m_ssl_context.set_verify_mode(ba::ssl::context::verify_none);
            m_ssl_context.set_options(
                        ba::ssl::context::default_workarounds |
                        ba::ssl::context::no_sslv2 );
            if (!cfg.m_tls_cert_file.empty()) {
                m_ssl_context.use_certificate_chain_file(cfg.m_tls_cert_file);
            }
            if (!cfg.m_tls_key_file.empty()) {
                m_ssl_context.use_private_key_file(cfg.m_tls_key_file, ba::ssl::context::pem);
            }
        } catch (std::exception const &e) {
            throw std::runtime_error(str(boost::format(
                "Can't load TLS key / certificate file: file='%1%', error='%2%'")
                % cfg.m_tls_key_file
                % e.what()));
        }

        for(auto &s: cfg.m_ssl_listen_points) {
            setup_acceptor(s, true);
        }
    }

    m_acceptors.reserve(cfg.m_listen_points.size());
    for(auto &s: cfg.m_listen_points) {
        setup_acceptor(s, false);
    }
    if (m_acceptors.empty()) {
        throw std::logic_error("No address to bind to!");
    }

    if (cfg.m_gid && setgid(cfg.m_gid) == -1) {
        g_log.msg(MSG_CRITICAL, "Can't change process group id !");
        throw std::exception();
    }

    if (cfg.m_uid && setuid(cfg.m_uid) == -1) {
        g_log.msg(MSG_CRITICAL, "Can't change process user id !");
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

    smtp_connection_ptr connection = std::make_shared<smtp_connection>(
                m_io_service, m_connection_manager, backend_mgr, m_ssl_context);

    m_acceptors.emplace_back(m_io_service);
    acceptor_t *acceptor = &m_acceptors[m_acceptors.size() - 1];

    acceptor->open(endpoint.protocol());
    acceptor->set_option(ba::ip::tcp::acceptor::reuse_address(true));
    acceptor->bind(endpoint);
    acceptor->listen();

    acceptor->async_accept(connection->socket(),
                           boost::bind(&server::handle_accept,
                                       this,
                                       acceptor,
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

    for (auto &a: m_acceptors) {
        a.close();
    }
    lock.unlock();

    m_threads_pool.join_all();
    m_acceptors.clear();
}


void server::handle_accept(acceptor_t *acceptor,
                           smtp_connection_ptr _connection,
                           bool _force_ssl,
                           const boost::system::error_code& e) {
    boost::mutex::scoped_lock lock(m_mutex);

    if (e == ba::error::operation_aborted)
        return;

    if (!e) {
        try {
            _connection->start(_force_ssl);
        } catch (const boost::system::system_error &e) {
            if (e.code() != ba::error::not_connected) {
                g_log.msg(MSG_NORMAL, str(boost::format("Accept exception: %1%") % e.what()));
            }
        }
        _connection.reset(new smtp_connection(m_io_service,
                                              m_connection_manager,
                                              backend_mgr,
                                              m_ssl_context));
    } else {
        if (e != ba::error::not_connected) {
            g_log.msg(MSG_NORMAL, str(boost::format("Accept error: %1%") % e.message()));
        }
    }

    acceptor->async_accept(_connection->socket(),
                           boost::bind(&server::handle_accept,
                                       this,
                                       acceptor,
                                       _connection,
                                       _force_ssl,
                                       ba::placeholders::error));
}
}
