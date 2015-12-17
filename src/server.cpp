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
    , m_io_service()
    , m_ssl_context(m_io_service, ba::ssl::context::sslv23)
    , mon_acceptor(new acceptor_t(m_io_service))
    , mon_socket(m_io_service)
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
                "failed to load TLS key / certificate file: file='%1%', error='%2%'")
                % cfg.m_tls_key_file
                % e.what()));
        }

        for(auto &s: cfg.m_ssl_listen_points) {
            setup_acceptor(s, true);
        }
    }

    if (!setup_mon_acceptor(cfg.mon_listen_point)) {
        throw std::runtime_error("failed to setup monitoring connection acceptor");
    }

    m_acceptors.reserve(cfg.m_listen_points.size());
    for(auto &s: cfg.m_listen_points) {
        setup_acceptor(s, false);
    }
    if (m_acceptors.empty()) {
        throw std::runtime_error("failed to setup any SMTP connection acceptor");
    }

    if (cfg.m_gid && setgid(cfg.m_gid) == -1) {
        g_log.msg(MSG_CRITICAL, "failed to change process group id");
        throw std::exception();
    }

    if (cfg.m_uid && setuid(cfg.m_uid) == -1) {
        g_log.msg(MSG_CRITICAL, "failed to change process user id");
        throw std::exception();
    }
}


bool server::setup_mon_acceptor(const string &addr)
{
    string::size_type pos = addr.find(":");
    if (pos == string::npos) {
        return false;
    }

    ba::ip::tcp::resolver resolver(m_io_service);
    ba::ip::tcp::resolver::query query(addr.substr(0, pos), addr.substr(pos+1));
    ba::ip::tcp::endpoint ep = *resolver.resolve(query);

    mon_acceptor->open(ep.protocol());
    mon_acceptor->set_option(ba::ip::tcp::acceptor::reuse_address(true));
    mon_acceptor->bind(ep);
    mon_acceptor->listen();
    mon_acceptor->async_accept(mon_socket,
                               boost::bind(&server::handle_mon_accept,
                                           this,
                                           ba::placeholders::error));
    return true;
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

    mon_acceptor->close();

    for (auto &a: m_acceptors) {
        a.close();
    }
    lock.unlock();

    m_threads_pool.join_all();
    m_acceptors.clear();
    mon_acceptor.reset();
}


void server::handle_mon_accept(const boost::system::error_code &ec)
{
    if (ec == ba::error::operation_aborted) {
        return;
    }

    if (!ec) {
        ostream os(&mon_response);
        get_mon_response(os);
        ba::async_write(mon_socket,
                        mon_response,
                        boost::bind(&server::handle_mon_write_request,
                                    this,
                                    ba::placeholders::error,
                                    ba::placeholders::bytes_transferred));
    } else {
        mon_acceptor->async_accept(mon_socket,
                                   boost::bind(&server::handle_mon_accept,
                                               this,
                                               ba::placeholders::error));
    }
}


void server::handle_mon_write_request(const boost::system::error_code &ec,
                                      size_t sz)
{
    if (ec == ba::error::operation_aborted) {
        return;
    }

    try {
        mon_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
        mon_socket.close();
    } catch (...) {}

    mon_acceptor->async_accept(mon_socket,
                               boost::bind(&server::handle_mon_accept,
                                           this,
                                           ba::placeholders::error));
}


void server::get_mon_response(std::ostream &os)
{
    os << "hui!\n";
}


void server::handle_accept(acceptor_t *acceptor,
                           smtp_connection_ptr _connection,
                           bool _force_ssl,
                           const boost::system::error_code& e)
{
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
