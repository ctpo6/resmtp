#include "server.h"

#include <iostream>

#include <boost/algorithm/string/compare.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread/thread.hpp>

#include "global.h"

using namespace std;
namespace ba = boost::asio;

namespace resmtp {

server::server(const server_parameters &cfg)
    : m_io_service_pool_size(cfg.m_worker_count)
    , m_io_service()
    , m_ssl_context(m_io_service, ba::ssl::context::sslv23)
    , mon_io_service()
    , mon_acceptor(new acceptor_t(mon_io_service))
    , mon_socket(mon_io_service)
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
                        ba::ssl::context::no_sslv2 |
                        ba::ssl::context::no_sslv3);
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
    // stop monitor
    mon_acceptor->close();

    // stop SMTP acceptors
    for (auto &a: m_acceptors) {
        a.close();
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
    for (auto &a: m_acceptors) {
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
																			size_t)
{
    if (ec == ba::error::operation_aborted) {
        return;
    }

    try {
        mon_socket.shutdown(ba::ip::tcp::socket::shutdown_both);
        mon_socket.close();
    } catch (...) {}

    mon_acceptor->async_accept(mon_socket,
                               boost::bind(&server::handle_mon_accept,
                                           this,
                                           ba::placeholders::error));
}


void server::get_mon_response(std::ostream &os)
{
    g::mon().print(os);
}


void server::handle_accept(acceptor_t *acceptor,
                           smtp_connection_ptr conn,
                           bool force_ssl,
                           const boost::system::error_code &ec)
{
    if (ec == ba::error::operation_aborted) {
        return;
    }

    if (!ec) {
        on_connection();
        try {
            conn->start(force_ssl);
            // TODO what really can be thrown here???
        } catch (const boost::system::system_error &e) {
            if (e.code() != ba::error::not_connected) {
                g::log().msg(log::crit,
                             str(boost::format("connection start exception: %1%")
                                 % e.what()));
            }
        }
        conn.reset(new smtp_connection(m_io_service,
                                       m_connection_manager,
                                       backend_mgr,
                                       m_ssl_context));
    } else {
        if (ec != ba::error::not_connected) {
            g::log().msg(log::crit,
                      str(boost::format("accept failed: %1%")
                          % ec.message()));
        }
    }

    acceptor->async_accept(conn->socket(),
                           boost::bind(&server::handle_accept,
                                       this,
                                       acceptor,
                                       conn,
                                       force_ssl,
                                       ba::placeholders::error));
}


void server::on_connection()
{
    // signal about inbound connection
    g::mon().on_conn();
}

}
