#include <iostream>
#include <fstream>

#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>

#include "log.h"
#include "smtp_client.h"
#include "util.h"

using namespace y::net;
namespace ba = boost::asio;
namespace bs = boost::system;

using std::list;
using std::string;

namespace {
string log_request_helper(const ba::streambuf& buf) {
	ba::const_buffers_1 b = static_cast<ba::const_buffers_1>(buf.data());
	boost::iterator_range<const char*> ib(
		ba::buffer_cast<const char*>(b),
		ba::buffer_cast<const char*>(b) + ba::buffer_size(b));
	return string(ib.begin(), ib.end());
}


void log_request(const char* d, size_t sz,
        list<string>& session_extracts,
        list<ba::const_buffer>& session_log,
        time_t session_time) {
    boost::iterator_range<const char*> ib(d, d+sz);
    session_extracts.push_back(str(boost::format(">> %3% [%1%]:%2%") % sz % ib % (time(0) - session_time)));
    const string& s = session_extracts.back();
    session_log.push_back(ba::const_buffer(s.c_str(), s.size()));
}


void log_request(const list< ba::const_buffer >& d, size_t sz,
        list< string >& session_extracts,
        list< ba::const_buffer >& session_log,
        time_t session_time) {
    session_extracts.push_back(str( boost::format(">> %2% [%1%]:") % sz % (time(0) - session_time)));
    const string& s = session_extracts.back();
    session_log.push_back( ba::const_buffer(s.c_str(), s.size()) );
    session_log.insert(session_log.end(), d.begin(), d.end());
}
}


smtp_client::smtp_client(ba::io_service &io_service,
                         smtp_backend_manager &bm)
    : backend_mgr(bm)
    , m_socket(io_service)
    , strand_(io_service)
    , m_resolver(io_service)
    , m_timer(io_service)
{
    m_line_buffer.reserve(1000);
}


#if 0
void smtp_client::start(const check_data_t& _data,
                        complete_cb_t complete,
                        envelope_ptr _envelope,
                        const server_parameters::remote_point &_remote,
                        const char *_proto_name,
                        const std::vector<std::string> &dns_servers) {
    m_data = _data;
    cb_complete = complete;
    m_envelope = _envelope;

    m_envelope->cleanup_answers();

    m_lmtp = _remote.m_proto == "lmtp";
    m_proto_name = _proto_name;

    m_timer_value = g_config.m_relay_connect_timeout;

    m_proto_state = STATE_START;

    m_relay_name = _remote.m_host_name;
    m_relay_port = _remote.m_port;

    m_use_xclient = false;
    m_use_pipelining = false;

    for (auto &s: dns_servers) {
        m_resolver.add_nameserver(ba::ip::address::from_string(s));
    }

    restart_timeout();

    try {
        m_endpoint.address(ba::ip::address::from_string(m_relay_name));
        m_endpoint.port(m_relay_port);
        backend_host_ip = m_relay_name;

        m_socket.async_connect(m_endpoint,
                strand_.wrap(boost::bind(&smtp_client::handle_simple_connect,
                                         shared_from_this(),
                                         ba::placeholders::error)));
    } catch(...) {
        g_log.msg(MSG_DEBUG,
                  str(boost::format("%1%-%2%-SEND-%3%S trying to resolve: %4%:%5%")
                      % m_data.m_session_id
                      % m_envelope->m_id
                      % m_proto_name
                      % m_relay_name
                      % m_relay_port));
        m_resolver.async_resolve(
            m_relay_name,
            dns::type_a,
            strand_.wrap(boost::bind(&smtp_client::handle_resolve,
                            shared_from_this(),
                            ba::placeholders::error,
                            ba::placeholders::iterator)));
    }
}
#endif


void smtp_client::start(const check_data_t &_data,
                        complete_cb_t complete,
                        envelope_ptr _envelope,
                        const std::vector<std::string> &dns_servers)
{
    m_data = _data;
    cb_complete = complete;

    m_envelope = _envelope;
    m_envelope->cleanup_answers();

    for (auto &s: dns_servers) {
        m_resolver.add_nameserver(ba::ip::address::from_string(s));
    }

    m_lmtp = false;
    m_proto_name = "SMTP";

    start_with_next_backend();
}


void smtp_client::start_with_next_backend()
{
    m_use_xclient = false;
    m_use_pipelining = false;

    m_proto_state = STATE_START;
    try {
        backend_host = backend_mgr.get_backend_host();
    } catch (const std::exception &e) {
        fault("All backend hosts aren't operational", "");
        return;
    }

    m_timer_value = g_config.m_relay_connect_timeout;
    restart_timeout();

    bs::error_code ec;
    ba::ip::tcp::endpoint ep;
    ep.address(ba::ip::address::from_string(backend_host.host_name, ec));
    if (!ec) {
        // backend_host.host_name is an IP address, proceed to connect
        ep.port(backend_host.port);
        backend_host_ip = backend_host.host_name;
        m_socket.async_connect(ep,
            strand_.wrap(boost::bind(&smtp_client::handle_simple_connect,
                                     shared_from_this(),
                                     ba::placeholders::error)));
    } else {
        // backend_host.host_name is a symbolic name, need to resolve
        g_log.msg(MSG_DEBUG,
                  str(boost::format("%1%-%2%-SEND-%3% resolve: %4%")
                      % m_data.m_session_id
                      % m_envelope->m_id
                      % m_proto_name
                      % backend_host.host_name));
        m_resolver.async_resolve(
            backend_host.host_name,
            dns::type_a,
            strand_.wrap(boost::bind(&smtp_client::handle_resolve,
                            shared_from_this(),
                            ba::placeholders::error,
                            ba::placeholders::iterator)));
    }
}


void smtp_client::handle_resolve(const bs::error_code& ec,
                                 dns::resolver::iterator it)
{
    if (!ec) {
        restart_timeout();

        ba::ip::tcp::endpoint ep(
                    boost::dynamic_pointer_cast<dns::a_resource>(*it)->address(),
                    backend_host.port);
        backend_host_ip = ep.address().to_string();

        g_log.msg(MSG_DEBUG,
                  str(boost::format("%1%-%2%-SEND-%3% connect to %4%[%5%]:%6%")
                      % m_data.m_session_id
                      % m_envelope->m_id
                      % m_proto_name
                      % backend_host.host_name
                      % backend_host_ip
                      % backend_host.port));

        m_socket.async_connect(ep,
            strand_.wrap(boost::bind(&smtp_client::handle_connect,
                                     shared_from_this(),
                                     ba::placeholders::error,
                                     ++it)));
    } else {
        if (ec != ba::error::operation_aborted) {
            backend_mgr.report_host_fail(backend_host,
                                         smtp_backend_manager::host_status::fail_resolve);
            start_with_next_backend();
//            fault(string("Resolve error: ") + ec.message(), "");
        }
    }
}


void smtp_client::handle_simple_connect(const bs::error_code& error) {
    if (!error) {
        m_proto_state = STATE_START;
        m_timer_value = g_config.m_relay_connect_timeout;
        start_read_line();
    } else {
        if (error != ba::error::operation_aborted) {
            backend_mgr.report_host_fail(backend_host,
                                         smtp_backend_manager::host_status::fail_connect);
            start_with_next_backend();

//            fault("Can't connect to host: " + error.message(), "");
        }
    }
}


void smtp_client::handle_connect(const bs::error_code& ec,
                                 dns::resolver::iterator it)
{
    if (!ec) {
        m_proto_state = STATE_START;
        m_timer_value = g_config.m_relay_connect_timeout;
        start_read_line();
        return;
    } else if (ec == ba::error::operation_aborted) {
        return;
    }
    else if (it != dns::resolver::iterator()) {     // if not last address
        m_socket.close();

        ba::ip::tcp::endpoint point(
                    boost::dynamic_pointer_cast<dns::a_resource>(*it)->address(),
                    backend_host.port);

        backend_host_ip = point.address().to_string();

        g_log.msg(MSG_DEBUG,
                  str(boost::format("%1%-%2%-SEND-%3% connect to %4%[%5%]:%6%")
                      % m_data.m_session_id
                      % m_envelope->m_id
                      % m_proto_name
                      % backend_host.host_name
                      % backend_host_ip
                      % backend_host.port));

        m_socket.async_connect(point,
            strand_.wrap(boost::bind(&smtp_client::handle_connect,
                                     shared_from_this(),
                                     ba::placeholders::error,
                                     ++it)));
        return;
    }

    // all resolved adresses of the host were tried out

    backend_mgr.report_host_fail(backend_host,
                                 smtp_backend_manager::host_status::fail_connect);
    start_with_next_backend();

//    fault("Can't connect to host: " + ec.message(), "");
}


void smtp_client::handle_write_data_request(const bs::error_code &_err,
                                            size_t sz)
{
    if (_err) {
        if (_err != ba::error::operation_aborted) {
            backend_mgr.report_host_fail(backend_host,
                                         smtp_backend_manager::host_status::fail);
            start_with_next_backend();

//            fault("Write error: " + _err.message(), "");
        }
        return;
    }

    std::ostream answer_stream(&m_response);
    answer_stream << ".\r\n";

    ba::async_write(m_socket,
                    m_response,
                    strand_.wrap(boost::bind(&smtp_client::handle_write_request,
                                             shared_from_this(),
                                             _1,
                                             _2,
                                             log_request_helper(m_response))));
}


void smtp_client::handle_write_request(const bs::error_code &_err,
                                       size_t sz,
                                       const string &s)
{
    if (_err) {
        if (_err != ba::error::operation_aborted) {
            backend_mgr.report_host_fail(backend_host,
                                         smtp_backend_manager::host_status::fail);
            start_with_next_backend();

//            fault("Write error: " + _err.message(), "");
        }
    } else {
        start_read_line();
    }
}


void smtp_client::start_read_line()
{
    restart_timeout();
    ba::async_read_until(m_socket,
            m_request,
            "\n",
            strand_.wrap(boost::bind(&smtp_client::handle_read_smtp_line,
                                     shared_from_this(),
                                     ba::placeholders::error)));
}


void smtp_client::handle_read_smtp_line(const bs::error_code &err) {
    if (err) {
        // TODO ????
        return;
    }

    std::istream response_stream(&m_request);
    if (!process_answer(response_stream)) {
        // TODO ????
        return;
    }

    g_log.msg(MSG_DEBUG,
              str(boost::format("%1%-%2%-SEND-%3%: %4%")
                  % m_data.m_session_id
                  % m_envelope->m_id
                  % m_proto_name
                  % util::str_cleanup_crlf(util::str_from_buf(m_response))));
    ba::async_write(
        m_socket,
        m_response,
        strand_.wrap(boost::bind(&smtp_client::handle_write_request,
                                 shared_from_this(),
                                 _1,
                                 _2,
                                 log_request_helper(m_response))));
}


bool smtp_client::process_answer(std::istream &_stream) {
    string line_buffer;
    line_buffer.reserve(1000);  // SMTP line can be up to 1000 chars

    while (std::getline(_stream, line_buffer)) {
        if (_stream.eof() || _stream.fail() || _stream.bad()) {
            m_line_buffer = line_buffer;
            start_read_line();
            return false;
        }
        if (!m_line_buffer.empty()) {
            m_line_buffer += line_buffer;
            line_buffer.swap(m_line_buffer);
            m_line_buffer.clear();
        }

        g_log.msg(MSG_DEBUG,
                  str(boost::format("%1%-%2%-RECV-%3%: %4%")
                      % m_data.m_session_id
                      % m_envelope->m_id
                      % m_proto_name
                      % util::str_cleanup_crlf(line_buffer)));

        // extract state code
        uint32_t code = 0xffffffff;
        try {
            if (line_buffer.size() >= 3) {
                code = boost::lexical_cast<uint32_t>(line_buffer.substr(0, 3));
            }
        } catch (const boost::bad_lexical_cast &) {}
        if (code == 0xffffffff) {
            backend_mgr.report_host_fail(backend_host,
                                         smtp_backend_manager::host_status::fail);
            start_with_next_backend();

//            fault("Invalid proto state code", line_buffer);

            return false;
        }

        // check state code
        const char *p_err_str = nullptr;
        switch (m_proto_state) {
        case STATE_START:
            if (code != 220) p_err_str = "Invalid greeting";
            break;
        case STATE_START_XCLIENT:
            if (code != 220) p_err_str = "Invalid XCLIENT greeting";
            break;
        case STATE_HELLO:
            if (code != 250) p_err_str = "Invalid answer on EHLO command";
            break;
        case STATE_HELLO_XCLIENT:
            if (code != 250) p_err_str = "Invalid answer on XCLIENT EHLO command";
            break;
        case STATE_AFTER_MAIL:
            if (code != 250) p_err_str = "Invalid answer on MAIL command";
            break;
        case STATE_AFTER_RCPT:
            if (code != 250) p_err_str = "Invalid answer on RCPT command";
            break;
        case STATE_AFTER_DATA:
            if (code != 354) p_err_str = "Invalid answer on DATA command";
            break;
        default:
            break;
        }
        if (p_err_str) {
            backend_mgr.report_host_fail(backend_host,
                                         smtp_backend_manager::host_status::fail);
            start_with_next_backend();

//            fault(p_err_str, line_buffer);

            return false;
        }


        if (m_proto_state == STATE_HELLO) {
            if (line_buffer.find("XCLIENT") != string::npos) {
                m_use_xclient = true;
            }
            if (line_buffer.find("PIPELINING") != string::npos) {
                m_use_pipelining = true;
            }
        }


        if (line_buffer.length() > 3 && line_buffer[3] == '-') {
            continue;
        }


        std::ostream answer_stream(&m_response);

        switch (m_proto_state) {
        case STATE_START:
            // send:
            // EHLO client.example.com

            m_timer_value = g_config.m_relay_cmd_timeout;

            answer_stream << (m_lmtp ? "LHLO " : "EHLO ")
                          << ba::ip::host_name()
                          << "\r\n";

            m_proto_state = STATE_HELLO;
            break;

        case STATE_START_XCLIENT:
            // send:
            // EHLO spike.porcupine.org

            m_timer_value = g_config.m_relay_cmd_timeout;

            answer_stream << (m_lmtp ? "LHLO " : "EHLO ")
                          << m_data.m_helo_host
                          << "\r\n";

            m_proto_state = STATE_HELLO_XCLIENT;
            break;

        case STATE_HELLO:
        case STATE_HELLO_XCLIENT:
            if (m_proto_state == STATE_HELLO && m_use_xclient) {
                // send:
                // XCLIENT HELO=spike.porcupine.org ADDR=168.100.189.2 NAME=spike.porcupine.org
                // or
                // XCLIENT HELO=spike.porcupine.org ADDR=168.100.189.2 NAME=[UNAVAILABLE]
                answer_stream << "XCLIENT PROTO=ESMTP HELO=" << m_data.m_helo_host
                              << " ADDR=" << m_data.m_remote_ip
                              << " NAME=" << (m_data.m_remote_host.empty() ? "[UNAVAILABLE]" : m_data.m_helo_host.c_str())
                              << "\r\n";
                m_proto_state = STATE_START_XCLIENT;
            } else {
                answer_stream << "MAIL FROM: <" << m_envelope->m_sender << ">\r\n";
                if (m_use_pipelining) {
                    for(m_current_rcpt = m_envelope->m_rcpt_list.begin();
                        m_current_rcpt != m_envelope->m_rcpt_list.end();
                        ++m_current_rcpt) {
                        answer_stream << "RCPT TO: <" << m_current_rcpt->m_name << ">\r\n";
                    }
                    answer_stream << "DATA\r\n";
                }

//                g_log.msg(MSG_DEBUG,
//                          str(boost::format("%1%-%2%-SEND-%3%: from=<%4%>")
//                              % m_data.m_session_id
//                              % m_envelope->m_id
//                              % m_proto_name
//                              % m_envelope->m_sender));

                m_proto_state = STATE_AFTER_MAIL;
            }

            break;

        case STATE_AFTER_MAIL:
            m_current_rcpt = m_envelope->m_rcpt_list.begin();
            if (m_current_rcpt == m_envelope->m_rcpt_list.end()) {

                g_log.msg(MSG_NORMAL, "Bad recipient list");
                fault("Invalid", line_buffer);

                // TODO just pass through???? no break?
            }

            if (!m_use_pipelining) {
                answer_stream << "RCPT TO: <" << m_current_rcpt->m_name  << ">\r\n";
            }

            m_proto_state = STATE_AFTER_RCPT;
            break;

        case STATE_AFTER_RCPT:
            if (++m_current_rcpt == m_envelope->m_rcpt_list.end()) {
                if (!m_use_pipelining) {
                    answer_stream << "DATA\r\n";
                }
                m_proto_state = STATE_AFTER_DATA;
            } else {
                if (!m_use_pipelining) {
                    answer_stream << "RCPT TO: <" << m_current_rcpt->m_name  << ">\r\n";
                }
            }
            break;

        case STATE_AFTER_DATA:
            if (m_lmtp) {
                m_current_rcpt = m_envelope->m_rcpt_list.begin();
            }

            m_timer_value = g_config.m_relay_data_timeout;
            restart_timeout();

            m_proto_state = STATE_AFTER_DOT;
            ba::async_write(m_socket, m_envelope->altered_message_,
                    strand_.wrap(boost::bind(&smtp_client::handle_write_data_request,
                                    shared_from_this(), _1, _2)));
            return false;
            break;

        case STATE_AFTER_DOT:
            m_timer_value = g_config.m_relay_cmd_timeout;

            if (m_lmtp) {
                m_current_rcpt->m_delivery_status = envelope::smtp_code_decode(code);
                m_current_rcpt->m_remote_answer = line_buffer;

                if (++m_current_rcpt == m_envelope->m_rcpt_list.end()) {
                    success();
// TODO: investigate why it was put here, commented out for now
#if 0
                    return false;
#endif
                    answer_stream << "QUIT\r\n";
                    m_proto_state = STATE_AFTER_QUIT;
                }
            } else {
                for(m_current_rcpt = m_envelope->m_rcpt_list.begin();
                    m_current_rcpt != m_envelope->m_rcpt_list.end();
                    ++m_current_rcpt) {
                    m_current_rcpt->m_delivery_status = envelope::smtp_code_decode(code);
                    m_current_rcpt->m_remote_answer = line_buffer;
                }

                success();
// TODO: investigate why it was put here, commented out for now
#if 0
                return false;
#endif
                answer_stream << "QUIT\r\n";
                m_proto_state = STATE_AFTER_QUIT;
            }

            break;

        case STATE_AFTER_QUIT:
            try {
                m_socket.close();
            } catch(...) {
                //skip
            }
            return false;
            break;

        case STATE_ERROR:
        default:
            break;
        }

        line_buffer.clear();
    }

    return true;
}


check::chk_status smtp_client::report_rcpt(bool _success,
                                           const string &_log,
                                           const string &_remote)
{
    bool accept = true;

    for(envelope::rcpt_list_t::iterator it = m_envelope->m_rcpt_list.begin();
        it != m_envelope->m_rcpt_list.end();
        ++it)
    {
        string remote;

        if (!it->m_remote_answer.empty())
        {
            remote = util::str_cleanup_crlf(it->m_remote_answer);
        }
        else if (!_remote.empty())
        {
            remote = util::str_cleanup_crlf(_remote);
        }
        else
        {
            remote = _log;
        }

        bool rcpt_success = (it->m_delivery_status == check::CHK_ACCEPT);

        accept = accept && rcpt_success;

        g_log.msg(MSG_NORMAL,
                  str(boost::format("%1%-%2%-SEND-%3%: to=<%4%>, relay=%5%[%6%]:%7%, delay=%8%, status=%9% (%10%)")
                      % m_data.m_session_id
                      % m_envelope->m_id
                      % m_proto_name
                      % it->m_name
                      % backend_host.host_name
                      % backend_host_ip
                      % backend_host.port
                      % m_envelope->m_timer.mark()
                      % (rcpt_success ? "sent" : "fault")
                      % remote ));
    }

    return accept ? check::CHK_ACCEPT : check::CHK_TEMPFAIL;
}


void smtp_client::fault(const string &_log, const string &_remote) {
    if(cb_complete.empty()) return;

    m_proto_state = STATE_ERROR;

    m_data.m_result = report_rcpt(false, _log, _remote);

    m_timer.cancel();
    m_resolver.cancel();

    try {
        m_socket.close();
    } catch (...) {}

    m_socket.get_io_service().post(cb_complete);
    cb_complete = NULL; // nullptr can't be assigned to boost::function
}


void smtp_client::success() {
    if(cb_complete.empty()) return;

    m_data.m_result = report_rcpt(true, "Success delivery", "");

    m_timer.cancel();
    m_resolver.cancel();

    try {
        m_socket.close();
    } catch (...) {}

    m_socket.get_io_service().post(cb_complete);
    cb_complete = NULL; // nullptr can't be assigned to boost::function
}


void smtp_client::do_stop() {
    try {
        m_socket.close();
        m_resolver.cancel();
        m_timer.cancel();
    } catch(...) {}
}


void smtp_client::stop()
{
    m_socket.get_io_service().post(
        strand_.wrap(
            boost::bind(&smtp_client::do_stop, shared_from_this())));
}


void smtp_client::handle_timer(const bs::error_code &_e) {
    if (_e) {
        return;
    }

    const char *state = "";
    switch (m_proto_state) {
    case STATE_START:
        state = "STATE_START";
        break;
    case STATE_START_XCLIENT:
        state = "STATE_START_XCLIENT";
        break;
    case STATE_HELLO:
        state = "STATE_HELLO";
        break;
    case STATE_HELLO_XCLIENT:
        state = "STATE_HELLO_XCLIENT";
        break;
    case STATE_AFTER_MAIL:
        state = "STATE_AFTER_MAIL";
        break;
    case STATE_AFTER_RCPT:
        state = "STATE_AFTER_RCPT";
        break;
    case STATE_AFTER_DATA:
        state = "STATE_AFTER_DATA";
        break;
    case STATE_AFTER_DOT:
        state = "STATE_AFTER_DOT";
        break;
    case STATE_AFTER_QUIT:
        state = "STATE_AFTER_QUIT";
        break;
    case STATE_ERROR:
        state = "STATE_ERROR";
        break;
    }

    backend_mgr.report_host_fail(backend_host,
                                 smtp_backend_manager::host_status::fail_connect);
    start_with_next_backend();

//    fault(string("SMTP/LMTP client connection timeout: ") + state, "");
}


void smtp_client::restart_timeout()
{
    m_timer.expires_from_now(boost::posix_time::seconds(m_timer_value));
    m_timer.async_wait(strand_.wrap(boost::bind(&smtp_client::handle_timer, shared_from_this(), ba::placeholders::error)));
}
