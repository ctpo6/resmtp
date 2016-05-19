#include "smtp_client.h"

#include <cassert>
#include <iostream>
#include <fstream>

#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>

#include "global.h"
#include "util.h"


using namespace std;
using namespace y::net;
namespace ba = boost::asio;
namespace bs = boost::system;
namespace r = resmtp;


#undef PDBG
#undef PLOG
#define PDBG(fmt, args...) log(r::log::debug, r::Log::strf(r::log::debug, "%s:%d %s: " fmt, __FILE__, __LINE__, __func__, ##args))
#define PLOG(prio, fmt, args...) log(prio, r::Log::strf(prio, "%s:%d %s: " fmt, __FILE__, __LINE__, __func__, ##args))


void smtp_client::log(r::log prio, const string &msg) noexcept
{
  // not very nice, but it helps to avoid useless strings construction
  if (r::Log::isEnabled(prio)) {
    g::log().msg(prio,
                 str(boost::format("%1%-%2%-BACK: %3%")
                     % m_data.m_session_id
                     % m_envelope->m_id
                     % msg));
  }
}


void smtp_client::log(const std::pair<resmtp::log, string> &msg) noexcept
{
  // not very nice, but it helps to avoid useless strings construction
  if (r::Log::isEnabled(msg.first)) {
    g::log().msg(msg.first,
                 str(boost::format("%1%-%2%-BACK: %3%")
                     % m_data.m_session_id
                     % m_envelope->m_id
                     % msg.second));
  }
}

#if 0
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
#endif

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


#ifdef RESMTP_LMTP_SUPPORT
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

    m_timer_value = g::cfg().backend_connect_timeout;

    m_proto_state = proto_state_t::start;

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
        g::log().msg(MSG_DEBUG,
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
                        envelope &envelope,
                        const vector<boost::asio::ip::address_v4> &dns_servers)
{
    m_data = _data;
    cb_complete = complete;

    m_envelope = &envelope;
    m_envelope->cleanup_answers();

    for (const auto &addr: dns_servers) {
        m_resolver.add_nameserver(addr);
    }

#ifdef RESMTP_LMTP_SUPPORT    
    m_lmtp = false;
#endif    

    m_use_xclient = false;
    m_use_pipelining = false;

    start_with_next_backend();
}


void smtp_client::start_with_next_backend()
{
    m_proto_state = proto_state_t::start;

    try {
        backend_host = backend_mgr.get_backend_host();
    } catch (const std::exception &e) {
        fault_all_backends();
        return;
    }

    m_timer_value = g::cfg().backend_connect_timeout;
    restart_timeout();

    bs::error_code ec;
    ba::ip::tcp::endpoint ep;
    ep.address(ba::ip::address::from_string(backend_host.host_name, ec));
    if (!ec) {
        // backend_host.host_name is an IP address, proceed to connect
        m_proto_state = proto_state_t::resolved;
        ep.port(backend_host.port);
        backend_host_ip = backend_host.host_name;
        on_backend_ip_address();
        m_socket.async_connect(ep,
            strand_.wrap(boost::bind(&smtp_client::handle_simple_connect,
                                     shared_from_this(),
                                     ba::placeholders::error)));
    } else {
        // backend_host.host_name is a symbolic name, need to resolve
        log(r::Log::pstrf(r::log::debug,
                          "resolving %s",
                          backend_host.host_name.c_str()));
        m_resolver.async_resolve(
            backend_host.host_name,
            dns::type_a,
            strand_.wrap(boost::bind(&smtp_client::handle_resolve,
                            shared_from_this(),
                            ba::placeholders::error,
                            ba::placeholders::iterator)));
    }
}


void smtp_client::handle_resolve(const bs::error_code &ec,
                                 dns::resolver::iterator it)
{
    if (!ec) {
        m_proto_state = proto_state_t::resolved;
        restart_timeout();
        ba::ip::tcp::endpoint ep(
                    boost::dynamic_pointer_cast<dns::a_resource>(*it)->address(),
                    backend_host.port);
        backend_host_ip = ep.address().to_string();
        on_backend_ip_address();
        log(r::Log::pstrf(r::log::debug,
                          "connecting %s[%s]:%u",
                          backend_host.host_name.c_str(),
                          backend_host_ip.c_str(),
                          (unsigned)backend_host.port));
        m_socket.async_connect(ep,
            strand_.wrap(boost::bind(&smtp_client::handle_connect,
                                     shared_from_this(),
                                     ba::placeholders::error,
                                     ++it)));
    } else {
        if (ec != ba::error::operation_aborted) {
            log(r::Log::pstrf(r::log::crit,
                              "failed to resolve backend host %s",
                              backend_host.host_name.c_str()));

            PDBG("call on_host_fail()");
            backend_mgr.on_host_fail(backend_host,
                                     smtp_backend_manager::host_status::fail_resolve);
            fault_backend();
            start_with_next_backend();
        }
    }
}

void smtp_client::handle_simple_connect(const bs::error_code &ec)
{
  if (!ec) {
    on_backend_conn();
  }
  else {
    if (ec != ba::error::operation_aborted) {
      log(r::Log::pstrf(r::log::crit,
                        "failed to connect to %s[%s]:%u",
                        backend_host.host_name.c_str(),
                        backend_host_ip.c_str(),
                        (unsigned)backend_host.port));

      PDBG("call on_host_fail()");
      backend_mgr.on_host_fail(backend_host,
                               smtp_backend_manager::host_status::fail_connect);
      fault_backend();
      start_with_next_backend();
    }
  }
}

void smtp_client::handle_connect(const bs::error_code &ec,
                                 dns::resolver::iterator it)
{
  if (!ec) {
    on_backend_conn();
    return;
  }
  else if (ec == ba::error::operation_aborted) {
    return;
  }
  else if (it != dns::resolver::iterator()) { // if not last address
    log(r::Log::pstrf(r::log::crit,
                      "failed to connect to %s[%s]:%u",
                      backend_host.host_name.c_str(),
                      backend_host_ip.c_str(),
                      (unsigned)backend_host.port));

    ba::ip::tcp::endpoint point(boost::dynamic_pointer_cast<dns::a_resource>(*it)->address(),
                                backend_host.port);
    backend_host_ip = point.address().to_string();

    log(r::Log::pstrf(r::log::debug,
                      "connecting to %s[%s]:%u",
                      backend_host.host_name.c_str(),
                      backend_host_ip.c_str(),
                      (unsigned)backend_host.port));

    m_socket.async_connect(point,
                           strand_.wrap(boost::bind(&smtp_client::handle_connect,
                                                    shared_from_this(),
                                                    ba::placeholders::error,
                                                    ++it)));
    return;
  }

  // all IP adresses of the host were tried out
  log(r::Log::pstrf(r::log::alert,
                    "ERROR: failed to connect to all IP adresses of backend host %s",
                    backend_host.host_name.c_str()));

  PDBG("call on_host_fail()");
  backend_mgr.on_host_fail(backend_host,
                           smtp_backend_manager::host_status::fail_connect);
  fault_backend();
  start_with_next_backend();
}


void smtp_client::handle_write_data_request(const bs::error_code &ec,
                                            size_t sz)
{
    if (ec) {
        if (ec != ba::error::operation_aborted) {
            PDBG("call on_host_fail()");
            backend_mgr.on_host_fail(backend_host,
                                     smtp_backend_manager::host_status::fail_connect);
            fault(util::strf("ERROR: write failed: %s",
                             ec.message().c_str()),
                  string());
        }
        return;
    }

    std::ostream answer_stream(&client_request);
    answer_stream << ".\r\n";

    ba::async_write(m_socket,
                    client_request,
                    strand_.wrap(boost::bind(&smtp_client::handle_write_request,
                                             shared_from_this(),
                                             _1,
                                             _2)));
}

void smtp_client::handle_write_request(const bs::error_code &ec, size_t sz)
{
  if (ec) {
    if (ec != ba::error::operation_aborted) {
      PDBG("call on_host_fail()");
      backend_mgr.on_host_fail(backend_host,
                               smtp_backend_manager::host_status::fail_connect);
      fault(util::strf("ERROR: write failed: %s", ec.message().c_str()),
            string());
    }
  }
  else {
    start_read_line();
  }
}

void smtp_client::start_read_line()
{
    restart_timeout();
    ba::async_read_until(m_socket,
            backend_response,
            "\n",
            strand_.wrap(boost::bind(&smtp_client::handle_read_smtp_line,
                                     shared_from_this(),
                                     ba::placeholders::error)));
}

void smtp_client::handle_read_smtp_line(const bs::error_code &ec)
{
  if (ec) {
    if (ec != ba::error::operation_aborted) {
      PDBG("call on_host_fail()");
      backend_mgr.on_host_fail(backend_host,
                               smtp_backend_manager::host_status::fail_connect);
      fault(util::strf("ERROR: write failed: %s", ec.message().c_str()),
            string());
    }
    return;
  }

  std::istream is(&backend_response);
  if (!process_answer(is)) {
    return;
  }

  if (r::Log::isEnabled(r::log::buffers)) { // to avoid expensive string operations
    log(r::log::buffers,
        str(boost::format("<<< %1%")
            % util::str_cleanup_crlf(util::str_from_buf(client_request))));
  }

  ba::async_write(m_socket,
                  client_request,
                  strand_.wrap(boost::bind(&smtp_client::handle_write_request,
                                           shared_from_this(),
                                           _1,
                                           _2)));
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

        if (r::Log::isEnabled(r::log::buffers)) {
          log(r::log::buffers,
              str(boost::format(">>> %1%")
                  % util::str_cleanup_crlf(line_buffer)));
        }

        if (!m_line_buffer.empty()) {
            m_line_buffer += line_buffer;
            line_buffer.swap(m_line_buffer);
            m_line_buffer.clear();
        }

        // extract state code
        uint32_t code = 0xffffffff;
        try {
            if (line_buffer.size() >= 3) {
                code = boost::lexical_cast<uint32_t>(line_buffer.substr(0, 3));
            }
        } catch (const boost::bad_lexical_cast &) {}
        if (code == 0xffffffff) {
//            backend_mgr.on_host_fail(backend_host,
//                                     smtp_backend_manager::host_status::fail);
//            start_with_next_backend();
            fault("ERROR: invalid SMTP state code", line_buffer);
            return false;
        }

        // check state code
        const char *p_err_str = nullptr;
        switch (m_proto_state) {
        case proto_state_t::connected:
            if (code != 220) p_err_str = "invalid greeting";
            break;
        case proto_state_t::after_hello:
            if (code != 250) p_err_str = "invalid answer on EHLO command";
            break;
        case proto_state_t::after_xclient:
            if (code != 220) p_err_str = "invalid XCLIENT greeting";
            break;
        case proto_state_t::after_hello_xclient:
            if (code != 250) p_err_str = "invalid answer on XCLIENT EHLO command";
            break;
        case proto_state_t::after_mail:
            if (code != 250) p_err_str = "invalid answer on MAIL command";
            break;
        case proto_state_t::after_rcpt:
            if (code != 250) p_err_str = "invalid answer on RCPT command";
            break;
        case proto_state_t::after_data:
            if (code != 354) p_err_str = "invalid answer on DATA command";
            break;
        case proto_state_t::after_dot:
            if (code != 250) p_err_str = "invalid answer on DOT";
            break;
        case proto_state_t::after_quit:
#if 0
            if (code != 221) p_err_str = "invalid answer on QUIT command";
#endif
            break;
        default:
            assert(false && "debug the code");
        }
        if (p_err_str) {
//            backend_mgr.on_host_fail(backend_host,
//                                     smtp_backend_manager::host_status::fail);
//            start_with_next_backend();
            fault(string("ERROR: ") + p_err_str, line_buffer);
            return false;
        }


        if (m_proto_state == proto_state_t::after_hello) {
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


        std::ostream answer_stream(&client_request);

        switch (m_proto_state) {
        case proto_state_t::connected:

            m_timer_value = g::cfg().backend_cmd_timeout;

#ifdef RESMTP_LMTP_SUPPORT
            answer_stream << (m_lmtp ? "LHLO " : "EHLO ")
                          << ba::ip::host_name()
                          << "\r\n";
#else
            answer_stream << "EHLO " << ba::ip::host_name() << "\r\n";
#endif            
            m_proto_state = proto_state_t::after_hello;
            break;

        case proto_state_t::after_xclient:
          
#ifdef RESMTP_LMTP_SUPPORT
            answer_stream << (m_lmtp ? "LHLO " : "EHLO ")
                          << m_data.m_helo_host
                          << "\r\n";
#else
            answer_stream << "EHLO " << m_data.m_helo_host << "\r\n";
#endif            
            m_proto_state = proto_state_t::after_hello_xclient;
            break;

        case proto_state_t::after_hello:
        case proto_state_t::after_hello_xclient:
            if (m_proto_state == proto_state_t::after_hello && m_use_xclient) {
                // send:
                // XCLIENT HELO=spike.porcupine.org ADDR=168.100.189.2 NAME=spike.porcupine.org
                // or
                // XCLIENT HELO=spike.porcupine.org ADDR=168.100.189.2 NAME=[UNAVAILABLE]
                answer_stream << "XCLIENT PROTO=ESMTP HELO=" << m_data.m_helo_host
                              << " ADDR=" << m_data.m_remote_ip
                              << " NAME=" << (m_data.m_remote_host.empty() ? "[UNAVAILABLE]" : m_data.m_remote_host.c_str())
                              << "\r\n";
                m_proto_state = proto_state_t::after_xclient;
            } else {
                answer_stream << "MAIL FROM:<" << m_envelope->m_sender << ">\r\n";
                if (m_use_pipelining) {
                    for(m_current_rcpt = m_envelope->m_rcpt_list.begin();
                        m_current_rcpt != m_envelope->m_rcpt_list.end();
                        ++m_current_rcpt) {
                        answer_stream << "RCPT TO:<" << m_current_rcpt->m_name << ">\r\n";
                    }
                    answer_stream << "DATA\r\n";
                }

                m_proto_state = proto_state_t::after_mail;
            }

            break;

        case proto_state_t::after_mail:
            m_current_rcpt = m_envelope->m_rcpt_list.begin();
            // TODO: move this check to the start()?
            if (m_current_rcpt == m_envelope->m_rcpt_list.end()) {
                fault("ERROR: invalid recipient list", line_buffer);
                return false;
            }

            if (!m_use_pipelining) {
                answer_stream << "RCPT TO: <" << m_current_rcpt->m_name << ">\r\n";
            }

            m_proto_state = proto_state_t::after_rcpt;
            break;

        case proto_state_t::after_rcpt:
            if (++m_current_rcpt == m_envelope->m_rcpt_list.end()) {
                if (!m_use_pipelining) {
                    answer_stream << "DATA\r\n";
                }
                m_proto_state = proto_state_t::after_data;
            } else {
                if (!m_use_pipelining) {
                    answer_stream << "RCPT TO: <" << m_current_rcpt->m_name << ">\r\n";
                }
            }
            break;

        case proto_state_t::after_data:
          
#ifdef RESMTP_LMTP_SUPPORT
            if (m_lmtp) {
                m_current_rcpt = m_envelope->m_rcpt_list.begin();
            }
#endif            

            m_timer_value = g::cfg().backend_data_timeout;
            restart_timeout();

            m_proto_state = proto_state_t::after_dot;
            ba::async_write(m_socket,
                            m_envelope->altered_message_,
                            strand_.wrap(boost::bind(
                                             &smtp_client::handle_write_data_request,
                                             shared_from_this(),
                                             _1,
                                             _2)));
            return false;
            break;

        case proto_state_t::after_dot:
            m_timer_value = g::cfg().backend_cmd_timeout;
            restart_timeout();
            
#ifdef RESMTP_LMTP_SUPPORT
            if (m_lmtp) {
                m_current_rcpt->m_delivery_status = envelope::smtp_code_decode(code);
                m_current_rcpt->m_remote_answer = line_buffer;

                if (++m_current_rcpt == m_envelope->m_rcpt_list.end()) {
                    answer_stream << "QUIT\r\n";
                    m_proto_state = proto_state_t::after_quit;
                }
            } 
            else 
#endif              
            {
                for(m_current_rcpt = m_envelope->m_rcpt_list.begin();
                    m_current_rcpt != m_envelope->m_rcpt_list.end();
                    ++m_current_rcpt) {
                    m_current_rcpt->m_delivery_status = envelope::smtp_code_decode(code);
                    m_current_rcpt->m_remote_answer = line_buffer;
                }
                answer_stream << "QUIT\r\n";
                m_proto_state = proto_state_t::after_quit;
            }
            break;

        case proto_state_t::after_quit:
            success();
            return false;
            break;

        default:
            assert(false && "debug the code!!!");
        }

        line_buffer.clear();
    }

    return true;
}


check::chk_status smtp_client::report_rcpt(bool success,
                                           std::string log_msg,
                                           std::string remote_answer)
{
    bool accept = true;

    string remote;
    for (const envelope::rcpt &rcpt : m_envelope->m_rcpt_list) {
        if (!rcpt.m_remote_answer.empty()) {
            remote = util::str_cleanup_crlf(rcpt.m_remote_answer);
        } else if (!remote_answer.empty()) {
            remote = util::str_cleanup_crlf(remote_answer);
        }

        bool rcpt_success = (rcpt.m_delivery_status == check::CHK_ACCEPT);

        accept = accept && rcpt_success;

        if (rcpt_success) {
            log(r::Log::pstrf(r::log::notice,
                              "%s[%s] OK: tarpit=%d helo=%s from=<%s> to=<%s> relay=%s",
                              m_data.m_remote_host.empty() ? "[UNAVAILABLE]" : m_data.m_remote_host.c_str(),
                              m_data.m_remote_ip.c_str(),
                              m_data.tarpit,
                              m_data.m_helo_host.c_str(),
                              m_envelope->m_sender.c_str(),
                              rcpt.m_name.c_str(),
                              backend_host.host_name.c_str()));
        }
        else {
            log(r::Log::pstrf(r::log::notice,
                              "%s[%s] FAIL: tarpit=%d helo=%s from=<%s> to=<%s> relay=%s (%s)",
                              m_data.m_remote_host.empty() ? "[UNAVAILABLE]" : m_data.m_remote_host.c_str(),
                              m_data.m_remote_ip.c_str(),
                              m_data.tarpit,
                              m_data.m_helo_host.c_str(),
                              m_envelope->m_sender.c_str(),
                              rcpt.m_name.c_str(),
                              backend_host.host_name.c_str(),
                              remote.c_str()));
        }
        remote.clear();
    }

    return accept ? check::CHK_ACCEPT : check::CHK_TEMPFAIL;
}


void smtp_client::fault(string log_msg, string remote_answer)
{
    if (!cb_complete) return;

    m_proto_state = proto_state_t::error;

    m_data.m_result = report_rcpt(false, log_msg, remote_answer);

    m_timer.cancel();
    m_resolver.cancel();

    bs::error_code ec;
    m_socket.close(ec);

    PLOG(r::log::debug, "call on_backend_conn_closed()");
    g::mon().on_backend_conn_closed(backend_host.index);

    m_socket.get_io_service().post(cb_complete);
    cb_complete = nullptr;
}


void smtp_client::fault_backend()
{
    m_proto_state = proto_state_t::error;

    m_timer.cancel();
    m_resolver.cancel();

    assert(!m_socket.is_open()
           && "socket must not be open here - debug the code!!!");
}


void smtp_client::fault_all_backends()
{
    if (!cb_complete) return;

    m_proto_state = proto_state_t::error;

    log(r::log::alert, "all backend hosts are unavailble");

    m_data.m_result = check::CHK_TEMPFAIL;

    m_timer.cancel();
    m_resolver.cancel();

    m_socket.get_io_service().post(cb_complete);
    cb_complete = nullptr;
}


void smtp_client::success()
{
    if (!cb_complete) return;

    m_data.m_result = report_rcpt(true, "success delivery", string());

    m_timer.cancel();
    m_resolver.cancel();
    
    bs::error_code ec;
    m_socket.close(ec);

    PLOG(r::log::debug, "call on_backend_conn_closed()");
    g::mon().on_backend_conn_closed(backend_host.index);

    m_socket.get_io_service().post(cb_complete);
    cb_complete = nullptr;
}


void smtp_client::do_stop()
{
    m_timer.cancel();
    m_resolver.cancel();

    // TODO is it really needed here???
    bs::error_code ec;
    m_socket.close(ec);
}


void smtp_client::stop()
{
    // changed to stop synchronously to make working with current implementation
    // of the server shutdown
#if 0
    m_socket.get_io_service().post(
        strand_.wrap(boost::bind(&smtp_client::do_stop,
                                 shared_from_this())));
#else
    do_stop();
#endif
}

void smtp_client::handle_timer(const bs::error_code &ec)
{
  if (ec) {
    return;
  }

  if (m_proto_state == proto_state_t::start) {
    log(r::Log::pstrf(r::log::debug,
                      "backend host resolve timeout %s",
                      backend_host.host_name.c_str()));

    PDBG("call on_host_fail()");
    backend_mgr.on_host_fail(backend_host,
                             smtp_backend_manager::host_status::fail_resolve);
    fault_backend();
    start_with_next_backend();
  }
  else {
    PDBG("call on_host_fail()");
    backend_mgr.on_host_fail(backend_host,
                             smtp_backend_manager::host_status::fail_connect);
    fault(util::strf("ERROR: backend host connection timeout (state=%s)",
                     get_proto_state_name(m_proto_state)),
          string());
  }
}


const char * smtp_client::get_proto_state_name(proto_state_t st)
{
    switch (st) {
    case proto_state_t::start:
        return "start";
    case proto_state_t::resolved:
        return "resolved";
    case proto_state_t::connected:
        return "connected";
    case proto_state_t::after_hello:
        return "after_hello";
    case proto_state_t::after_xclient:
        return "after_xclient";
    case proto_state_t::after_hello_xclient:
        return "after_hello_xclient";
    case proto_state_t::after_mail:
        return "after_mail";
    case proto_state_t::after_rcpt:
        return "after_rcpt";
    case proto_state_t::after_data:
        return "after_data";
    case proto_state_t::after_dot:
        return "after_dot";
    case proto_state_t::after_quit:
        return "after_quit";
    case proto_state_t::error:
        return "error";
        // no default: to allow gcc with -Wall produce a warning if some case: missed
    }
    assert(false && "update the switch() above");
    return nullptr;
}


void smtp_client::restart_timeout()
{
    m_timer.expires_from_now(boost::posix_time::seconds(m_timer_value));
    m_timer.async_wait(strand_.wrap(boost::bind(&smtp_client::handle_timer,
                                                shared_from_this(),
                                                ba::placeholders::error)));
}


void smtp_client::on_backend_ip_address()
{
    g::mon().on_backend_ip_address(backend_host.index, backend_host_ip);
}


void smtp_client::on_backend_conn()
{
    m_proto_state = proto_state_t::connected;

    log(r::Log::pstrf(r::log::debug,
                      "connect %s[%s]:%u",
                      backend_host.host_name.c_str(),
                      backend_host_ip.c_str(),
                      (unsigned)backend_host.port));

    g::mon().on_backend_conn(backend_host.index);

    m_timer_value = g::cfg().backend_connect_timeout;
    start_read_line();
}
