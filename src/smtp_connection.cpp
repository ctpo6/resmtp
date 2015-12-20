#include "smtp_connection.h"

#include <algorithm>
#include <cassert>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <unordered_set>
#include <vector>

#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/type_traits.hpp>

#include "aspf.h"
#include "header_parser.h"
#include "ip_options.h"
#include "global.h"
#include "log.h"
#include "options.h"
#include "param_parser.h"
#include "smtp_backend_manager.h"
#include "smtp_connection_manager.h"
#include "util.h"
#include "rfc_date.h"
#include "rfc822date.h"

// must be included the last
//#include "coroutine/yield.hpp"

using namespace std;
using namespace y::net;
namespace ba = boost::asio;


smtp_connection::smtp_connection(boost::asio::io_service &_io_service,
        smtp_connection_manager &_manager,
        smtp_backend_manager &bmgr,
        boost::asio::ssl::context& _context) :
    io_service_(_io_service),
    strand_(_io_service),
    m_ssl_socket(_io_service, _context),
    m_timer(_io_service),
    m_timer_spfdkim(_io_service),
    m_tarpit_timer(_io_service),
    m_manager(_manager),
    backend_mgr(bmgr),
    m_resolver(_io_service),
    m_dkim_status(dkim_check::DKIM_NONE),
    m_envelope(new envelope())
{
}


boost::asio::ip::tcp::socket& smtp_connection::socket()
{
    return m_ssl_socket.next_layer();
}


void smtp_connection::start(bool force_ssl) {
    m_force_ssl = force_ssl;

    m_connected_ip = socket().remote_endpoint().address();

    m_max_rcpt_count = g_config.m_max_rcpt_count;

    // if specified, get the number of recipients for specific IP
    ip_options_config::ip_options_t opt;
    if (g_ip_config.check(m_connected_ip.to_v4(), opt)) {
        m_max_rcpt_count = opt.m_rcpt_count;
    }

    m_session_id = envelope::generate_new_id();

    m_timer_value = g_config.frontend_cmd_timeout;

    for (auto &s: g_config.m_dns_servers) {
        m_resolver.add_nameserver(ba::ip::address::from_string(s));
    }

    // resolve client IP to host name
    m_remote_host_name.clear();
//    PDBG("call async_resolve() %s", m_connected_ip.to_string().c_str());
    m_resolver.async_resolve(
                util::rev_order_av4_str(m_connected_ip.to_v4(), "in-addr.arpa"),
                dns::type_ptr,
                strand_.wrap(boost::bind(
                                 &smtp_connection::handle_back_resolve,
                                 shared_from_this(), _1, _2)));
}


void smtp_connection::handle_back_resolve(
        const boost::system::error_code& ec,
        dns::resolver::iterator it) {
    if (!ec) {
        if (auto ptr = boost::dynamic_pointer_cast<dns::ptr_resource>(*it)) {
            m_remote_host_name = util::unfqdn(ptr->pointer());
        }
    } else if(ec == boost::asio::error::operation_aborted) {
        return;
    }

    g_log.msg(MSG_NORMAL,
              str(boost::format("%1%-RECV: ******** connected from %2%[%3%] ********")
                  % m_session_id
                  % (m_remote_host_name.empty() ? "UNKNOWN" : m_remote_host_name.c_str())
                  % m_connected_ip.to_string()));
    
    // blacklist check is OFF
    if (!g_config.m_rbl_active) {
        handle_dnsbl_check();
        return;
    }

    //--------------------------------------------------------------------------
    // start blacklist check
    //--------------------------------------------------------------------------
    m_dnsbl_check.reset(new rbl_check(io_service_));
    for (auto &s: g_config.m_dns_servers) {
        m_dnsbl_check->add_nameserver(ba::ip::address::from_string(s));
    }
    std::istringstream is(g_config.m_rbl_hosts);
    for (std::istream_iterator<std::string> it(is);
         it != std::istream_iterator<std::string>();
         ++it) {
        m_dnsbl_check->add_rbl_source(*it);
    }
    m_dnsbl_check->start(m_connected_ip.to_v4(), bind(
        &smtp_connection::handle_dnsbl_check, shared_from_this()));
}


void smtp_connection::handle_dnsbl_check() {
//    PDBG("ENTER");

    if(m_dnsbl_check) {
        m_dnsbl_status = m_dnsbl_check->get_status(m_dnsbl_status_str);
        m_dnsbl_check->stop();
        m_dnsbl_check.reset();
    }
    else {
        m_dnsbl_status = false;
    }

    //--------------------------------------------------------------------------
    // is IP blacklisted ?
    //--------------------------------------------------------------------------
    if (m_dnsbl_status) {
        g_log.msg(MSG_NORMAL,
            str(boost::format("%1%-RECV: REJECT connection from blacklisted host %2%[%3%]: %4%")
                % m_session_id
                % (m_remote_host_name.empty() ? "UNKNOWN" : m_remote_host_name.c_str())
                % m_connected_ip.to_v4().to_string()
                % m_dnsbl_status_str));

        std::ostream response_stream(&m_response);
        response_stream << m_dnsbl_status_str;

        if (m_force_ssl) {
            ssl_state_ = ssl_active;
            m_ssl_socket.async_handshake(
                        boost::asio::ssl::stream_base::server,
                        strand_.wrap(
                            boost::bind(
                                &smtp_connection::handle_start_hello_write,
                                shared_from_this(),
                                boost::asio::placeholders::error,
                                true)));
        } else {
            send_response(boost::bind(
                &smtp_connection::handle_last_write_request,
                shared_from_this(),
                boost::asio::placeholders::error));
        }
        return;
    }

    //--------------------------------------------------------------------------
    // start whitelist check
    //--------------------------------------------------------------------------
    m_dnswl_check.reset(new rbl_check(io_service_));
    for (auto &s: g_config.m_dns_servers) {
        m_dnswl_check->add_nameserver(ba::ip::address::from_string(s));
    }
    m_dnswl_check->add_rbl_source(g_config.m_dnswl_host);
    m_dnswl_check->start(
                m_connected_ip.to_v4(),
                bind(&smtp_connection::start_proto, shared_from_this()));
}


void smtp_connection::start_proto() {
    m_proto_state = STATE_START;
    ssl_state_ = ssl_none;

    restart_timeout();

    add_new_command("helo", &smtp_connection::smtp_helo);
    add_new_command("ehlo", &smtp_connection::smtp_ehlo);
    add_new_command("mail", &smtp_connection::smtp_mail);
    add_new_command("rcpt", &smtp_connection::smtp_rcpt);
    add_new_command("data", &smtp_connection::smtp_data);
    add_new_command("quit", &smtp_connection::smtp_quit);
    add_new_command("rset", &smtp_connection::smtp_rset);
    add_new_command("noop", &smtp_connection::smtp_noop);
    // "starttls" is available only for initially unencrypted connections if TLS support is enabled in config
    if (g_config.m_use_tls && !m_force_ssl) {
        add_new_command("starttls", &smtp_connection::smtp_starttls);
    }

    // get whitelist check result, reset checker
    assert(m_dnswl_check);
    m_dnswl_status = m_dnswl_check->get_status(m_dnswl_status_str);
    m_dnswl_check->stop();
    m_dnswl_check.reset();
    PDBG("m_dnswl_status:%d  m_dnswl_status_str:%s", m_dnswl_status, m_dnswl_status_str.c_str());
    if (!m_dnswl_status && g_config.m_tarpit_delay_seconds) {
        on_connection_tarpitted();
        g_log.msg(MSG_NORMAL,
                  str(boost::format("%1%-RECV: TARPIT %2%[%3%]")
                      % m_session_id
                      % (m_remote_host_name.empty() ? "UNKNOWN" : m_remote_host_name.c_str())
                      % m_connected_ip.to_v4().to_string()));
    }

    //--------------------------------------------------------------------------
    // send greeting msg
    //--------------------------------------------------------------------------
    std::ostream response_stream(&m_response);
    string error;
    if (m_manager.start(shared_from_this(), error)) {

        response_stream << "220 " << boost::asio::ip::host_name() << " "
                        << (g_config.m_smtp_banner.empty() ? "Ok" : g_config.m_smtp_banner) << "\r\n";

        if (m_force_ssl) {
            ssl_state_ = ssl_active;
    	    m_ssl_socket.async_handshake(boost::asio::ssl::stream_base::server,
            	    strand_.wrap(boost::bind(&smtp_connection::handle_start_hello_write, shared_from_this(),
                                boost::asio::placeholders::error, false)));
        } else {
			send_response(boost::bind(
				&smtp_connection::handle_write_request,
				shared_from_this(),
				boost::asio::placeholders::error));
		}
	} else {
		g_log.msg(MSG_NORMAL,
				  str(boost::format("%1%-RECV: REJECT connection from host %2%[%3%]: %4%")
					  % m_session_id % m_remote_host_name
					  % m_connected_ip.to_v4().to_string()
					  % error));
        response_stream << error;

        if (m_force_ssl) {
            ssl_state_ = ssl_active;
    	    m_ssl_socket.async_handshake(boost::asio::ssl::stream_base::server,
            	    strand_.wrap(boost::bind(&smtp_connection::handle_start_hello_write, shared_from_this(),
                                boost::asio::placeholders::error, true)));
        } else {
            send_response(boost::bind(
                &smtp_connection::handle_last_write_request,
                shared_from_this(),
                boost::asio::placeholders::error));
        }
    }
}


void smtp_connection::on_connection_tarpitted()
{
    tarpit = true;
    g::mon().conn_tarpitted();
}


void smtp_connection::on_connection_close()
{
    g::mon().conn_closed(conn_close_status, tarpit);
}


bool smtp_connection::check_socket_read_buffer_is_empty()
{
    ba::socket_base::bytes_readable command(true);
    socket().io_control(command);
    return command.get() == 0;
}


void smtp_connection::handle_start_hello_write(
        const boost::system::error_code& _error,
        bool _close) {
    if(_error) {
        return;
    }

	if (_close) {
        send_response(boost::bind(
            &smtp_connection::handle_last_write_request,
            shared_from_this(),
            boost::asio::placeholders::error));
    } else {
        send_response(boost::bind(
            &smtp_connection::handle_write_request,
            shared_from_this(),
            boost::asio::placeholders::error));
    }
}


void smtp_connection::start_read() {
    if (m_proto_state == STATE_CHECK_RCPT ||
            m_proto_state == STATE_CHECK_DATA ||
            m_proto_state == STATE_CHECK_MAILFROM) {
        m_timer.cancel();               // wait for check to complete
        return;
    }

    restart_timeout();

    if (size_t unread_size = buffers_.size() - m_envelope->orig_message_token_marker_size_) {
        handle_read_helper(unread_size);
    }
    else if (!m_read_pending_) {
        if (ssl_state_ == ssl_active) {
            m_ssl_socket.async_read_some(buffers_.prepare(512),
                    strand_.wrap(boost::bind(&smtp_connection::handle_read, shared_from_this(),
                                    boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)));
        }
        else {
            socket().async_read_some(buffers_.prepare(512),
                    strand_.wrap(boost::bind(&smtp_connection::handle_read, shared_from_this(),
                                    boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)));
        }
        m_read_pending_ = true;
    }
}

// Parses text as part of the message data from [b, e) input range.
/**
 * Returns:
 *   true, if futher input required and we have nothing to output
 *   false, otherwise
 * parsed: iterator pointing directly past the parsed and processed part of the input range;
 * read: iterator pointing directly past the last read character of the input range (anything in between [parsed, read) is a prefix of a eom token);
 */
bool smtp_connection::handle_read_data_helper(
        const yconst_buffers_iterator& b,
        const yconst_buffers_iterator& e,
        yconst_buffers_iterator& parsed,
        yconst_buffers_iterator& read)
{
    yconst_buffers_iterator eom;
    bool eom_found = eom_parser_.parse(b, e, eom, read);

    if (g_config.m_remove_extra_cr) {
        yconst_buffers_iterator p = b;
        yconst_buffers_iterator crlf_b, crlf_e;
        bool crlf_found = false;
        while (p != eom) {
            crlf_found = crlf_parser_.parse(p, eom, crlf_b, crlf_e);
            if (crlf_found) {
                if (crlf_e - crlf_b > 2) { // \r{2+}\n
                    m_envelope->orig_message_size_ += append(p, crlf_b, m_envelope->orig_message_);        // text preceeding \r+\n token
                    m_envelope->orig_message_size_ += append(crlf_e-2, crlf_e, m_envelope->orig_message_); // \r\n
                    parsed = crlf_e;
                } else {
                    m_envelope->orig_message_size_ += append(p, crlf_e, m_envelope->orig_message_);
                    parsed = crlf_e;
                }
            } else {
                m_envelope->orig_message_size_ += append(p, crlf_b, m_envelope->orig_message_);
                parsed = crlf_b;
            }
            p = crlf_e;
        }
    } else {
        m_envelope->orig_message_size_ += append(b, eom, m_envelope->orig_message_);
        parsed = eom;
    }

    if (eom_found) {
        m_proto_state = STATE_CHECK_DATA;
        io_service_.post(strand_.wrap(bind(&smtp_connection::start_check_data, shared_from_this())));
        parsed = read;
        return false;
    }

    return true;
}

// Parses and executes commands from [b, e) input range.
/**
 * Returns:
 *   true, if futher input required and we have nothing to output
 *   false, otherwise
 * parsed: iterator pointing directly past the parsed and processed part of the input range;
 * read: iterator pointing directly past the last read character of the input range (anything in between [parsed, read) is a prefix of a command);
*/
bool smtp_connection::handle_read_command_helper(
        const yconst_buffers_iterator& b,
        const yconst_buffers_iterator& e,
        yconst_buffers_iterator& parsed,
        yconst_buffers_iterator& read) {
    if ((read = std::find(b, e, '\n')) == e) {
        return true;
    }

    string command(parsed, read);
    parsed = ++read;

    std::ostream os(&m_response);
    bool res = execute_command(command, os);

    if (res) {
        switch (ssl_state_) {
        case ssl_none:
        case ssl_active:
            send_response(boost::bind(
                &smtp_connection::handle_write_request,
                shared_from_this(),
                boost::asio::placeholders::error));
            break;

        case ssl_hand_shake:
            boost::asio::async_write(socket(), m_response,
                    strand_.wrap(boost::bind(&smtp_connection::handle_ssl_handshake, shared_from_this(),
                                    boost::asio::placeholders::error)));
            break;
        }
    } else {
        send_response(boost::bind(
            &smtp_connection::handle_last_write_request,
            shared_from_this(),
            boost::asio::placeholders::error));
    }
    return false;
}

// Parses the first size characters of buffers_.data().
void smtp_connection::handle_read_helper(std::size_t size)
{
    yconst_buffers bufs = buffers_.data();
    yconst_buffers_iterator b = ybuffers_begin(bufs);
    yconst_buffers_iterator e = b + size;
    yconst_buffers_iterator bb = b + m_envelope->orig_message_token_marker_size_;
    assert (bb < e);

    yconst_buffers_iterator read = bb;
    yconst_buffers_iterator parsed = b;
    bool cont = (m_proto_state == STATE_BLAST_FILE)
            ? handle_read_data_helper(bb, e, parsed, read)
            : handle_read_command_helper(bb, e, parsed, read);

    std::ptrdiff_t parsed_len = parsed - b;
    m_envelope->orig_message_token_marker_size_ = read - parsed;

    buffers_.consume(parsed_len);

    if (cont)
        start_read();
}


void smtp_connection::handle_read(const boost::system::error_code& ec,
                                  size_t size)
{
    m_read_pending_ = false;

    if (size == 0) {
        conn_close_status = status_t::fail;
        m_manager.stop(shared_from_this());
        return;
    }

    if (!ec) {
        buffers_.commit(size);
        handle_read_helper(buffers_.size());
    } else {
        if (ec != boost::asio::error::operation_aborted) {
            conn_close_status = status_t::fail;
            m_manager.stop(shared_from_this());
        }
    }
}


void smtp_connection::start_check_data()
{
    m_check_data.m_session_id = m_session_id;
    m_check_data.m_result = check::CHK_ACCEPT;
    m_check_data.m_answer = "";
    // we will need client IP in the upstream SMTP client for XCLIENT command
    m_check_data.m_remote_ip = m_connected_ip.to_string();
    m_check_data.m_remote_host = m_remote_host_name;
    m_check_data.m_helo_host = m_helo_host;

    m_timer.cancel();

    if (m_envelope->orig_message_size_ > g_config.m_message_size_limit)
    {
        m_error_count++;

        m_check_data.m_result = check::CHK_REJECT;
        m_check_data.m_answer =  "552 5.3.4 Error: message file too big;";

        g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-RECV: warning: queue file size limit exceeded") % m_check_data.m_session_id %  m_envelope->m_id ));

        end_check_data();
    }
    else
    {
//        PDBG("call smtp_delivery_start()");
        smtp_delivery_start();
    }
}


void smtp_connection::handle_spf_timeout(const boost::system::error_code& ec)
{
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }

    if (spf_check_) {
        spf_check_->stop();
    }
    spf_check_.reset();
}


void smtp_connection::handle_dkim_timeout(const boost::system::error_code& ec)
{
    if (ec == boost::asio::error::operation_aborted)
        return;
    if (dkim_check_)
        dkim_check_->stop();
    dkim_check_.reset();
    if (m_smtp_delivery_pending) {
//        PDBG("call smtp_delivery_start()");
        smtp_delivery_start();
    }
}

namespace {
template <class Range>
void log_message_id(Range message_id, const string& session_id, const string& envelope_id)
{
    g_log.msg(MSG_NORMAL,
            str(boost::format("%1%-%2%-RECV: message-id=%3%") % session_id % envelope_id % message_id));
}


void handle_parse_header(const header_iterator_range_t &name,
                         const header_iterator_range_t &header,
                         const header_iterator_range_t &value,
                         list<header_iterator_range_t> &h,
                         header_iterator_range_t &message_id,
                         unordered_set<string> &unique_h) {
    string lname;   // lower-cased header name
    lname.reserve(name.size());
    std::transform(name.begin(), name.end(), back_inserter(lname), ::tolower);
    unique_h.insert(lname);

    if (!strcmp(lname.c_str(), "message-id")) {
        message_id = value;
    }

    h.push_back(header);
}
}

void smtp_connection::smtp_delivery_start()
{
//    PDBG("ENTER");
#if 0
    if (dkim_check_ && dkim_check_->is_inprogress()) // wait for DKIM check to complete
    {
        m_smtp_delivery_pending = true;
        return;
    }
#endif
    m_smtp_delivery_pending = false;

    yconst_buffers& orig_m = m_envelope->orig_message_;
    yconst_buffers& alt_m = m_envelope->altered_message_;
    yconst_buffers& orig_h = m_envelope->orig_headers_;
    yconst_buffers& added_h = m_envelope->added_headers_;

#if 0
    reenter (m_envelope->smtp_delivery_coro_)
    {
#endif
        has_dkim_headers_ = false;

        if (m_check_data.m_result != check::CHK_ACCEPT) {
            PDBG("call end_check_data()");
            end_check_data();
            return;
        }

//        PDBG("");
        // alter headers & compose the resulting message here
        typedef list<header_iterator_range_t> hl_t; // header fields subset from the original message for the composed message
        hl_t h;
        header_iterator_range_t message_id;
        unordered_set<string> unique_h;
        header_iterator_range_t::iterator b = ybuffers_begin(orig_m);
        header_iterator_range_t::iterator e = ybuffers_end(orig_m);
        header_iterator_range_t r(b, e);
//        PDBG("call parse_header()");
        m_envelope->orig_message_body_beg_ = parse_header(r,
                boost::bind(&handle_parse_header,
                            _1,
                            _2,
                            _3,
                            boost::ref(h),
                            boost::ref(message_id),
                            boost::ref(unique_h)));

        shared_const_chunk crlf(new chunk_csl("\r\n"));
        for(hl_t::const_iterator it=h.begin(); it!=h.end(); ++it) {
            // append existing headers
            append(it->begin(), it->end(), orig_h);
            append(crlf, orig_h);
        }

        // add missing headers
        if (unique_h.find("message-id") == unique_h.end()) {
            time_t rawtime;
            time(&rawtime);
            struct tm timeinfo;
            localtime_r(&rawtime, &timeinfo);
            char timeid[100];
            strftime(timeid, sizeof(timeid), "%Y%m%d%H%M%S", &timeinfo);

            // format: <20100406110540.C671D18D007F@mxback1.mail.yandex.net>
            string message_id_str = str(boost::format("<%1%.%2%@%3%>")
                                        % timeid
                                        % m_envelope->m_id
                                        % boost::asio::ip::host_name());

            append(str(boost::format("Message-Id: %1%\r\n") % message_id_str), added_h);

            log_message_id(message_id_str, m_check_data.m_session_id, m_envelope->m_id); // log composed message-id
        } else {
            log_message_id(message_id, m_check_data.m_session_id, m_envelope->m_id); // log original message-id
        }

        if (unique_h.find("date") == unique_h.end()) {
            char timestr[256];
            char zonestr[256];
            time_t rawtime;
            time (&rawtime);
            append(str(boost::format("Date: %1%")
                       % rfc822date(&rawtime,
                                    timestr,
                                    sizeof(timestr),
                                    zonestr,
                                    sizeof(zonestr))),
                   added_h);
        }

        if (unique_h.find("from") == unique_h.end()) {
            append("From: MAILER-DAEMON\r\n", added_h);
        }

        if (unique_h.find("to") == unique_h.end()) {
            append("To: undisclosed-recipients:;\r\n", added_h);
        }

#if 0
        has_dkim_headers_ = unique_h.find("dkim-signature") != unique_h.end();
        PDBG("has_dkim_headers_=%d", has_dkim_headers_);
        if (has_dkim_headers_) {
            dkim_check_.reset( new dkim_check);
            m_smtp_delivery_pending = true;

            m_timer_spfdkim.expires_from_now(
                boost::posix_time::seconds(g_config.m_dkim_timeout));
            m_timer_spfdkim.async_wait(
                strand_.wrap(boost::bind(&smtp_connection::handle_dkim_timeout,
                                shared_from_this(), boost::asio::placeholders::error)));

            m_dkim_status = dkim_check::DKIM_NONE;
            m_dkim_identity.clear();
            yield dkim_check_->start(
                strand_.get_io_service(),
                dkim_parameters(ybuffers_begin(orig_m),
                        m_envelope->orig_message_body_beg_,
                        ybuffers_end(orig_m)),
                strand_.wrap(
                    boost::bind(&smtp_connection::handle_dkim_check,
                            shared_from_this(), _1, _2)));

            m_smtp_delivery_pending = false;
        }

        bool has_dkim = m_dkim_status != dkim_check::DKIM_NONE;
        bool has_spf = m_spf_result && m_spf_expl;

        if (has_dkim || has_spf) {
            PDBG("");
            // add Authentication-Results header
            string ah;
            string dkim_identity;
            if (has_dkim && !m_dkim_identity.empty())
                dkim_identity = str( boost::format(" header.i=%1%") % m_dkim_identity );
            if (has_dkim && has_spf)
                ah = str(boost::format("Authentication-Results: %1%; spf=%2% (%3%) smtp.mail=%4%; dkim=%5%%6%\r\n")
                        % boost::asio::ip::host_name() % m_spf_result.get() % m_spf_expl.get() % m_smtp_from
                        % dkim_check::status(m_dkim_status) % dkim_identity);
            else if (has_spf)
                ah = str(boost::format("Authentication-Results: %1%; spf=%2% (%3%) smtp.mail=%4%\r\n")
                        % boost::asio::ip::host_name() % m_spf_result.get() % m_spf_expl.get() % m_smtp_from);
            else
                ah = str(boost::format("Authentication-Results: %1%; dkim=%2%%3%\r\n")
                        % boost::asio::ip::host_name() % dkim_check::status(m_dkim_status) % dkim_identity);

            g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-%3%")
                            % m_session_id % m_envelope->m_id % ah));

            append(ah, added_h);
        }
#endif

//        shared_const_chunk crlf (new chunk_csl("\r\n"));
        append(added_h.begin(), added_h.end(), alt_m);
        append(orig_h.begin(), orig_h.end(), alt_m);
        append(crlf, alt_m);
        append(m_envelope->orig_message_body_beg_, ybuffers_end(orig_m), alt_m);

#if 0   // LMTP support is turned off for now
        if (g_config.m_use_local_relay) {
            if (m_smtp_client)
                m_smtp_client->stop();
            m_smtp_client.reset(new smtp_client(io_service_, backend_mgr));

            m_smtp_client->start(
                m_check_data,
                strand_.wrap(bind(&smtp_connection::end_lmtp_proto, shared_from_this())),
                m_envelope,
                g_config.m_local_relay_host,
                "LOCAL",
                g_config.m_dns_servers);
        } else {
            smtp_delivery();
        }
#endif
        smtp_delivery();

#if 0
    } // reenter
#endif
}

void smtp_connection::end_lmtp_proto()
{
    m_envelope->remove_delivered_rcpt();
    if (m_envelope->m_rcpt_list.empty()) {
        end_check_data();
    } else {
        PDBG("call smtp_delivery()");
        smtp_delivery();
    }
}

void smtp_connection::smtp_delivery() {
    PDBG("ENTER");
    if (m_smtp_client) {
        m_smtp_client->stop();
    }
    m_smtp_client.reset(new smtp_client(io_service_, backend_mgr));
    m_smtp_client->start(
        m_check_data,
        strand_.wrap(bind(&smtp_connection::end_check_data, shared_from_this())),
        m_envelope,
        g_config.m_dns_servers);
}


void smtp_connection::end_check_data() {
    if (m_smtp_client) {
        m_check_data = m_smtp_client->check_data();
        m_smtp_client->stop();
    }
    m_smtp_client.reset();

    m_proto_state = STATE_HELLO;

    std::ostream response_stream(&m_response);

    switch (m_check_data.m_result)
    {
        case check::CHK_ACCEPT:
        case check::CHK_DISCARD:
            response_stream << "250 2.0.0 Ok: queued on " << boost::asio::ip::host_name() << " as";
            break;

        case check::CHK_REJECT:
            if (!m_check_data.m_answer.empty())
            {
                response_stream << m_check_data.m_answer;
            }
            else
            {
                response_stream << "550 " << boost::asio::ip::host_name();
            }

            break;

        case check::CHK_TEMPFAIL:
            if (!m_check_data.m_answer.empty())
            {
                response_stream << m_check_data.m_answer;
            }
            else
            {
                response_stream << temp_error;
            }

            break;
    }

    response_stream << " " << m_session_id << "-" <<  m_envelope->m_id << "\r\n";

    send_response(boost::bind(&smtp_connection::handle_write_request,
                              shared_from_this(),
                              boost::asio::placeholders::error));
#if 0
    if (ssl_state_ == ssl_active)
    {
        boost::asio::async_write(m_ssl_socket, m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
    }
    else
    {
        boost::asio::async_write(socket(), m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
    }
#endif
}


void smtp_connection::send_response(
        boost::function<void(const boost::system::error_code &)> handler) {
    if (m_response.size() == 0) {
        PDBG("nothing to send");
        return;
    }

    if (m_dnswl_status || g_config.m_tarpit_delay_seconds == 0) {
        // send immediately
        send_response2(handler);
        return;
    }

    // send with tarpit timeout
    g_log.msg(MSG_DEBUG,
              str(boost::format("TARPIT: delay %1% seconds")
                  % g_config.m_tarpit_delay_seconds));
    m_tarpit_timer.expires_from_now(
        boost::posix_time::seconds(g_config.m_tarpit_delay_seconds));
    m_tarpit_timer.async_wait(strand_.wrap(
        boost::bind(&smtp_connection::send_response2,
                    shared_from_this(),
                    handler)));
}


void smtp_connection::send_response2(
        boost::function<void(const boost::system::error_code &)> handler) {
    // check that the client hasn't sent something before receiving greeting msg
    if (g_config.m_socket_check &&
            m_proto_state == STATE_START &&
            !check_socket_read_buffer_is_empty()) {
        g_log.msg(MSG_NORMAL,
                  str(boost::format("%1%: ABORT SESSION (bad client behavior)")
                      % m_session_id));
        conn_close_status = status_t::fail_client_early_write;
        m_manager.stop(shared_from_this());
        return;
    }

	g_log.msg(MSG_DEBUG,
			  str(boost::format("%1%-SEND: %2%")
				  % m_session_id
				  % util::str_cleanup_crlf(util::str_from_buf(m_response))));
	if(ssl_state_ == ssl_active) {
        ba::async_write(
            m_ssl_socket,
            m_response,
            strand_.wrap(boost::bind(handler, boost::asio::placeholders::error)));
    } else {
        ba::async_write(
            socket(),
            m_response,
            strand_.wrap(boost::bind(handler, boost::asio::placeholders::error)));
    }
}


void smtp_connection::handle_write_request(const boost::system::error_code &ec)
{
    if (!ec) {
        if (m_error_count > g_config.m_hard_error_limit) {
            g_log.msg(MSG_NORMAL,
                      str(boost::format("%1%: too many errors")
                          % m_session_id));

            std::ostream response_stream(&m_response);
            response_stream << "421 4.7.0 " << boost::asio::ip::host_name() << " Error: too many errors\r\n";
            boost::asio::async_write(socket(), m_response,
                    strand_.wrap(boost::bind(&smtp_connection::handle_last_write_request, shared_from_this(),
                                    boost::asio::placeholders::error)));
            return;
        }
        start_read();
    } else {
        if (ec != boost::asio::error::operation_aborted) {
            conn_close_status = status_t::fail;
            m_manager.stop(shared_from_this());
        }
    }
}

void smtp_connection::handle_last_write_request(
        const boost::system::error_code &ec)
{
#if 0
    // socket will be closed in stop()
    if (!ec) {
        try {
            socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            socket().close();
        } catch (...) {}
    }
#endif
    if (ec != boost::asio::error::operation_aborted) {
        if (ec) {
            conn_close_status = status_t::fail;
        }
        m_manager.stop(shared_from_this());
    }
}


void smtp_connection::handle_ssl_handshake(const boost::system::error_code& ec)
{
    if (!ec) {
        ssl_state_ = ssl_active;
        m_ssl_socket.async_handshake(boost::asio::ssl::stream_base::server,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
    } else {
        if (ec != boost::asio::error::operation_aborted) {
            conn_close_status = status_t::fail;
            m_manager.stop(shared_from_this());
        }
    }
}


bool smtp_connection::execute_command(string cmd, std::ostream &os)
{
    g_log.msg(MSG_DEBUG,
              str(boost::format("%1%-RECV: exec cmd='%2%'")
                  % m_session_id
                  % util::str_cleanup_crlf(cmd)));

    // trim starting whitespace
    string::size_type pos = cmd.find_first_not_of( " \t" );
    if (pos != std::string::npos) {
        cmd.erase(0, pos);
    }
    // trim trailing whitespace
    pos = cmd.find_last_not_of( " \t\r\n" );
    if (pos != string::npos) {
        cmd.resize(pos + 1);
    }

    // Split line into command and argument parts
    string arg;
    pos = cmd.find(' ');
    if (pos != string::npos) {
        arg = cmd.substr(pos + 1);
        cmd.resize(pos);
    }

    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

    proto_map_t::iterator func = m_proto_map.find(cmd);
    if (func != m_proto_map.end()) {
        return (func->second)(this, arg, os);
    } else {
        ++m_error_count;
        os << "502 5.5.2 Syntax error, command unrecognized.\r\n";
    }

    return true;
}


void smtp_connection::add_new_command(const char *_command, proto_func_t _func)
{
    m_proto_map[_command] = _func;
}


bool smtp_connection::smtp_quit( const std::string& _cmd, std::ostream &_response )
{
    _response << "221 2.0.0 Closing connection.\r\n";
    return false;
}

bool smtp_connection::smtp_noop ( const std::string& _cmd, std::ostream &_response )
{
    _response << "250 2.0.0 Ok\r\n";
    return true;
}

bool smtp_connection::smtp_starttls ( const std::string& _cmd, std::ostream &_response )
{
    ssl_state_ = ssl_hand_shake;
    _response << "220 Go ahead\r\n";
    return true;
}

bool smtp_connection::smtp_rset( const std::string& _cmd, std::ostream &_response )
{
    if ( m_proto_state > STATE_START )
        m_proto_state = STATE_HELLO;
    m_envelope.reset(new envelope());
    _response << "250 2.0.0 Ok\r\n";
    return true;
}


bool smtp_connection::hello( const std::string &_host)
{
    if ( _host.empty() )
    {
        m_proto_state = STATE_START;
        return false;
    }

    m_proto_state = STATE_HELLO;

    m_helo_host = _host;

    return true;
}

bool smtp_connection::smtp_helo( const std::string& _cmd, std::ostream &_response )
{

    if ( hello( _cmd ) )
    {
        _response << "250 " << boost::asio::ip::host_name() << "\r\n";
        m_ehlo = false;
    }
    else
    {
        m_error_count++;

        _response << "501 5.5.4 HELO requires domain address.\r\n";
    }

    return true;
}

bool smtp_connection::smtp_ehlo( const std::string& _cmd, std::ostream &_response )
{
    std::string esmtp_flags("250-8BITMIME\r\n250-PIPELINING\r\n" );

    if (g_config.m_message_size_limit > 0) {
        esmtp_flags += str(boost::format("250-SIZE %1%\r\n")
                           % g_config.m_message_size_limit);
    }

    if (g_config.m_use_tls && !m_force_ssl) {
        esmtp_flags += "250-STARTTLS\r\n";
    }

    esmtp_flags += "250 ENHANCEDSTATUSCODES\r\n";

    if (hello(_cmd)) {
        _response << "250-" << boost::asio::ip::host_name() << "\r\n" << esmtp_flags;
        m_ehlo = true;
    } else {
        ++m_error_count;
        _response << "501 5.5.4 EHLO requires domain address.\r\n";
    }

    return true;
}

namespace {
string extract_addr(string s) {
    string::size_type beg = s.find("<");
    if (beg != string::npos) {
        string::size_type end = s.find(">", beg);
        if (end != string::npos) {
            return s.substr(beg + 1, end - beg - 1);
        }
    }
    return s;
}

bool is_invalid(char _elem) {
    return !((_elem >= 'a' && _elem <='z') || (_elem >= 'A' && _elem <='Z') ||
            (_elem >= '0' && _elem <='9') || _elem == '-' || _elem =='.' ||
            _elem == '_' || _elem == '@' || _elem == '%' || _elem == '+' ||
            _elem == '=' || _elem == '!' || _elem == '#' ||   _elem == '$' ||
            _elem == '"' ||   _elem == '*' ||   _elem == '-' || _elem == '/' ||
            _elem == '?' ||   _elem == '^' ||   _elem == '`' || _elem == '{' ||
            _elem == '}' ||   _elem == '|' ||   _elem == '~' || _elem == '&'
             ) ;
}
}

bool smtp_connection::smtp_rcpt(const std::string& _cmd, std::ostream &_response) {
    if (m_proto_state != STATE_AFTER_MAIL && m_proto_state != STATE_RCPT_OK) {
        PDBG("m_proto_state = %d", m_proto_state);
        ++m_error_count;
        _response << "503 5.5.4 Bad sequence of commands.\r\n";
        PDBG("RETURN TRUE");
        return true;
    }

    if (strncasecmp( _cmd.c_str(), "to:", 3 ) != 0) {
        ++m_error_count;
        _response << "501 5.5.4 Wrong param.\r\n";
        PDBG("RETURN TRUE");
        return true;
    }

    if (m_envelope->m_rcpt_list.size() >= m_max_rcpt_count) {
        ++m_error_count;
        _response << "452 4.5.3 Error: too many recipients\r\n";
        PDBG("RETURN TRUE");
        return true;
    }

    std::string addr(util::trim(extract_addr(util::trim(_cmd.substr(3)))));

    if (addr.empty()) {
        ++m_error_count;
        _response << "501 5.1.3 Bad recipient address syntax.\r\n";
        PDBG("RETURN TRUE");
        return true;
    }

    std::string::size_type dog_pos = addr.find("@");
    if (dog_pos == std::string::npos) {
        ++m_error_count;
        _response << "504 5.5.2 Recipient address rejected: need fully-qualified address\r\n";
        PDBG("RETURN TRUE");
        return true;
    }

    if (std::count_if(addr.begin(), addr.end(), is_invalid) > 0) {
        ++m_error_count;
        _response << "501 5.1.3 Bad recipient address syntax.\r\n";
        PDBG("RETURN TRUE");
        return true;
    }

    if (addr.find("%") != std::string::npos) {
        ++m_error_count;
        _response << "501 5.1.3 Bad recipient address syntax.\r\n";
        PDBG("RETURN TRUE");
        return true;
    }

    m_proto_state = STATE_CHECK_RCPT;

    m_check_rcpt.m_result = check::CHK_ACCEPT;
    m_check_rcpt.m_session_id = m_session_id;
    m_check_rcpt.m_answer.clear();
    try {
        m_check_rcpt.m_remote_ip = m_connected_ip.to_string();
    } catch(...) {
        m_check_rcpt.m_remote_ip = "unknown";
    }

    m_check_rcpt.m_rcpt = addr;
    m_check_rcpt.m_suid = 0;
    m_check_rcpt.m_uid.clear();

    m_timer.cancel();

    socket().get_io_service().post(strand_.wrap(boost::bind(
        &smtp_connection::handle_bb_result_helper, shared_from_this())));

    return true;
}


void smtp_connection::handle_bb_result_helper() {
    std::string result = str(boost::format("250 2.1.5 <%1%> recipient ok\r\n")
                             % m_check_rcpt.m_rcpt);

    switch (m_check_rcpt.m_result) {
    case check::CHK_ACCEPT:
        m_envelope->add_recipient(m_check_rcpt.m_rcpt,
                                  m_check_rcpt.m_suid,
                                  m_check_rcpt.m_uid);
        m_proto_state = STATE_RCPT_OK;
        break;

    case check::CHK_DISCARD:
        break;

    case check::CHK_REJECT:
        ++m_error_count;
        result = "550 5.7.1 No such user!\r\n";
        break;

    case check::CHK_TEMPFAIL:
        ++m_error_count;
        result = "450 4.7.1 No such user!\r\n";
        break;
    }

    if (!m_envelope->m_rcpt_list.empty()) {
        m_proto_state = STATE_RCPT_OK;
    } else {
        m_proto_state = STATE_AFTER_MAIL;
    }

    if (!m_check_rcpt.m_answer.empty()) {
        PDBG("m_check_rcpt.m_answer = %s", m_check_rcpt.m_answer.c_str());
        result = m_check_rcpt.m_answer;
    }

    std::ostream response_stream(&m_response);
    response_stream << result;

    send_response(boost::bind(
        &smtp_connection::handle_write_request,
        shared_from_this(),
        boost::asio::placeholders::error));
#if 0
    if (ssl_state_ == ssl_active) {
        boost::asio::async_write(m_ssl_socket, m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));

    } else {
        boost::asio::async_write(socket(), m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
    }
#endif
}


void smtp_connection::handle_spf_check(boost::optional<std::string> result,
                                       boost::optional<std::string> expl) {
    m_spf_result = result;
    m_spf_expl = expl;
    spf_check_.reset();
    m_timer_spfdkim.cancel();
}


void smtp_connection::handle_dkim_check(dkim_check::DKIM_STATUS status, const std::string& identity)
{
    m_dkim_status = status;
    m_dkim_identity = identity;

    dkim_check_.reset();
    m_timer_spfdkim.cancel();
    if (m_smtp_delivery_pending) {
        PDBG("call smtp_delivery_start()");
        smtp_delivery_start();
    }
}

bool smtp_connection::smtp_mail(const std::string& _cmd,
                                std::ostream &_response)
{
    if (strncasecmp(_cmd.c_str(), "from:", 5) != 0) {
        ++m_error_count;
        _response << "501 5.5.4 Syntax: MAIL FROM:<address>\r\n";
        return true;
    }

    if (m_proto_state == STATE_START) {
        ++m_error_count;
        _response << "503 5.5.4 Good girl is greeting first.\r\n";
        return true;
    }

    param_parser::params_map pmap;
    std::string addr;
    param_parser::parse(_cmd.substr(5), addr, pmap);
    addr = util::trim(extract_addr(addr));

    if (std::count_if(addr.begin(), addr.end(), is_invalid) > 0)
    {
        ++m_error_count;
        _response << "501 5.1.7 Bad address mailbox syntax.\r\n";
        return true;
    }

    if (g_config.m_message_size_limit > 0) {
        unsigned int msize = atoi(pmap["size"].c_str());
        if (msize > g_config.m_message_size_limit) {
            ++m_error_count;
            _response << "552 5.3.4 Message size exceeds fixed limit.\r\n";
            return true;
        }
    }

    m_proto_state = STATE_CHECK_MAILFROM;

    end_mail_from_command(true, false, addr, "");

    return true;
}

bool smtp_connection::smtp_data( const std::string& _cmd, std::ostream &_response )
{
    if (m_proto_state != STATE_RCPT_OK) {
        PDBG("m_proto_state = %d", m_proto_state);
        ++m_error_count;
        _response << "503 5.5.4 Bad sequence of commands.\r\n";
        return true;
    }

    if (m_envelope->m_rcpt_list.empty()) {
        m_error_count++;
        _response << "503 5.5.4 No correct recipients.\r\n";
        return true;
    }

    _response << "354 Enter mail, end with \".\" on a line by itself\r\n";

    m_proto_state = STATE_BLAST_FILE;
    m_timer_value = g_config.frontend_data_timeout;
    m_envelope->orig_message_size_ = 0;

    time_t now;
    time(&now);

    append(str(boost::format("Received: from %1% (%1% [%2%])\r\n\tby %3% (resmtp/Rambler) with %4% id %5%;\r\n\t%6%\r\n")
               % (m_remote_host_name.empty() ? "UNKNOWN" : m_remote_host_name.c_str())
               % m_connected_ip.to_string()
               % boost::asio::ip::host_name()
               % (m_ehlo ? "ESMTP": "SMTP")
               % m_envelope->m_id
               % mail_date(now)),
           m_envelope->added_headers_);

//    append(str( boost::format("X-Yandex-Front: %1%\r\n")
//                % boost::asio::ip::host_name()
//                ),
//            m_envelope->added_headers_);

//    append(str( boost::format("X-Yandex-TimeMark: %1%\r\n")
//                    % now
//                ),
//            m_envelope->added_headers_);

    return true;
}

void smtp_connection::stop()
{
	m_timer.cancel();
	m_resolver.cancel();

    m_proto_state = STATE_START;

    try {
        socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
        socket().close();
    } catch (...) {}

    if (m_dnsbl_check) {
        m_dnsbl_check->stop();
        m_dnsbl_check.reset();
    }

    if (m_dnswl_check) {
        m_dnswl_check->stop();
        m_dnswl_check.reset();
    }

    if (m_smtp_client) {
        m_smtp_client->stop();
        m_smtp_client.reset();
    }

    on_connection_close();

    g_log.msg(MSG_NORMAL,
              str(boost::format("%1%-RECV: ******** disconnected from %2%[%3%] ********")
                  % m_session_id
                  % (m_remote_host_name.empty() ? "UNKNOWN" : m_remote_host_name.c_str())
                  % m_connected_ip.to_string()));
}


void smtp_connection::handle_timer(const boost::system::error_code &ec)
{
    if (ec) {
        return;
    }

    std::ostream response_stream(&m_response);
    response_stream << "421 4.4.2 "
                    << boost::asio::ip::host_name()
                    << " Error: timeout exceeded\r\n";

    if (m_proto_state == STATE_BLAST_FILE) {
        g_log.msg(MSG_NORMAL,
                  str(boost::format("%1%-RECV: timeout after DATA (%2% bytes) from %3%[%4%]")
                      % m_session_id
                      % buffers_.size()
                      % (m_remote_host_name.empty() ? "UNKNOWN" : m_remote_host_name.c_str())
                      % m_connected_ip.to_string()));
    } else {
        const char *state_desc = "";
        switch (m_proto_state)
        {
        case STATE_START:
            state_desc = "CONNECT";
            break;
        case STATE_AFTER_MAIL:
            state_desc = "MAIL FROM";
            break;
        case STATE_RCPT_OK:
            state_desc = "RCPT TO";
            break;
        case STATE_HELLO:
        default:
            state_desc = "HELO";
            break;
        }
        g_log.msg(MSG_NORMAL,
                  str(boost::format("%1%-RECV: timeout after %2% from %3%[%4%]")
                      % m_session_id
                      % state_desc
                      % (m_remote_host_name.empty() ? "UNKNOWN" : m_remote_host_name.c_str())
                      % m_connected_ip.to_string()));
    }

    send_response(boost::bind(
        &smtp_connection::handle_last_write_request,
        shared_from_this(),
        boost::asio::placeholders::error));
}

void smtp_connection::restart_timeout()
{
    m_timer.expires_from_now(boost::posix_time::seconds(m_timer_value));
    m_timer.async_wait(
        strand_.wrap(boost::bind(&smtp_connection::handle_timer,
                        shared_from_this(), boost::asio::placeholders::error)));
}

void smtp_connection::end_mail_from_command(bool _start_spf,
                                            bool _start_async,
                                            std::string _addr,
                                            const std::string &_response)
{
    if (_start_spf)
    {
        // start SPF check
        spf_parameters p;
        p.domain = m_helo_host;
        p.from = _addr;
        p.ip = m_connected_ip.to_string();
        m_spf_result.reset();
        m_spf_expl.reset();
        spf_check_.reset(new spf_check);

        spf_check_->start(io_service_, p,
                strand_.wrap(boost::protect(boost::bind(&smtp_connection::handle_spf_check,
                                        shared_from_this(), _1, _2)))
                          );

        m_timer_spfdkim.expires_from_now(boost::posix_time::seconds(g_config.m_spf_timeout));
        m_timer_spfdkim.async_wait(
            strand_.wrap(boost::bind(&smtp_connection::handle_spf_timeout,
                            shared_from_this(), boost::asio::placeholders::error)));
    }

    m_envelope.reset(new envelope());

    m_smtp_from = _addr;

    m_envelope->m_sender = _addr.empty() ? "<>" : _addr;

    g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-RECV: from=<%3%>") % m_session_id % m_envelope->m_id % m_envelope->m_sender));

    std::ostream response_stream(&m_response);

    if (_response.empty())
    {
		m_proto_state = STATE_AFTER_MAIL;
		response_stream << "250 2.1.0 <" <<  _addr << "> ok\r\n";
    }
    else
    {
		response_stream << _response << "\r\n";
    }

    m_message_count++;

    if (_start_async)
    {

    	if (ssl_state_ == ssl_active)
		{
    	    boost::asio::async_write(m_ssl_socket, m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));

		}
		else
		{
    	    boost::asio::async_write(socket(), m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
		}
    }
}
